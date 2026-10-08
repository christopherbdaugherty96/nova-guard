// Read-only check for plaintext secrets at rest in OpenClaw's files.
//
// Reports contain only a location (file, and line for .env files) and a key
// name. Secret values, any fragment of them, lengths, hashes, and parser error
// messages (which can quote file bytes) are never placed in a result.
import { closeSync, constants, fstatSync, openSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import JSON5 from "json5";

export interface SecretLocations {
  /** OPENCLAW_STATE_DIR, normally ~/.openclaw. */
  stateDir: string;
  /** OPENCLAW_CONFIG_PATH, normally <stateDir>/openclaw.json. */
  configPath: string;
  homeDir: string;
  homeDirKnown?: false;
  /** Extra $include roots from OPENCLAW_INCLUDE_ROOTS, already resolved. */
  includeRoots?: readonly string[];
  /**
   * Further agent directories whose models.json OpenClaw's audit reads
   * (listAgentModelsJsonPaths): configured agentDir values and
   * OPENCLAW_AGENT_DIR / PI_CODING_AGENT_DIR, already resolved.
   */
  agentDirs?: readonly string[];
}

export type SecretFileRead =
  | { status: "missing" }
  | { status: "unreadable" }
  | { status: "ok"; text: string };

export interface SecretFileReader {
  readText(file: string): SecretFileRead;
  /**
   * Names of real subdirectories (symlinks are not followed); [] if absent.
   * "unreadable" when the directory exists but cannot be listed.
   */
  listDirectories(dir: string): string[] | "unreadable";
}

export interface SecretFinding {
  /** "plaintext": a literal value; "fallback": a non-empty ${VAR:-default}. */
  kind: "plaintext" | "fallback";
  file: string;
  /** 1-based line number, for .env files only. */
  line?: number;
  /** Variable name or dotted JSON path. Never the value. */
  key: string;
}

export interface PlaintextSecretsResult {
  grade: "pass" | "warning" | "unknown";
  findings: SecretFinding[];
  /** Files that exist but could not be read or parsed. */
  unreadable: string[];
  /** Coverage gaps that are not filesystem paths and must not be path-rendered. */
  unresolved?: number;
  /** Files that were read and checked. */
  scanned: string[];
  summary: string;
}

/** Larger files are not read; a real config or .env is far smaller. */
const maxFileBytes = 1024 * 1024;
const maxDepth = 64;
// OpenClaw's own limit (src/config/includes.ts): includes nest at most 10 deep.
const maxIncludeDepth = 10;
// Includes can fan out (one file included under many keys, many levels deep).
// Real configs need a handful of visits; past this the rest is graded unknown.
const maxIncludeVisits = 256;
const includeKey = "$include";
const maxKeyLength = 200;

// Mirrors OpenClaw's own secrets audit: substring fragments that mark a name
// as secret-bearing. False positives are noise; false negatives leak keys.
const secretNameFragments = [
  "api-key",
  "apikey",
  "token",
  "secret",
  "password",
  "passwd",
  "credential",
  "private-key",
  "access-key",
];
// Credential fields in OpenClaw's SecretRef credential surface whose names
// carry none of the fragments above.
const exactSecretNames = new Set([
  "key",
  "authorization",
  "proxy-authorization",
  "encrypt-key",
  "service-account",
  "auth-tag",
  "passphrase",
]);
// Names that point at a secret held elsewhere rather than holding one.
const indirectNameSuffix = /(?:file|path|env|ref|url|uri)$/;

/** "apiKeys", "API_KEY", "openai.api-key" -> "api-keys", "api-key", "openai-api-key". */
function normalizeName(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1-$2")
    .replace(/([A-Z])([A-Z][a-z])/g, "$1-$2")
    .toLowerCase()
    .replace(/[_.\s]+/g, "-");
}

export function isSecretLikeName(name: string): boolean {
  const normalized = normalizeName(name);
  if (exactSecretNames.has(normalized)) {
    return true;
  }
  if (indirectNameSuffix.test(normalized)) {
    return false;
  }
  return secretNameFragments.some((fragment) => normalized.includes(fragment));
}

/**
 * Numbers are checked only under names that hold a credential (a password,
 * secret, token, key, or PIN), never counts such as maxTokens or tokenLimit.
 */
function isNumericSecretName(name: string): boolean {
  const normalized = normalizeName(name);
  return (
    !indirectNameSuffix.test(normalized) &&
    (/(?:^|-)(?:token|key|api-key|apikey|pin)$/.test(normalized) ||
      ["password", "passwd", "secret"].some((fragment) => normalized.includes(fragment)))
  );
}

// Non-secret placeholders OpenClaw persists in apiKey fields
// (src/agents/model-auth-markers.ts, src/secrets/provider-credential-values.ts).
const nonSecretMarkers = new Set([
  "custom-local",
  "codex-app-server",
  "gcp-vertex-credentials",
  "ollama-local",
  "minimax-oauth",
  "secretref-managed",
  "AWS_BEARER_TOKEN_BEDROCK",
  "AWS_ACCESS_KEY_ID",
  "AWS_PROFILE",
]);
const nonSecretMarkerPrefixes = ["oauth:"];
// "secretref-env:NAME" names an env var; anything after the name is a value.
const secretRefEnvMarker = /^secretref-env:[A-Za-z_][A-Za-z0-9_]*$/;
// Persisted env-var-name markers such as "OPENAI_API_KEY". A real credential
// is not an upper-case identifier ending in _KEY or _TOKEN.
const envNameMarker = /^[A-Z][A-Z0-9_]*_(?:API_KEY|KEY|TOKEN)$/;

/**
 * OpenClaw's apiKey placeholders exempt only apiKey fields. SecretRef markers
 * ("secretref-managed", "secretref-env:NAME") name where a secret is held and
 * are exempt anywhere.
 */
function isNonSecretMarker(value: string, name: string): boolean {
  const trimmed = value.trim();
  if (trimmed === "secretref-managed" || secretRefEnvMarker.test(trimmed)) return true;
  if (!normalizeName(name).endsWith("api-key")) return false;
  return (
    nonSecretMarkers.has(trimmed) ||
    nonSecretMarkerPrefixes.some((prefix) => trimmed.startsWith(prefix)) ||
    envNameMarker.test(trimmed)
  );
}

// Scheme words that may precede a reference, as in "Bearer ${TOKEN}".
const authScheme = /^(?:bearer|basic|token)$/i;

interface ParsedReferences {
  references: { name: string; fallback?: string }[];
  /** The value with every reference removed. */
  literal: string;
}

/**
 * Finds OpenClaw env references in one linear pass: "${NAME}" or
 * "${NAME:-fallback}", upper-case names only, with "$${...}" an escaped
 * literal. Fallbacks have no length cap (a JWT or certificate can be long).
 */
function parseReferences(value: string): ParsedReferences {
  const references: ParsedReferences["references"] = [];
  let literal = "";
  let index = 0;
  while (index < value.length) {
    const start = value.indexOf("${", index);
    if (start === -1) break;
    if (start > 0 && value[start - 1] === "$") {
      literal += value.slice(index, start + 2);
      index = start + 2;
      continue;
    }
    // The name runs to its actual end: [A-Z_][A-Z0-9_]*, with no length cap.
    let afterName = start + 2;
    if (/[A-Z_]/.test(value[afterName] ?? "")) {
      afterName += 1;
      while (/[A-Z0-9_]/.test(value[afterName] ?? "")) afterName += 1;
    }
    const name = afterName > start + 2 ? value.slice(start + 2, afterName) : undefined;
    // Search for "}" only after ":-", and stop once none remains, so every
    // character is scanned a bounded number of times.
    let close = -1;
    if (name !== undefined && value[afterName] === "}") {
      close = afterName;
      references.push({ name });
    } else if (name !== undefined && value.startsWith(":-", afterName)) {
      close = value.indexOf("}", afterName + 2);
      if (close === -1) break;
      references.push({ name, fallback: value.slice(afterName + 2, close) });
    } else {
      literal += value.slice(index, start + 2);
      index = start + 2;
      continue;
    }
    literal += value.slice(index, start);
    index = close + 1;
  }
  return { references, literal: literal + value.slice(index) };
}

function classifyValue(value: string, name: string): SecretFinding["kind"] | undefined {
  const keyIsSecret = isSecretLikeName(name);
  const { references, literal } = parseReferences(value);
  for (const { name: variable, fallback } of references) {
    if (fallback !== undefined && fallback.length > 0 && (keyIsSecret || isSecretLikeName(variable))) {
      return "fallback";
    }
  }
  if (!keyIsSecret || value.trim().length === 0 || isNonSecretMarker(value, name)) {
    return undefined;
  }
  // A value made only of references (optionally after an auth scheme and ":"
  // separators) holds no secret; any other literal text is still plaintext.
  const remainder = literal.replace(/[\s:]+/g, " ").trim();
  if (references.length > 0 && (remainder.length === 0 || authScheme.test(remainder))) {
    return undefined;
  }
  return "plaintext";
}

function sanitize(text: string): string {
  const clean = text.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, "");
  return clean.length > maxKeyLength ? `${clean.slice(0, maxKeyLength - 1)}…` : clean;
}

/**
 * Field names reported as written: OpenClaw schema words (config sections,
 * fixed channel ids, and secret field names). They are public vocabulary, so
 * none can be a user's secret. Every other path segment is a user-controlled
 * map key (a provider id, header name, env var name, ...) and is reported as
 * "*", so `models.providers.*.apiKey`, never the provider's name. A missing
 * entry only costs detail: an unknown field name also becomes "*".
 */
const schemaFieldNames = new Set([
  "gateway", "auth", "mode", "token", "tokens", "password", "passwords",
  "models", "providers", "apiKey", "apiKeys", "headers", "channels", "discord",
  "slack", "telegram", "whatsapp", "signal", "imessage", "matrix", "msteams",
  "googlechat", "irc", "line", "mattermost", "nostr", "feishu", "env", "vars",
  "tools", "web", "search", "fetch", "webSearch", "webFetch", "endpoint",
  "baseUrl", "agents", "defaults", "list", "plugins", "entries", "config",
  "skills", "profiles", "key", "keys", "secret", "secrets", "secretKey",
  "botToken", "appToken", "userToken", "signingSecret", "clientSecret",
  "accessToken", "refreshToken", "webhookSecret", "privateKey", "accessKey",
  "accessKeyId", "secretAccessKey", "apiToken", "authToken", "bearerToken",
  "credential", "credentials", "serviceAccount", "serviceAccountKey", "remote",
  "tailscale", "trustedProxy", "hooks", "memory", "browser", "session",
  "messages", "talk", "pin", "encryptionKey", "signingKey", "sessionKey",
  "cookie", "oauth", "accounts", "encryptKey", "authTag", "passphrase",
  "request", "proxy", "tls",
]);

function reportedKey(segments: PathSegment[]): string {
  return segments
    .map((segment) =>
      typeof segment === "number" ? String(segment) : schemaFieldNames.has(segment) ? segment : "*",
    )
    .join(".");
}

// A .env variable name is the key name itself and is shown, unless it looks
// like a credential (a 12-character run mixing letters and digits, or > 64).
function reportedEnvName(name: string): string {
  const credentialLike =
    name.length > 64 ||
    (name.match(/[A-Za-z0-9]{12,}/g) ?? []).some((run) => /[0-9]/.test(run) && /[A-Za-z]/.test(run));
  return credentialLike ? "*" : name;
}

function finding(
  kind: SecretFinding["kind"],
  file: string,
  segments: PathSegment[],
  line?: number,
): SecretFinding {
  const key = sanitize(line === undefined ? reportedKey(segments) : reportedEnvName(String(segments[0])));
  return line === undefined
    ? { kind, file: sanitize(file), key }
    : { kind, file: sanitize(file), line, key };
}

/**
 * Port of dotenv 18.0.3's parse() (BSD-2-Clause, Copyright (c) 2015, Scott
 * Motte), the parser OpenClaw uses for .env files, with line numbers added.
 * Ported rather than imported so the scanner loads no child_process code; a
 * test checks it against dotenv itself. Later assignments win, as in dotenv.
 */
const dotenvLine =
  /(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/gm;

/** Every assignment in file order, including ones a later line overrides. */
export function parseDotEnvAssignments(text: string): { key: string; value: string; line: number }[] {
  const assignments: { key: string; value: string; line: number }[] = [];
  const lines = text.replace(/\r\n?/gm, "\n");
  // Count newlines incrementally so line numbers stay linear in file size.
  let counted = 0;
  let line = 1;
  for (const match of lines.matchAll(dotenvLine)) {
    const key = match[1]!;
    let value = (match[2] ?? "").trim();
    const quote = value[0];
    value = value.replace(/^(['"`])([\s\S]*)\1$/gm, "$2");
    if (quote === '"') {
      value = value.replace(/\\n/g, "\n").replace(/\\r/g, "\r");
    }
    const keyOffset = match.index! + match[0].indexOf(key);
    for (; counted < keyOffset; counted += 1) {
      if (lines.charCodeAt(counted) === 10) line += 1;
    }
    assignments.push({ key, value, line });
  }
  return assignments;
}

/** dotenv's resulting map: the last assignment of each key wins. */
export function parseDotEnv(text: string): Map<string, { value: string; line: number }> {
  const parsed = new Map<string, { value: string; line: number }>();
  for (const { key, value, line } of parseDotEnvAssignments(text)) {
    parsed.delete(key);
    parsed.set(key, { value, line });
  }
  return parsed;
}

// An overridden assignment is still a secret on disk, so every one is checked.
function scanEnvFile(file: string, text: string): SecretFinding[] {
  return parseDotEnvAssignments(text)
    .filter(({ key, value }) => isSecretLikeName(key) && value.trim().length > 0)
    .map(({ key, line }) => finding("plaintext", file, [key], line));
}

/** Object keys are strings; array positions are numbers, so a digit-only key is never mistaken for one. */
type PathSegment = string | number;

type Visit = (value: string | number, segments: PathSegment[], name: string) => void;

/**
 * Walks every string and number with its path and the name that governs it:
 * the key itself, or for array items the nearest enclosing key. Returns false
 * if the document is too deep to finish.
 */
function walkValues(node: unknown, segments: PathSegment[], name: string, visit: Visit): boolean {
  if (segments.length > maxDepth) return false;
  if (typeof node === "string" || typeof node === "number") {
    visit(node, segments, name);
    return true;
  }
  if (Array.isArray(node)) {
    return node.every((item, index) => walkValues(item, [...segments, index], name, visit));
  }
  if (node !== null && typeof node === "object") {
    return Object.entries(node).every(([key, value]) => walkValues(value, [...segments, key], key, visit));
  }
  return true;
}

function scanConfig(
  file: string,
  parsed: unknown,
  prefix: PathSegment[] = [],
  rootName = "",
): SecretFinding[] | undefined {
  const findings: SecretFinding[] = [];
  const complete = walkValues(parsed, prefix, rootName, (value, segments, name) => {
    if (typeof value === "number") {
      if (isNumericSecretName(name)) findings.push(finding("plaintext", file, segments));
      return;
    }
    const kind = classifyValue(value, name);
    if (kind) findings.push(finding(kind, file, segments));
  });
  return complete ? findings : undefined;
}

interface IncludeSite {
  target: string;
  /** Logical config path of the object holding "$include". */
  segments: PathSegment[];
  /** The key that governs the included content (its parent's key). */
  name: string;
}

/**
 * Every "$include" in a document, in order, with where it is included. A value
 * that is not a string or an array of strings makes OpenClaw reject the
 * config, so it is recorded as invalid.
 */
function listIncludes(
  node: unknown,
  segments: PathSegment[] = [],
  name = "",
  found: { sites: IncludeSite[]; invalid: boolean } = { sites: [], invalid: false },
): { sites: IncludeSite[]; invalid: boolean } {
  if (segments.length > maxDepth || node === null || typeof node !== "object") return found;
  if (Array.isArray(node)) {
    node.forEach((item, index) => listIncludes(item, [...segments, index], name, found));
    return found;
  }
  for (const [key, value] of Object.entries(node)) {
    if (key === includeKey) {
      const items = Array.isArray(value) ? value : [value];
      for (const item of items) {
        if (typeof item === "string") found.sites.push({ target: item, segments, name });
        else found.invalid = true;
      }
    } else {
      listIncludes(value, [...segments, key], key, found);
    }
  }
  return found;
}

function scanModelsJson(file: string, parsed: unknown): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const providers = (parsed as { providers?: unknown } | null)?.providers;
  if (providers === null || typeof providers !== "object") return findings;
  for (const [providerId, provider] of Object.entries(providers)) {
    if (provider === null || typeof provider !== "object") continue;
    const { apiKey, headers } = provider as { apiKey?: unknown; headers?: unknown };
    const apiKeyKind = typeof apiKey === "string" ? classifyValue(apiKey, "apiKey") : undefined;
    if (apiKeyKind) findings.push(finding(apiKeyKind, file, ["providers", providerId, "apiKey"]));
    if (headers === null || typeof headers !== "object") continue;
    for (const [header, value] of Object.entries(headers)) {
      const kind = typeof value === "string" ? classifyValue(value, header) : undefined;
      if (kind) findings.push(finding(kind, file, ["providers", providerId, "headers", header]));
    }
  }
  return findings;
}

function unique(paths: string[]): string[] {
  return [...new Map(paths.map((file) => [path.resolve(file), file])).values()];
}

/**
 * Checks OpenClaw's on-disk secret locations, as listed by OpenClaw's own
 * secrets audit: the state-directory and config-directory .env files,
 * ~/.config/openclaw/gateway.env, openclaw.json, and each agent's models.json.
 * Auth-profile databases and the live process environment are not scanned.
 */
export function assessPlaintextSecrets(
  locations: SecretLocations | (Omit<SecretLocations, "stateDir"> & { stateDir?: undefined }),
  reader: SecretFileReader = nodeSecretFileReader,
): PlaintextSecretsResult {
  const findings: SecretFinding[] = [];
  const unreadable: string[] = [];
  let unresolved = 0;
  const scanned: string[] = [];

  // A required file (an $include target) that is missing cannot be ruled out.
  // Returns the file's findings, or undefined if it was missing or unreadable.
  const read = (
    file: string,
    scan: (text: string) => SecretFinding[] | undefined,
    required = false,
  ): SecretFinding[] | undefined => {
    const result = reader.readText(file);
    if (result.status === "missing" && !required) return undefined;
    const found = result.status === "ok" ? scan(result.text) : undefined;
    if (found === undefined) {
      unreadable.push(sanitize(file));
      return undefined;
    }
    scanned.push(sanitize(file));
    return found;
  };
  const parse = (text: string): unknown => {
    try {
      return JSON5.parse(text);
    } catch {
      // Parser messages can quote file bytes; they are never surfaced.
      return undefined;
    }
  };

  const envFiles = unique([
    ...(locations.stateDir ? [path.join(locations.stateDir, ".env")] : []),
    path.join(path.dirname(locations.configPath), ".env"),
    ...(locations.homeDirKnown === false ? [] : [path.join(locations.homeDir, ".config", "openclaw", "gateway.env")]),
  ]);
  for (const file of envFiles) findings.push(...(read(file, (text) => scanEnvFile(file, text)) ?? []));

  // OpenClaw's $include rules (src/config/includes.ts): paths resolve against
  // the including file, must stay inside the config directory or an
  // OPENCLAW_INCLUDE_ROOTS root, and nest at most ten deep. Anything OpenClaw
  // would refuse (outside the roots, too deep, malformed) makes it reject the
  // config, so it is graded unknown rather than skipped.
  const includeRoots = [path.dirname(locations.configPath), ...(locations.includeRoots ?? [])].map(
    (root) => path.resolve(root),
  );
  const insideIncludeRoot = (file: string) =>
    includeRoots.some((root) => {
      const relative = path.relative(root, file);
      return (
        relative !== "" &&
        relative !== ".." &&
        !relative.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(relative)
      );
    });
  // Each visit is one file read in one include context (logical path and
  // governing key), so a file included at two sites is checked under each.
  // A visit is redone when a shallower include reaches it, replacing its
  // earlier findings, so coverage does not depend on traversal order; equal
  // or deeper revisits stop, so cycles end.
  const shallowestDepth = new Map<string, number>();
  const configFindings = new Map<string, SecretFinding[]>();
  const reachedFiles = new Set<string>();
  const tooDeep: string[] = [];
  const refused: string[] = [];
  let visits = 0;
  const scanConfigFile = (file: string, depth: number, prefix: PathSegment[], name: string) => {
    const visit = `${path.resolve(file)}\u0000${name}\u0000${JSON.stringify(prefix)}`;
    const previous = shallowestDepth.get(visit);
    if (previous !== undefined && previous <= depth) return;
    if (visits >= maxIncludeVisits) {
      // Not scanned in this context, so secrets there cannot be ruled out.
      refused.push(sanitize(file));
      return;
    }
    visits += 1;
    shallowestDepth.set(visit, depth);
    reachedFiles.add(path.resolve(file));
    const includes: IncludeSite[] = [];
    const found = read(
      file,
      (text) => {
        const parsed = parse(text);
        if (parsed === undefined) return undefined;
        const { sites, invalid } = listIncludes(parsed);
        // The file's own findings still count; what it cannot include is unknown.
        if (invalid) refused.push(sanitize(file));
        for (const site of sites) {
          const target = path.isAbsolute(site.target)
            ? path.normalize(site.target)
            : path.resolve(path.dirname(file), site.target);
          if (!insideIncludeRoot(target)) {
            refused.push(sanitize(target));
            continue;
          }
          // Included content sits at the site's logical path, under its key.
          includes.push({
            target,
            segments: [...prefix, ...site.segments],
            name: site.segments.length > 0 ? site.name : name,
          });
        }
        return scanConfig(file, parsed, prefix, name);
      },
      depth > 0,
    );
    configFindings.set(visit, found ?? []);
    for (const site of includes) {
      if (depth + 1 > maxIncludeDepth) {
        // Unless another route reaches it, the file cannot be ruled out.
        tooDeep.push(site.target);
        continue;
      }
      scanConfigFile(site.target, depth + 1, site.segments, site.name);
    }
  };
  scanConfigFile(locations.configPath, 0, [], "");
  for (const target of tooDeep) {
    if (!reachedFiles.has(path.resolve(target))) unreadable.push(sanitize(target));
  }
  unreadable.push(...refused);
  for (const found of configFindings.values()) findings.push(...found);

  const agentsRoot = locations.stateDir ? path.join(locations.stateDir, "agents") : undefined;
  const agents = agentsRoot ? reader.listDirectories(agentsRoot) : "unreadable";
  // Other agents' models.json files cannot be found, so secrets cannot be ruled out.
  if (agents === "unreadable") {
    if (agentsRoot) unreadable.push(sanitize(agentsRoot));
    else unresolved += 1;
  }
  const modelsFiles = unique([
    ...(agentsRoot ? [path.join(agentsRoot, "main", "agent", "models.json")] : []),
    ...(agents === "unreadable" ? [] : [...agents].sort()).map((agent) =>
      path.join(agentsRoot!, agent, "agent", "models.json"),
    ),
    ...(locations.agentDirs ?? []).map((dir) => path.join(dir, "models.json")),
  ]);
  for (const file of modelsFiles) {
    const found = read(file, (text) => {
      const parsed = parse(text);
      return parsed === undefined ? undefined : scanModelsJson(file, parsed);
    });
    findings.push(...(found ?? []));
  }

  // A rescanned include file is listed once.
  const dedupe = (items: string[]) => [...new Set(items)];
  unreadable.splice(0, unreadable.length, ...dedupe(unreadable));
  scanned.splice(0, scanned.length, ...dedupe(scanned));

  const files = new Set(findings.map((item) => item.file)).size;
  const coverageGaps = unreadable.length + unresolved;
  const unreadableNote = unresolved === 0
    ? unreadable.length === 0
      ? ""
      : `${unreadable.length} file${unreadable.length === 1 ? "" : "s"} could not be read`
    : `${coverageGaps} location${coverageGaps === 1 ? "" : "s"} could not be checked`;
  let summary: string;
  if (findings.length > 0) {
    summary =
      `${findings.length} plaintext secret${findings.length === 1 ? "" : "s"} found in ` +
      `${files} file${files === 1 ? "" : "s"}${unreadableNote ? `; ${unreadableNote}` : ""}.`;
  } else if (coverageGaps > 0) {
    summary = `${unreadableNote}; plaintext secrets could not be ruled out.`;
  } else {
    summary = "No plaintext secrets found in OpenClaw's config, .env, or models.json files.";
  }

  return {
    grade: findings.length > 0 ? "warning" : coverageGaps > 0 ? "unknown" : "pass",
    findings,
    unreadable,
    ...(unresolved > 0 ? { unresolved } : {}),
    scanned,
    summary,
  };
}

/** Read-only file access: files are opened for reading only and capped in size. */
export const nodeSecretFileReader: SecretFileReader = {
  readText(file) {
    let fd: number | undefined;
    try {
      // stat first: opening a FIFO for reading would block until a writer appears.
      const before = statSync(file);
      if (!before.isFile() || before.size > maxFileBytes) return { status: "unreadable" };
      const nonBlocking = (constants as { O_NONBLOCK?: number }).O_NONBLOCK ?? 0;
      fd = openSync(file, constants.O_RDONLY | nonBlocking);
      const stats = fstatSync(fd);
      if (!stats.isFile() || stats.size > maxFileBytes) return { status: "unreadable" };
      return { status: "ok", text: readFileSync(fd, "utf8") };
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      return code === "ENOENT" || code === "ENOTDIR" ? { status: "missing" } : { status: "unreadable" };
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
  },
  listDirectories(dir) {
    try {
      return readdirSync(dir, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => entry.name)
        .sort();
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      return code === "ENOENT" || code === "ENOTDIR" ? [] : "unreadable";
    }
  },
};
