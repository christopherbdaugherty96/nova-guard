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
}

export type SecretFileRead =
  | { status: "missing" }
  | { status: "unreadable" }
  | { status: "ok"; text: string };

export interface SecretFileReader {
  readText(file: string): SecretFileRead;
  /** Names of real subdirectories (symlinks are not followed); [] if absent. */
  listDirectories(dir: string): string[];
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
  /** Files that were read and checked. */
  scanned: string[];
  summary: string;
}

/** Larger files are not read; a real config or .env is far smaller. */
const maxFileBytes = 1024 * 1024;
const maxDepth = 64;
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
  if (normalized === "key" || normalized === "authorization" || normalized === "proxy-authorization") {
    return true;
  }
  if (indirectNameSuffix.test(normalized)) {
    return false;
  }
  return secretNameFragments.some((fragment) => normalized.includes(fragment));
}

/** Numbers are checked only under names that hold a secret, never counts like maxTokens. */
function isNumericSecretName(name: string): boolean {
  const normalized = normalizeName(name);
  return (
    !indirectNameSuffix.test(normalized) &&
    ["password", "passwd", "secret"].some((fragment) => normalized.includes(fragment))
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
const nonSecretMarkerPrefixes = ["oauth:", "secretref-env:"];
// Persisted env-var-name markers such as "OPENAI_API_KEY". A real credential
// is not an upper-case identifier ending in _KEY or _TOKEN.
const envNameMarker = /^[A-Z][A-Z0-9_]*_(?:API_KEY|KEY|TOKEN)$/;

function isNonSecretMarker(value: string, name: string): boolean {
  const trimmed = value.trim();
  return (
    nonSecretMarkers.has(trimmed) ||
    nonSecretMarkerPrefixes.some((prefix) => trimmed.startsWith(prefix)) ||
    (normalizeName(name).endsWith("api-key") && envNameMarker.test(trimmed))
  );
}

// OpenClaw substitutes only upper-case names; "$${VAR}" is an escaped literal.
// The fallback is bounded so unterminated input cannot cause quadratic scans.
const envReference = /(?<!\$)\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]{0,512}))?\}/g;
// Scheme words that may precede a reference, as in "Bearer ${TOKEN}".
const authScheme = /^(?:bearer|basic|token)$/i;

function classifyValue(value: string, name: string): SecretFinding["kind"] | undefined {
  const keyIsSecret = isSecretLikeName(name);
  let hasReference = false;
  for (const [, variable, fallback] of value.matchAll(envReference)) {
    hasReference = true;
    if (fallback !== undefined && fallback.length > 0 && (keyIsSecret || isSecretLikeName(variable!))) {
      return "fallback";
    }
  }
  if (!keyIsSecret || value.trim().length === 0 || isNonSecretMarker(value, name)) {
    return undefined;
  }
  // A value made only of references (optionally after an auth scheme) holds no
  // secret; any other literal text around a reference is still plaintext.
  const literal = value.replace(envReference, "").trim();
  if (hasReference && (literal.length === 0 || authScheme.test(literal))) {
    return undefined;
  }
  return "plaintext";
}

function sanitize(text: string): string {
  const clean = text.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, "");
  return clean.length > maxKeyLength ? `${clean.slice(0, maxKeyLength - 1)}…` : clean;
}

// A path segment that looks like a credential (long, or a long run mixing
// letters and digits) is replaced so a user-chosen map key cannot leak one.
function isCredentialLikeSegment(segment: string): boolean {
  if (segment.length >= 24) return true;
  return (segment.match(/[A-Za-z0-9]{12,}/g) ?? []).some((run) => /[0-9]/.test(run) && /[A-Za-z]/.test(run));
}

function reportedKey(segments: string[]): string {
  return segments.map((segment) => (isCredentialLikeSegment(segment) ? "<redacted>" : segment)).join(".");
}

function finding(kind: SecretFinding["kind"], file: string, segments: string[], line?: number): SecretFinding {
  const key = sanitize(reportedKey(segments));
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

export function parseDotEnv(text: string): Map<string, { value: string; line: number }> {
  const parsed = new Map<string, { value: string; line: number }>();
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
    parsed.delete(key);
    parsed.set(key, { value, line });
  }
  return parsed;
}

function scanEnvFile(file: string, text: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  for (const [key, { value, line }] of parseDotEnv(text)) {
    if (isSecretLikeName(key) && value.trim().length > 0) {
      findings.push(finding("plaintext", file, [key], line));
    }
  }
  return findings.sort((a, b) => a.line! - b.line!);
}

type Visit = (value: string | number, segments: string[], name: string) => void;

/**
 * Walks every string and number with its path and the name that governs it:
 * the key itself, or for array items the nearest enclosing key. Returns false
 * if the document is too deep to finish.
 */
function walkValues(node: unknown, segments: string[], name: string, visit: Visit): boolean {
  if (segments.length > maxDepth) return false;
  if (typeof node === "string" || typeof node === "number") {
    visit(node, segments, name);
    return true;
  }
  if (Array.isArray(node)) {
    return node.every((item, index) => walkValues(item, [...segments, String(index)], name, visit));
  }
  if (node !== null && typeof node === "object") {
    return Object.entries(node).every(([key, value]) => walkValues(value, [...segments, key], key, visit));
  }
  return true;
}

function scanConfig(file: string, parsed: unknown): SecretFinding[] | undefined {
  const findings: SecretFinding[] = [];
  const complete = walkValues(parsed, [], "", (value, segments, name) => {
    if (typeof value === "number") {
      if (isNumericSecretName(name)) findings.push(finding("plaintext", file, segments));
      return;
    }
    const kind = classifyValue(value, name);
    if (kind) findings.push(finding(kind, file, segments));
  });
  return complete ? findings : undefined;
}

function scanModelsJson(file: string, parsed: unknown): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const providers = (parsed as { providers?: unknown } | null)?.providers;
  if (providers === null || typeof providers !== "object") return findings;
  for (const [providerId, provider] of Object.entries(providers)) {
    if (provider === null || typeof provider !== "object") continue;
    const { apiKey, headers } = provider as { apiKey?: unknown; headers?: unknown };
    if (typeof apiKey === "string" && classifyValue(apiKey, "apiKey") !== undefined) {
      findings.push(finding("plaintext", file, ["providers", providerId, "apiKey"]));
    }
    if (headers === null || typeof headers !== "object") continue;
    for (const [header, value] of Object.entries(headers)) {
      if (typeof value === "string" && classifyValue(value, header) !== undefined) {
        findings.push(finding("plaintext", file, ["providers", providerId, "headers", header]));
      }
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
  locations: SecretLocations,
  reader: SecretFileReader = nodeSecretFileReader,
): PlaintextSecretsResult {
  const findings: SecretFinding[] = [];
  const unreadable: string[] = [];
  const scanned: string[] = [];

  const read = (file: string, scan: (text: string) => SecretFinding[] | undefined) => {
    const result = reader.readText(file);
    if (result.status === "missing") return;
    const found = result.status === "ok" ? scan(result.text) : undefined;
    if (found === undefined) {
      unreadable.push(sanitize(file));
      return;
    }
    scanned.push(sanitize(file));
    findings.push(...found);
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
    path.join(locations.stateDir, ".env"),
    path.join(path.dirname(locations.configPath), ".env"),
    path.join(locations.homeDir, ".config", "openclaw", "gateway.env"),
  ]);
  for (const file of envFiles) read(file, (text) => scanEnvFile(file, text));

  read(locations.configPath, (text) => {
    const parsed = parse(text);
    return parsed === undefined ? undefined : scanConfig(locations.configPath, parsed);
  });

  const agentsRoot = path.join(locations.stateDir, "agents");
  const modelsFiles = unique([
    path.join(agentsRoot, "main", "agent", "models.json"),
    ...reader
      .listDirectories(agentsRoot)
      .sort()
      .map((agent) => path.join(agentsRoot, agent, "agent", "models.json")),
  ]);
  for (const file of modelsFiles) {
    read(file, (text) => {
      const parsed = parse(text);
      return parsed === undefined ? undefined : scanModelsJson(file, parsed);
    });
  }

  const files = new Set(findings.map((item) => item.file)).size;
  const unreadableNote =
    unreadable.length === 0
      ? ""
      : `${unreadable.length} file${unreadable.length === 1 ? "" : "s"} could not be read`;
  let summary: string;
  if (findings.length > 0) {
    summary =
      `${findings.length} plaintext secret${findings.length === 1 ? "" : "s"} found in ` +
      `${files} file${files === 1 ? "" : "s"}${unreadableNote ? `; ${unreadableNote}` : ""}.`;
  } else if (unreadable.length > 0) {
    summary = `${unreadableNote}; plaintext secrets could not be ruled out.`;
  } else {
    summary = "No plaintext secrets found in OpenClaw's config, .env, or models.json files.";
  }

  return {
    grade: findings.length > 0 ? "warning" : unreadable.length > 0 ? "unknown" : "pass",
    findings,
    unreadable,
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
    } catch {
      return [];
    }
  },
};
