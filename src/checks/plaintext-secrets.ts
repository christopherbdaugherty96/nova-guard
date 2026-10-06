// Read-only check for plaintext secrets at rest in OpenClaw's files.
//
// Reports contain only a location (file, and line for .env files) and a key
// name. Secret values, any fragment of them, lengths, hashes, and parser error
// messages (which can quote file bytes) are never placed in a result.
import { closeSync, fstatSync, openSync, readdirSync, readFileSync } from "node:fs";
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

export function isSecretLikeName(name: string): boolean {
  const normalized = name.toLowerCase().replace(/_/g, "-");
  if (normalized === "key" || normalized === "authorization" || normalized === "proxy-authorization") {
    return true;
  }
  if (indirectNameSuffix.test(normalized)) {
    return false;
  }
  return secretNameFragments.some((fragment) => normalized.includes(fragment));
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

function isNonSecretMarker(value: string): boolean {
  const trimmed = value.trim();
  return (
    nonSecretMarkers.has(trimmed) ||
    nonSecretMarkerPrefixes.some((prefix) => trimmed.startsWith(prefix)) ||
    envNameMarker.test(trimmed)
  );
}

// OpenClaw substitutes only upper-case names; "$${VAR}" is an escaped literal.
const envReference = /(?<!\$)\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}/g;

function classifyValue(value: string, keyIsSecret: boolean): SecretFinding["kind"] | undefined {
  let hasReference = false;
  for (const [, variable, fallback] of value.matchAll(envReference)) {
    hasReference = true;
    if (fallback !== undefined && fallback.length > 0 && (keyIsSecret || isSecretLikeName(variable!))) {
      return "fallback";
    }
  }
  if (!keyIsSecret || hasReference || value.trim().length === 0 || isNonSecretMarker(value)) {
    return undefined;
  }
  return "plaintext";
}

function sanitize(text: string): string {
  const clean = text.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, "");
  return clean.length > maxKeyLength ? `${clean.slice(0, maxKeyLength - 1)}…` : clean;
}

function finding(kind: SecretFinding["kind"], file: string, key: string, line?: number): SecretFinding {
  return line === undefined
    ? { kind, file: sanitize(file), key: sanitize(key) }
    : { kind, file: sanitize(file), line, key: sanitize(key) };
}

const envAssignment = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/;

function scanEnvFile(file: string, text: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  text.split(/\r?\n/).forEach((line, index) => {
    const match = envAssignment.exec(line);
    if (!match || !isSecretLikeName(match[1]!)) return;
    let value = match[2]!.trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (value.trim().length > 0) {
      findings.push(finding("plaintext", file, match[1]!, index + 1));
    }
  });
  return findings;
}

/** Walks every string in a parsed document; returns false if too deep to finish. */
function walkStrings(
  node: unknown,
  pathSegments: string[],
  visit: (value: string, segments: string[]) => void,
): boolean {
  if (pathSegments.length > maxDepth) return false;
  if (typeof node === "string") {
    visit(node, pathSegments);
    return true;
  }
  if (Array.isArray(node)) {
    return node.every((item, index) => walkStrings(item, [...pathSegments, String(index)], visit));
  }
  if (node !== null && typeof node === "object") {
    return Object.entries(node).every(([key, value]) => walkStrings(value, [...pathSegments, key], visit));
  }
  return true;
}

function scanConfig(file: string, parsed: unknown): SecretFinding[] | undefined {
  const findings: SecretFinding[] = [];
  const complete = walkStrings(parsed, [], (value, segments) => {
    const name = segments[segments.length - 1] ?? "";
    const kind = classifyValue(value, isSecretLikeName(name));
    if (kind) findings.push(finding(kind, file, segments.join(".")));
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
    if (typeof apiKey === "string" && apiKey.trim().length > 0 && !isNonSecretMarker(apiKey)) {
      findings.push(finding("plaintext", file, `providers.${providerId}.apiKey`));
    }
    if (headers === null || typeof headers !== "object") continue;
    for (const [header, value] of Object.entries(headers)) {
      if (
        typeof value === "string" &&
        value.trim().length > 0 &&
        isSecretLikeName(header) &&
        !isNonSecretMarker(value)
      ) {
        findings.push(finding("plaintext", file, `providers.${providerId}.headers.${header}`));
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
      fd = openSync(file, "r");
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
