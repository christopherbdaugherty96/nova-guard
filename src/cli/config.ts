import { realpathSync } from "node:fs";
import path from "node:path";

import JSON5 from "json5";

import { nodeSecretFileReader, type SecretFileReader } from "../checks/plaintext-secrets.js";
import type { SkillConfigInput } from "../checks/risky-skills.js";

/**
 * Reads OpenClaw's config and resolves `$include` the way OpenClaw does
 * (src/config/includes.ts and src/infra/deep-merge.ts at b8324c64): a string
 * or array of strings anywhere in the document, resolved against the
 * including file, confined (lexically and after symlinks) to the config
 * directory or an OPENCLAW_INCLUDE_ROOTS root, at most ten deep, no cycles;
 * several includes deep-merge in order (arrays concatenate, objects merge,
 * other values replace), then sibling keys merge over them. Anything OpenClaw
 * would reject makes it refuse the config, so the result is "unreadable",
 * never a partial config. Read-only.
 */

const includeKey = "$include";
const maxIncludeDepth = 10;
const maxIncludePathLength = 4096;
// OpenClaw has no fan-out limit; past this many include loads the config is
// treated as unreadable rather than expanded further.
const maxIncludeLoads = 256;
const blockedKeys = new Set(["__proto__", "constructor", "prototype"]);

class IncludeRejected extends Error {}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function sanitize(value: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (!blockedKeys.has(key)) out[key] = isPlainObject(entry) ? sanitize(entry) : entry;
  }
  return out;
}

// OpenClaw's mergeDeep with { arrays: "concat", undefinedValues: "replace" }.
function deepMerge(base: unknown, override: unknown): unknown {
  if (Array.isArray(base) && Array.isArray(override)) return [...base, ...override];
  if (!isPlainObject(base) || !isPlainObject(override)) return override;
  const merged = sanitize(base);
  for (const [key, value] of Object.entries(override)) {
    if (blockedKeys.has(key)) continue;
    const current = merged[key];
    if (isPlainObject(value)) {
      merged[key] = isPlainObject(current) ? deepMerge(current, value) : sanitize(value);
    } else if (Array.isArray(current) && Array.isArray(value)) {
      merged[key] = [...current, ...value];
    } else {
      merged[key] = value;
    }
  }
  return merged;
}

function parse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return JSON5.parse(text);
  }
}

function isInside(base: string, candidate: string): boolean {
  const relative = path.relative(base, candidate);
  return relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function tryRealpath(file: string): string {
  try {
    return realpathSync(file);
  } catch {
    return file;
  }
}

export function loadOpenClawConfig(
  configPath: string,
  includeRoots: readonly string[],
  reader: SecretFileReader = nodeSecretFileReader,
): SkillConfigInput {
  const main = reader.readText(configPath);
  if (main.status === "missing") return { status: "missing" };
  if (main.status === "unreadable") return { status: "unreadable" };

  const roots = [path.dirname(path.resolve(configPath)), ...includeRoots.filter((root) => path.isAbsolute(root))]
    .map((root) => path.normalize(root))
    .map((root) => ({ lexical: root, real: path.normalize(tryRealpath(root)) }));
  let loads = 0;

  const resolveInclude = (target: string, basePath: string): string => {
    if (target.includes("\0") || target.length >= maxIncludePathLength) throw new IncludeRejected();
    const resolved = path.normalize(path.isAbsolute(target) ? target : path.resolve(path.dirname(basePath), target));
    if (resolved.length >= maxIncludePathLength) throw new IncludeRejected();
    if (!roots.some((root) => isInside(root.lexical, resolved))) throw new IncludeRejected();
    let real: string;
    try {
      real = path.normalize(realpathSync(resolved));
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      // A missing file still fails below, when it cannot be read.
      if (code === "ENOENT" || code === "ENOTDIR") return resolved;
      throw new IncludeRejected();
    }
    if (!roots.some((root) => isInside(root.real, real))) throw new IncludeRejected();
    return resolved;
  };

  const process = (value: unknown, basePath: string, visited: ReadonlySet<string>, depth: number): unknown => {
    if (Array.isArray(value)) return value.map((item) => process(item, basePath, visited, depth));
    if (!isPlainObject(value)) return value;
    if (!Object.hasOwn(value, includeKey)) {
      const out: Record<string, unknown> = {};
      for (const [key, entry] of Object.entries(value)) {
        if (!blockedKeys.has(key)) out[key] = process(entry, basePath, visited, depth);
      }
      return out;
    }

    const includeValue = value[includeKey];
    const targets = Array.isArray(includeValue) ? includeValue : [includeValue];
    if (!Array.isArray(includeValue) && typeof includeValue !== "string") throw new IncludeRejected();
    const loaded: unknown[] = [];
    for (const target of targets) {
      if (typeof target !== "string") throw new IncludeRejected();
      const resolved = resolveInclude(target, basePath);
      if (visited.has(resolved) || depth >= maxIncludeDepth) throw new IncludeRejected();
      loads += 1;
      if (loads > maxIncludeLoads) throw new IncludeRejected();
      const file = reader.readText(resolved);
      if (file.status !== "ok") throw new IncludeRejected();
      loaded.push(process(parse(file.text), resolved, new Set([...visited, resolved]), depth + 1));
    }
    const included = Array.isArray(includeValue)
      ? loaded.reduce<unknown>((current, entry) => deepMerge(current, entry), {})
      : loaded[0];

    const siblings = Object.keys(value).filter((key) => key !== includeKey && !blockedKeys.has(key));
    if (siblings.length === 0) return included;
    if (!isPlainObject(included)) throw new IncludeRejected();
    const rest: Record<string, unknown> = {};
    for (const key of siblings) rest[key] = process(value[key], basePath, visited, depth);
    return deepMerge(included, rest);
  };

  try {
    const resolvedMain = path.normalize(path.resolve(configPath));
    return { status: "ok", config: process(parse(main.text), resolvedMain, new Set([resolvedMain]), 0) };
  } catch {
    // Parse errors and rejected includes alike: OpenClaw would not load this config.
    return { status: "unreadable" };
  }
}
