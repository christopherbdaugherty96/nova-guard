import { realpathSync, statSync } from "node:fs";
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
// OpenClaw's mergeDeep drops these when includes merge; plain traversal only
// loses __proto__ (which JSON parsing would turn into a prototype).
const blockedKeys = new Set(["__proto__", "constructor", "prototype"]);
// Each merge copies the accumulated result, so many large includes cost
// quadratic time (in OpenClaw too); past this many copied entries the config
// is treated as unreadable instead.
const maxMergeWork = 2_000_000;

class IncludeRejected extends Error {}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

interface MergeBudget {
  work: number;
}

function charge(budget: MergeBudget, amount: number): void {
  budget.work += amount;
  if (budget.work > maxMergeWork) throw new IncludeRejected();
}

// A deep copy: every nested key it copies is charged to the merge budget.
function sanitize(value: Record<string, unknown>, budget: MergeBudget): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    charge(budget, 1);
    if (!blockedKeys.has(key)) out[key] = isPlainObject(entry) ? sanitize(entry, budget) : entry;
  }
  return out;
}

function sizeOf(value: unknown): number {
  return Array.isArray(value) ? value.length : isPlainObject(value) ? Object.keys(value).length : 1;
}

// OpenClaw's mergeDeep with { arrays: "concat", undefinedValues: "replace" }.
function deepMerge(base: unknown, override: unknown, budget: MergeBudget): unknown {
  if (Array.isArray(base) && Array.isArray(override)) {
    charge(budget, base.length + override.length);
    return [...base, ...override];
  }
  if (!isPlainObject(base) || !isPlainObject(override)) return override;
  charge(budget, sizeOf(override));
  const merged = sanitize(base, budget);
  for (const [key, value] of Object.entries(override)) {
    if (blockedKeys.has(key)) continue;
    const current = merged[key];
    if (isPlainObject(value)) {
      merged[key] = isPlainObject(current) ? deepMerge(current, value, budget) : sanitize(value, budget);
    } else if (Array.isArray(current) && Array.isArray(value)) {
      charge(budget, current.length + value.length);
      merged[key] = [...current, ...value];
    } else {
      merged[key] = value;
    }
  }
  return merged;
}

/**
 * OpenClaw refuses a config whose root is not an object (and its schema
 * rejects these sections in any other shape), so such a config is unreadable.
 */
function hasLoadableShape(config: unknown): boolean {
  if (!isPlainObject(config)) return false;
  const section = (value: unknown) => value === undefined || isPlainObject(value);
  const text = (value: unknown) => value === undefined || typeof value === "string";
  // A list of strings: OpenClaw's schema rejects any other element, and the
  // checks would otherwise silently skip it.
  const strings = (value: unknown) =>
    value === undefined || (Array.isArray(value) && value.every((item) => typeof item === "string"));
  // An agent entry: an object whose id, workspace, and agentDir are strings.
  const agent = (value: unknown) =>
    isPlainObject(value) && text(value.id) && text(value.workspace) && text(value.agentDir);
  const oneOf = (value: unknown, allowed: readonly string[]) =>
    value === undefined || (typeof value === "string" && allowed.includes(value));
  // A secret: a literal or ${VAR} string, or a SecretRef object.
  const secret = (value: unknown) => value === undefined || typeof value === "string" || isPlainObject(value);
  const gateway = config.gateway;
  const skills = config.skills;
  const agents = config.agents;
  const load = isPlainObject(skills) ? skills.load : undefined;
  // Every gateway field the gateway check reads, in the shapes and values
  // OpenClaw's schema accepts (docs/verified-openclaw-contract.md, Gateway).
  const gatewayOk = (value: Record<string, unknown>) => {
    const auth = value.auth;
    const tailscale = value.tailscale;
    return (
      oneOf(value.bind, ["auto", "loopback", "lan", "tailnet", "custom"]) &&
      text(value.customBindHost) &&
      strings(value.trustedProxies) &&
      section(tailscale) &&
      (!isPlainObject(tailscale) || oneOf(tailscale.mode, ["off", "serve", "funnel"])) &&
      section(auth) &&
      (!isPlainObject(auth) ||
        (oneOf(auth.mode, ["none", "token", "password", "trusted-proxy"]) &&
          secret(auth.token) &&
          secret(auth.password) &&
          section(auth.trustedProxy) &&
          (!isPlainObject(auth.trustedProxy) || text(auth.trustedProxy.userHeader))))
    );
  };
  return (
    section(gateway) &&
    section(agents) &&
    section(skills) &&
    (!isPlainObject(gateway) || gatewayOk(gateway)) &&
    (!isPlainObject(agents) ||
      ((agents.list === undefined || (Array.isArray(agents.list) && agents.list.every(agent))) &&
        section(agents.entries) &&
        (!isPlainObject(agents.entries) || Object.values(agents.entries).every(agent)) &&
        section(agents.defaults) &&
        (!isPlainObject(agents.defaults) || text(agents.defaults.workspace)))) &&
    section(load) &&
    (!isPlainObject(load) || (strings(load.extraDirs) && strings(load.allowSymlinkTargets)))
  );
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
  const budget: MergeBudget = { work: 0 };

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
    // OpenClaw's guarded open refuses hardlinked include files.
    try {
      if (statSync(real).nlink > 1) throw new IncludeRejected();
    } catch (error) {
      if (error instanceof IncludeRejected) throw error;
    }
    return resolved;
  };

  const process = (value: unknown, basePath: string, visited: ReadonlySet<string>, depth: number): unknown => {
    if (Array.isArray(value)) return value.map((item) => process(item, basePath, visited, depth));
    if (!isPlainObject(value)) return value;
    if (!Object.hasOwn(value, includeKey)) {
      const out: Record<string, unknown> = {};
      for (const [key, entry] of Object.entries(value)) {
        if (key !== "__proto__") out[key] = process(entry, basePath, visited, depth);
      }
      return out;
    }

    const includeValue = value[includeKey];
    const targets = Array.isArray(includeValue) ? includeValue : [includeValue];
    if (!Array.isArray(includeValue) && typeof includeValue !== "string") throw new IncludeRejected();
    // Several includes merge one at a time, so the merge budget applies before
    // every parsed file is held in memory at once.
    let included: unknown = Array.isArray(includeValue) ? {} : undefined;
    for (const target of targets) {
      if (typeof target !== "string") throw new IncludeRejected();
      const resolved = resolveInclude(target, basePath);
      if (visited.has(resolved) || depth >= maxIncludeDepth) throw new IncludeRejected();
      loads += 1;
      if (loads > maxIncludeLoads) throw new IncludeRejected();
      const file = reader.readText(resolved);
      if (file.status !== "ok") throw new IncludeRejected();
      const entry = process(parse(file.text), resolved, new Set([...visited, resolved]), depth + 1);
      included = Array.isArray(includeValue) ? deepMerge(included, entry, budget) : entry;
    }

    const siblings = Object.keys(value).filter((key) => key !== includeKey && key !== "__proto__");
    if (siblings.length === 0) return included;
    if (!isPlainObject(included)) throw new IncludeRejected();
    const rest: Record<string, unknown> = {};
    for (const key of siblings) rest[key] = process(value[key], basePath, visited, depth);
    return deepMerge(included, rest, budget);
  };

  try {
    const resolvedMain = path.normalize(path.resolve(configPath));
    const config = process(parse(main.text), resolvedMain, new Set([resolvedMain]), 0);
    return hasLoadableShape(config) ? { status: "ok", config } : { status: "unreadable" };
  } catch {
    // Parse errors and rejected includes alike: OpenClaw would not load this config.
    return { status: "unreadable" };
  }
}
