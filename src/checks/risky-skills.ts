import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readSync,
  realpathSync,
  statSync,
} from "node:fs";
import path from "node:path";

import { isScannable, scanSkillContent, scanSource, type SkillRuleSeverity } from "./skill-scan-rules.js";

/**
 * Risky skill patterns, using OpenClaw's own installed-skill code-safety rules
 * (`openclaw security audit --deep`, ported in skill-scan-rules.ts) over the
 * skill roots OpenClaw loads from (src/skills/loading at
 * b8324c64acf5979602711163cb4b5c01ea557388). Discovery deliberately errs
 * toward extra coverage: a directory OpenClaw would skip only costs noise,
 * while one it loads but nova-guard skips would be a false pass. Anything
 * that cannot be evaluated is reported as unknown. Read-only throughout.
 */

export interface SkillLocations {
  stateDir: string;
  /** OpenClaw's effective home (OPENCLAW_HOME, else the OS home); "~" in config expands to it. */
  homeDir: string;
  /** The OS home, when it differs from homeDir; ~/.agents/skills lives here. */
  osHomeDir?: string;
  /** OPENCLAW_WORKSPACE_DIR, when set; otherwise <stateDir>/workspace. */
  workspaceDir?: string;
}

/** The resolved OpenClaw config (after $include), or why it is unavailable. */
export type SkillConfigInput =
  | { status: "ok"; config: unknown }
  | { status: "missing" }
  | { status: "unreadable" };

export interface RiskySkillFinding {
  ruleId: string;
  severity: SkillRuleSeverity;
  /** The skill directory as discovered (a location, never the skill's name field). */
  skillDir: string;
  file: string;
  line: number;
}

export type SkillUnknownReason =
  | "unreadable"
  | "too-large"
  | "scan-truncated"
  | "discovery-truncated"
  | "relative-path"
  | "config-unreadable"
  | "time-limit";

export interface RiskySkillsResult {
  grade: "pass" | "warning" | "critical" | "unknown";
  findings: RiskySkillFinding[];
  /** Locations that could not be evaluated, so risks there cannot be ruled out. */
  unknown: { path: string; reason: SkillUnknownReason }[];
  /** Distinct skill directories found. */
  skills: number;
  summary: string;
}

interface SkillDirent {
  name: string;
  isFile(): boolean;
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
}

export type SkillTextRead = { status: "ok"; text: string } | { status: "too-large" } | { status: "not-file" };

/** Read-only filesystem access; errors are thrown with their errno code. */
export interface SkillFs {
  realpath(file: string): string;
  lstat(file: string): { isFile(): boolean; isDirectory(): boolean; isSymbolicLink(): boolean };
  stat(file: string): { isFile(): boolean; isDirectory(): boolean };
  readdir(dir: string): SkillDirent[];
  readText(file: string, maxBytes: number): SkillTextRead;
}

export const nodeSkillFs: SkillFs = {
  // The native resolver is one syscall; the JS one lstats every path prefix,
  // which is quadratic in depth.
  realpath: (file) => realpathSync.native(file),
  lstat: (file) => lstatSync(file),
  stat: (file) => statSync(file),
  readdir: (dir) => readdirSync(dir, { withFileTypes: true }),
  readText(file, maxBytes) {
    // stat first: opening a FIFO for reading would block until a writer appears.
    const before = statSync(file);
    if (!before.isFile()) return { status: "not-file" };
    if (before.size > maxBytes) return { status: "too-large" };
    const nonBlocking = (constants as { O_NONBLOCK?: number }).O_NONBLOCK ?? 0;
    const fd = openSync(file, constants.O_RDONLY | nonBlocking);
    try {
      const stats = fstatSync(fd);
      if (!stats.isFile()) return { status: "not-file" };
      // Read at most one byte past the limit, so a growing file is still bounded.
      const buffer = Buffer.alloc(maxBytes + 1);
      let length = 0;
      while (length < buffer.length) {
        const read = readSync(fd, buffer, length, buffer.length - length, null);
        if (read === 0) break;
        length += read;
      }
      if (length > maxBytes) return { status: "too-large" };
      return { status: "ok", text: buffer.subarray(0, length).toString("utf8") };
    } finally {
      closeSync(fd);
    }
  },
};

// OpenClaw's limits: SKILL.md files over 256,000 bytes are not loaded; the
// code scan reads at most 500 script files of up to 1 MiB, walking at most
// 100,000 directory entries per skill.
const maxSkillFileBytes = 256_000;
const maxScriptFileBytes = 1024 * 1024;
const maxScriptFiles = 500;
const maxScanEntries = 100_000;
// Deepest skill OpenClaw loads: root/skills (nested root), a child "skills"
// at grouped depth 0, then six grouped levels = 8. One more for margin.
const maxDiscoveryDepth = 9;
// Total script-file directory entries walked across all skills.
const maxTotalScanEntries = 1_000_000;
const maxDiscoveryDirsPerRoot = 20_000;
// Directories visited across every root together.
const defaultMaxDiscoveryDirs = 200_000;
// Symlinks resolved during discovery, across every root together.
const defaultMaxSymlinkResolutions = 20_000;
// Resolving a link costs about depth^2 path lookups (realpath(3) checks every
// prefix), so links are also charged by their target's depth squared. This
// caps the worst case near a minute while 20,000 shallow links stay well
// inside it.
const defaultMaxSymlinkCost = 2_000_000_000;
// What a link costs to resolve cannot be known in advance (multi-hop chains,
// links that fail deep in a tree), so the time spent resolving discovery
// links is also capped. 20,000 ordinary links take well under a second.
const defaultMaxSymlinkMillis = 30_000;
// A hard ceiling on the whole assessment. Hostile trees can make individual
// filesystem calls arbitrarily slow (deep symlink chains), so per-item budgets
// alone cannot bound the run; past this, the remainder is unknown, never pass.
const defaultMaxMillis = 120_000;
const maxReportedPathLength = 4096;

type SymlinkPolicy = "any" | "contained" | "contained-or-allowed";

interface SkillRoot {
  dir: string;
  symlinks: SymlinkPolicy;
  /** Workshop roots hold skills; the root itself is never one. */
  container?: boolean;
}

function errorCode(error: unknown): string | undefined {
  return (error as NodeJS.ErrnoException | undefined)?.code;
}

function isMissing(error: unknown): boolean {
  const code = errorCode(error);
  return code === "ENOENT" || code === "ENOTDIR";
}

function sanitize(text: string): string {
  const clean = text.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, "");
  return clean.length > maxReportedPathLength ? `${clean.slice(0, maxReportedPathLength - 1)}…` : clean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isInside(base: string, candidate: string): boolean {
  const relative = path.relative(base, candidate);
  return (
    relative === "" ||
    (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  );
}

// OpenClaw's normalizeAgentId (packages/normalization-core/src/agent-id.ts).
function normalizeAgentId(value: unknown): string {
  const trimmed = typeof value === "string" ? value.trim() : "";
  const normalized = trimmed.toLowerCase();
  if (/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(trimmed)) return normalized;
  const agentId = normalized
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+/, "")
    .replace(/-+$/, "")
    .slice(0, 64);
  return agentId || "main";
}

function stringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.trim() !== "")
    : [];
}

export function assessRiskySkills(
  locations: SkillLocations,
  configInput: SkillConfigInput,
  fs: SkillFs = nodeSkillFs,
  limits: {
    maxDiscoveryDirs?: number;
    maxSymlinkResolutions?: number;
    maxSymlinkCost?: number;
    maxSymlinkMillis?: number;
    maxMillis?: number;
    now?: () => number;
  } = {},
): RiskySkillsResult {
  const maxDiscoveryDirs = limits.maxDiscoveryDirs ?? defaultMaxDiscoveryDirs;
  const maxSymlinkResolutions = limits.maxSymlinkResolutions ?? defaultMaxSymlinkResolutions;
  const maxSymlinkCost = limits.maxSymlinkCost ?? defaultMaxSymlinkCost;
  let symlinkResolutions = 0;
  let symlinkCost = 0;
  const maxSymlinkMillis = limits.maxSymlinkMillis ?? defaultMaxSymlinkMillis;
  const now = limits.now ?? (() => performance.now());
  let symlinkMillis = 0;
  const unknown: RiskySkillsResult["unknown"] = [];
  const findings: RiskySkillFinding[] = [];
  const markUnknown = (location: string, reason: SkillUnknownReason) =>
    unknown.push({ path: sanitize(location), reason });
  const deadline = now() + (limits.maxMillis ?? defaultMaxMillis);
  let timedOut = false;
  const timeUp = (): boolean => {
    if (!timedOut && now() > deadline) {
      timedOut = true;
      markUnknown("scan", "time-limit");
    }
    return timedOut;
  };

  if (configInput.status === "unreadable") markUnknown("config", "config-unreadable");
  const config = configInput.status === "ok" && isRecord(configInput.config) ? configInput.config : {};
  const skillsConfig = isRecord(config.skills) ? config.skills : {};
  const load = isRecord(skillsConfig.load) ? skillsConfig.load : {};
  const agents = isRecord(config.agents) ? config.agents : {};
  const defaults = isRecord(agents.defaults) ? agents.defaults : {};

  // OpenClaw's resolveUserPath: "~" expands to home; anything else relative
  // resolves against OpenClaw's working directory, which is not knowable here.
  const userPath = (raw: string): string | undefined => {
    const trimmed = raw.trim();
    if (trimmed === "") return undefined;
    const expanded = trimmed.replace(/^~(?=$|[\\/])/, () => locations.homeDir);
    if (!path.isAbsolute(expanded)) {
      markUnknown(trimmed, "relative-path");
      return undefined;
    }
    return path.resolve(expanded);
  };

  // Workspaces (src/agents/agent-scope-config.ts resolveAgentWorkspaceDir).
  // Every candidate a roster could select is included.
  const workspaces: string[] = [locations.workspaceDir ?? path.join(locations.stateDir, "workspace")];
  const defaultsWorkspace =
    typeof defaults.workspace === "string" ? userPath(defaults.workspace) : undefined;
  if (defaultsWorkspace) workspaces.push(defaultsWorkspace);

  const roster: Record<string, unknown>[] = [];
  if (Object.hasOwn(agents, "entries") && agents.entries !== undefined) {
    if (isRecord(agents.entries)) {
      for (const [id, entry] of Object.entries(agents.entries)) {
        if (isRecord(entry)) roster.push({ ...entry, id });
      }
    }
  } else if (Array.isArray(agents.list)) {
    // OpenClaw accepts any non-null object here; one without an id is "main".
    for (const entry of agents.list) {
      if (typeof entry === "object" && entry !== null) roster.push(entry as Record<string, unknown>);
    }
  } else if (!Object.hasOwn(agents, "list") || agents.list === undefined) {
    roster.push({ id: "main" });
  }

  const agentDirs: string[] = [];
  for (const entry of roster) {
    const id = normalizeAgentId(entry.id);
    const configured = typeof entry.workspace === "string" ? entry.workspace.trim() : "";
    if (configured) {
      const resolved = userPath(configured);
      if (resolved) workspaces.push(resolved);
    } else if (defaultsWorkspace) {
      workspaces.push(path.join(defaultsWorkspace, id));
    } else {
      workspaces.push(path.join(locations.stateDir, `workspace-${id}`));
    }
    const agentDir = typeof entry.agentDir === "string" ? entry.agentDir.trim() : "";
    const resolvedAgentDir = agentDir ? userPath(agentDir) : path.join(locations.stateDir, "agents", id, "agent");
    if (resolvedAgentDir) agentDirs.push(resolvedAgentDir);
  }
  // Agents no longer in the roster can still hold workshop skills.
  const agentsRoot = path.join(locations.stateDir, "agents");
  try {
    for (const entry of [...fs.readdir(agentsRoot)].sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isDirectory()) agentDirs.push(path.join(agentsRoot, entry.name, "agent"));
    }
  } catch (error) {
    if (!isMissing(error)) markUnknown(agentsRoot, "unreadable");
  }

  const allowedTargets = stringList(load.allowSymlinkTargets)
    .map(userPath)
    .filter((dir): dir is string => dir !== undefined);

  // Skill roots (src/skills/loading/workspace-skill-sources.ts). Managed and
  // personal roots follow symlinks anywhere; the others enforce containment.
  const roots: SkillRoot[] = [];
  for (const dir of stringList(load.extraDirs)) {
    const resolved = userPath(dir);
    if (resolved) roots.push({ dir: resolved, symlinks: "contained-or-allowed" });
  }
  for (const agentDir of agentDirs) {
    roots.push({ dir: path.join(agentDir, "workshop-skills"), symlinks: "contained", container: true });
  }
  roots.push({ dir: path.join(locations.stateDir, "skills"), symlinks: "any" });
  // OpenClaw's personal root uses the OS home; both homes are scanned.
  roots.push({ dir: path.join(locations.osHomeDir ?? locations.homeDir, ".agents", "skills"), symlinks: "any" });
  roots.push({ dir: path.join(locations.homeDir, ".agents", "skills"), symlinks: "any" });
  for (const workspace of workspaces) {
    roots.push({ dir: path.join(workspace, ".agents", "skills"), symlinks: "contained-or-allowed" });
    roots.push({ dir: path.join(workspace, "skills"), symlinks: "contained-or-allowed" });
  }

  const tryRealpath = (file: string): string | undefined => {
    try {
      return fs.realpath(file);
    } catch {
      return undefined;
    }
  };
  const allowedRealTargets = allowedTargets
    .map(tryRealpath)
    .filter((dir): dir is string => dir !== undefined);

  const hasSkillFile = (dir: string): boolean => {
    try {
      fs.lstat(path.join(dir, "SKILL.md"));
      return true;
    } catch (error) {
      // Like OpenClaw, an inaccessible SKILL.md still marks a skill candidate.
      return !isMissing(error);
    }
  };

  const skillsByRealPath = new Map<string, string>();
  // Roots are walked once per real directory and policy, so many links to
  // one tree (for example, agents' workshop roots) cost one walk.
  const seenRoots = new Set<string>();
  let totalDiscoveryDirs = 0;
  for (const root of roots) {
    if (timeUp()) break;
    const rootDir = path.resolve(root.dir);
    let rootReal: string;
    try {
      rootReal = fs.realpath(rootDir);
    } catch (error) {
      if (!isMissing(error)) markUnknown(rootDir, "unreadable");
      continue;
    }
    const rootKey = `${rootReal}\u0000${root.symlinks}\u0000${root.container === true}`;
    if (seenRoots.has(rootKey)) continue;
    seenRoots.add(rootKey);
    const visited = new Set<string>([rootReal]);
    const queue: { dir: string; real: string; depth: number }[] = [{ dir: rootDir, real: rootReal, depth: 0 }];
    let visitedDirs = 0;
    let truncated = false;
    // fs calls use real paths: a root reached through a long symlink chain
    // would otherwise make every call re-walk the chain. Reports keep the
    // discovered paths.
    for (const { dir, real, depth } of queue) {
      if (truncated || timeUp()) break;
      visitedDirs += 1;
      totalDiscoveryDirs += 1;
      if (visitedDirs > maxDiscoveryDirsPerRoot || totalDiscoveryDirs > maxDiscoveryDirs) {
        markUnknown(rootDir, "discovery-truncated");
        break;
      }
      if (!(root.container && depth === 0) && hasSkillFile(real)) {
        if (!skillsByRealPath.has(real)) skillsByRealPath.set(real, dir);
        continue;
      }
      if (depth >= maxDiscoveryDepth) continue;
      let entries: SkillDirent[];
      try {
        entries = fs.readdir(real);
      } catch (error) {
        if (!isMissing(error)) markUnknown(dir, "unreadable");
        continue;
      }
      for (const entry of [...entries].sort((a, b) => a.name.localeCompare(b.name))) {
        if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
        const child = path.join(dir, entry.name);
        let childReal: string | undefined;
        if (entry.isDirectory()) {
          // A real subdirectory of a real directory: no realpath walk needed.
          childReal = path.join(real, entry.name);
        } else if (entry.isSymbolicLink()) {
          symlinkResolutions += 1;
          if (symlinkResolutions > maxSymlinkResolutions) {
            markUnknown(rootDir, "discovery-truncated");
            truncated = true;
            break;
          }
          const started = now();
          childReal = tryRealpath(path.join(real, entry.name));
          symlinkMillis += now() - started;
          if (symlinkMillis > maxSymlinkMillis) {
            markUnknown(rootDir, "discovery-truncated");
            truncated = true;
            break;
          }
          if (childReal === undefined) continue;
          const components = childReal.split(path.sep).length;
          symlinkCost += components * components;
          if (symlinkCost > maxSymlinkCost) {
            markUnknown(rootDir, "discovery-truncated");
            truncated = true;
            break;
          }
          try {
            if (!fs.stat(childReal).isDirectory()) continue;
          } catch {
            continue;
          }
          const permitted =
            root.symlinks === "any" ||
            isInside(rootReal, childReal) ||
            (root.symlinks === "contained-or-allowed" &&
              allowedRealTargets.some((target) => isInside(target, childReal as string)));
          if (!permitted) continue;
        } else {
          continue;
        }
        if (childReal === undefined || visited.has(childReal)) continue;
        visited.add(childReal);
        queue.push({ dir: child, real: childReal, depth: depth + 1 });
      }
    }
  }

  const report = (skillDir: string, file: string, hits: ReturnType<typeof scanSource>) => {
    for (const hit of hits) {
      findings.push({
        ruleId: hit.ruleId,
        severity: hit.severity,
        skillDir: sanitize(skillDir),
        file: sanitize(file),
        line: hit.line,
      });
    }
  };
  // A file reached through several skills (nested skills, links to the same
  // tree) is read and scanned once, keyed by its real path.
  const scanCache = new Map<string, ReturnType<typeof scanSource> | undefined>();
  // The skill's real path is known from discovery and the walk follows no
  // links, so <skill real path>/<relative path> names the file without a
  // realpath call per file.
  const scanOnce = (
    file: string,
    realFile: string,
    maxBytes: number,
    scan: (text: string) => ReturnType<typeof scanSource>,
  ) => {
    const key = `${maxBytes}\u0000${realFile}`;
    if (!scanCache.has(key)) {
      const text = readFor(file, realFile, maxBytes);
      scanCache.set(key, text === undefined ? undefined : scan(text));
    }
    return scanCache.get(key);
  };
  const readFor = (file: string, realFile: string, maxBytes: number): string | undefined => {
    let result: SkillTextRead;
    try {
      result = fs.readText(realFile, maxBytes);
    } catch (error) {
      if (!isMissing(error)) markUnknown(file, "unreadable");
      return undefined;
    }
    if (result.status === "too-large") markUnknown(file, "too-large");
    if (result.status === "not-file") markUnknown(file, "unreadable");
    return result.status === "ok" ? result.text : undefined;
  };

  let totalScanEntries = 0;
  for (const [skillReal, skillDir] of skillsByRealPath) {
    if (timeUp()) break;
    // SKILL.md: OpenClaw applies both its skill-text and source rules.
    const skillFile = path.join(skillDir, "SKILL.md");
    const skillHits = scanOnce(skillFile, path.join(skillReal, "SKILL.md"), maxSkillFileBytes, (text) => [
      ...scanSkillContent(text),
      ...scanSource(text),
    ]);
    if (skillHits) report(skillDir, skillFile, skillHits);

    // Script files, walked like OpenClaw's scanner: no symlinks, no dot
    // entries, no node_modules.
    const files: { file: string; real: string }[] = [];
    let entriesSeen = 0;
    let truncated = false;
    const queue = [{ dir: skillDir, real: skillReal }];
    for (const { dir, real } of queue) {
      if (truncated || timeUp()) break;
      let entries: SkillDirent[];
      try {
        entries = fs.readdir(real);
      } catch (error) {
        if (!isMissing(error)) markUnknown(dir, "unreadable");
        continue;
      }
      for (const entry of [...entries].sort((a, b) => a.name.localeCompare(b.name))) {
        entriesSeen += 1;
        totalScanEntries += 1;
        if (entriesSeen > maxScanEntries || totalScanEntries > maxTotalScanEntries) {
          truncated = true;
          break;
        }
        if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) {
          queue.push({ dir: path.join(dir, entry.name), real: path.join(real, entry.name) });
        } else if (entry.isFile() && isScannable(entry.name)) {
          files.push({ file: path.join(dir, entry.name), real: path.join(real, entry.name) });
          if (files.length > maxScriptFiles) {
            truncated = true;
            break;
          }
        }
      }
    }
    if (truncated) markUnknown(skillDir, "scan-truncated");
    for (const { file, real } of files.slice(0, maxScriptFiles)) {
      if (timeUp()) break;
      const hits = scanOnce(file, real, maxScriptFileBytes, scanSource);
      if (hits) report(skillDir, file, hits);
    }
  }

  findings.sort(
    (a, b) =>
      a.skillDir.localeCompare(b.skillDir) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line ||
      a.ruleId.localeCompare(b.ruleId),
  );
  const seenUnknown = new Set<string>();
  const dedupedUnknown = unknown.filter((entry) => {
    const key = `${entry.reason}\u0000${entry.path}`;
    if (seenUnknown.has(key)) return false;
    seenUnknown.add(key);
    return true;
  });

  const skills = skillsByRealPath.size;
  const critical = findings.some((finding) => finding.severity === "critical");
  const grade: RiskySkillsResult["grade"] = critical
    ? "critical"
    : findings.length > 0
      ? "warning"
      : dedupedUnknown.length > 0
        ? "unknown"
        : "pass";
  const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;
  const unknownNote =
    dedupedUnknown.length > 0 ? `${plural(dedupedUnknown.length, "location")} could not be checked` : "";
  let summary: string;
  if (findings.length > 0) {
    const flagged = new Set(findings.map((finding) => finding.skillDir)).size;
    summary = `${plural(findings.length, "risky pattern")} found in ${plural(flagged, "skill")}${unknownNote ? `; ${unknownNote}` : ""}.`;
  } else if (dedupedUnknown.length > 0) {
    summary = `${unknownNote}; risky skills could not be ruled out.`;
  } else {
    summary = `No risky patterns found in ${plural(skills, "skill")}.`;
  }

  return { grade, findings, unknown: dedupedUnknown, skills, summary };
}
