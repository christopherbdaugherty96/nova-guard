import os from "node:os";
import path from "node:path";

/**
 * Where OpenClaw keeps its files, resolved the way OpenClaw does
 * (src/config/paths.ts, src/config/state-dir.ts, src/infra/home-dir.ts,
 * src/agents/workspace-default-path.ts at b8324c64): OPENCLAW_HOME, then the
 * OS home; OPENCLAW_STATE_DIR, else ~/.openclaw; OPENCLAW_CONFIG_PATH, else
 * <state>/openclaw.json; OPENCLAW_WORKSPACE_DIR, else <state>/workspace when
 * OPENCLAW_STATE_DIR is set, else the profile's workspace; and
 * OPENCLAW_INCLUDE_ROOTS. Only environment variables are read.
 */
export interface OpenClawLocations {
  homeDir: string;
  osHomeDir: string;
  stateDir: string;
  configPath: string;
  /** Undefined when OPENCLAW_PROFILE is invalid: OpenClaw then refuses to resolve it. */
  workspaceDir: string | undefined;
  /** Whether the state directory is OpenClaw's default (~/.openclaw). */
  defaultStateDir: boolean;
  includeRoots: string[];
}

// OpenClaw's normalizeHomeDirValue: blank, "undefined", and "null" are unset.
function homeValue(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed && trimmed !== "undefined" && trimmed !== "null" ? trimmed : undefined;
}

function safeHomedir(homedir: () => string): string | undefined {
  try {
    return homeValue(homedir());
  } catch {
    return undefined;
  }
}

const profileName = /^[a-z0-9][a-z0-9_-]{0,63}$/i;

export function resolveOpenClawLocations(
  env: NodeJS.ProcessEnv,
  homedir: () => string = os.homedir,
): OpenClawLocations | undefined {
  const rawOsHome = homeValue(env.HOME) ?? homeValue(env.USERPROFILE) ?? safeHomedir(homedir);
  // A relative home would resolve against the gateway's working directory.
  if (!rawOsHome || !path.isAbsolute(rawOsHome)) return undefined;
  const osHomeDir = path.resolve(rawOsHome);

  const explicitHome = homeValue(env.OPENCLAW_HOME)?.replace(/^~(?=$|[\\/])/, () => osHomeDir);
  if (explicitHome !== undefined && !path.isAbsolute(explicitHome)) return undefined;
  const homeDir = explicitHome ? path.resolve(explicitHome) : osHomeDir;

  // OpenClaw's resolveUserPath: trim, expand a leading ~ to OpenClaw's home, resolve.
  // OpenClaw's resolveUserPath: trim and expand a leading ~ to OpenClaw's home.
  // A path still relative after that resolves against the gateway's working
  // directory, which nova-guard cannot know, so it is not trusted (undefined).
  const userPath = (raw: string): string | undefined => {
    const expanded = raw.trim().replace(/^~(?=$|[\\/])/, () => homeDir);
    return path.isAbsolute(expanded) ? path.resolve(expanded) : undefined;
  };

  const stateOverride = env.OPENCLAW_STATE_DIR?.trim();
  const stateDir = stateOverride ? userPath(stateOverride) : path.join(homeDir, ".openclaw");
  if (!stateDir) return undefined;
  const configOverride = env.OPENCLAW_CONFIG_PATH?.trim();
  const configPath = configOverride ? userPath(configOverride) : path.join(stateDir, "openclaw.json");
  if (!configPath) return undefined;

  let workspaceDir: string | undefined;
  const workspaceOverride = env.OPENCLAW_WORKSPACE_DIR?.trim();
  const profile = env.OPENCLAW_PROFILE?.trim();
  if (workspaceOverride) {
    // OpenClaw resolves this one without ~ expansion, against its own working directory.
    workspaceDir = path.isAbsolute(workspaceOverride) ? path.resolve(workspaceOverride) : undefined;
  } else if (stateOverride) {
    workspaceDir = path.join(stateDir, "workspace");
  } else if (profile && profile.toLowerCase() !== "default") {
    workspaceDir = profileName.test(profile) ? path.join(homeDir, `.openclaw-${profile}`, "workspace") : undefined;
  } else {
    workspaceDir = path.join(homeDir, ".openclaw", "workspace");
  }

  const includeRoots: string[] = [];
  for (const entry of (env.OPENCLAW_INCLUDE_ROOTS ?? "").split(path.delimiter)) {
    if (!entry.trim()) continue;
    // A relative root is dropped: includes it would allow then stay refused (unknown).
    const resolved = userPath(entry);
    if (resolved && !includeRoots.includes(resolved)) includeRoots.push(resolved);
  }

  const defaultStateDir = stateDir === path.join(homeDir, ".openclaw");
  return { homeDir, osHomeDir, stateDir, configPath, workspaceDir, defaultStateDir, includeRoots };
}
