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
  /** A redaction base; when homeDirKnown is false this is only the filesystem root. */
  homeDir: string;
  /** Present only when the home is unknown but absolute overrides are usable. */
  homeDirKnown?: false;
  /** Undefined when only an absolute OPENCLAW_HOME is usable: the OS home is unknown. */
  osHomeDir: string | undefined;
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
  // A relative home would resolve against the gateway's working directory, so
  // it is not trusted. OpenClaw's own home (OPENCLAW_HOME) takes precedence and
  // needs the OS home only to expand a leading ~ (resolveEffectiveHomeDir).
  const osHomeDir = rawOsHome && path.isAbsolute(rawOsHome) ? path.resolve(rawOsHome) : undefined;

  const rawHome = homeValue(env.OPENCLAW_HOME);
  let explicitHome: string | undefined;
  if (rawHome !== undefined) {
    if (/^~(?=$|[\\/])/.test(rawHome)) {
      if (osHomeDir) explicitHome = rawHome.replace(/^~(?=$|[\\/])/, () => osHomeDir);
    } else {
      explicitHome = rawHome;
    }
    if (explicitHome && !path.isAbsolute(explicitHome)) explicitHome = undefined;
  }
  const stateOverride = env.OPENCLAW_STATE_DIR?.trim();
  const absoluteState = stateOverride && path.isAbsolute(stateOverride) ? path.resolve(stateOverride) : undefined;
  const resolvedHome = rawHome !== undefined ? (explicitHome ? path.resolve(explicitHome) : undefined) : osHomeDir;
  if (rawHome !== undefined && !resolvedHome && !absoluteState) return undefined;
  const homeDirKnown = resolvedHome !== undefined;
  const homeDir = resolvedHome ?? (absoluteState ? path.parse(absoluteState).root : undefined);
  if (!homeDir) return undefined;

  // OpenClaw's resolveUserPath: trim, expand a leading ~ to OpenClaw's home, resolve.
  // OpenClaw's resolveUserPath: trim and expand a leading ~ to OpenClaw's home.
  // A path still relative after that resolves against the gateway's working
  // directory, which nova-guard cannot know, so it is not trusted (undefined).
  const userPath = (raw: string): string | undefined => {
    const trimmed = raw.trim();
    if (/^~(?=$|[\\/])/.test(trimmed) && !homeDirKnown) return undefined;
    const expanded = trimmed.replace(/^~(?=$|[\\/])/, () => homeDir);
    return path.isAbsolute(expanded) ? path.resolve(expanded) : undefined;
  };

  const stateDir = stateOverride ? userPath(stateOverride) : homeDirKnown ? path.join(homeDir, ".openclaw") : undefined;
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

  const defaultStateDir = homeDirKnown && stateDir === path.join(homeDir, ".openclaw");
  return {
    homeDir,
    ...(homeDirKnown ? {} : { homeDirKnown: false as const }),
    osHomeDir,
    stateDir,
    configPath,
    workspaceDir,
    defaultStateDir,
    includeRoots,
  };
}
