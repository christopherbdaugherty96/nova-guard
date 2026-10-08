import { spawn } from "node:child_process";
import { accessSync, constants, readFileSync, statSync } from "node:fs";
import path from "node:path";

/**
 * Reads OpenClaw's installed version and returns its version output, or
 * undefined when it cannot be trusted: not found,
 * non-zero exit, oversized output, or no exit before the hard timeout (the
 * process is killed and partial output is discarded). No shell is ever used.
 *
 * Only absolute PATH entries are searched (an empty or relative entry would
 * mean the current directory), and the absolute path found is what runs. On
 * POSIX the probe gets its own process group, so a timeout kills everything it
 * started. On Windows, where Node cannot keep a reliable lifetime handle for
 * every descendant after the direct child exits, nova-guard does not execute
 * OpenClaw. It resolves npm's `openclaw.cmd` shim and reads the adjacent
 * package.json version instead. `openclaw --version` is OpenClaw's own code; nova-guard writes
 * nothing, but cannot vouch for what OpenClaw does when asked its version.
 */

const defaultTimeoutMs = 10_000;
const maxOutputBytes = 4096;

export interface VersionProbeOptions {
  env: NodeJS.ProcessEnv;
  timeoutMs?: number;
  platform?: NodeJS.Platform;
}

/** The script an npm `.cmd` shim runs, if it is a plain npm shim under its own directory. */
export function npmShimScript(shimText: string, shimDir: string): string | undefined {
  const match = /"%dp0%\\([^"%]+\.(?:m?js|cjs))"/i.exec(shimText);
  if (!match?.[1]) return undefined;
  const script = path.resolve(shimDir, ...match[1].split("\\"));
  // A global shim's script lives under its own directory; a project-local
  // shim in node_modules/.bin points at its sibling package in node_modules.
  const root = path.basename(shimDir).toLowerCase() === ".bin" ? path.dirname(shimDir) : shimDir;
  const relative = path.relative(root, script);
  if (relative === "" || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    return undefined;
  }
  return script;
}

function isFile(file: string): boolean {
  try {
    return statSync(file).isFile();
  } catch {
    return false;
  }
}

function pathDirs(env: NodeJS.ProcessEnv): string[] {
  const raw = env.PATH ?? env.Path ?? "";
  return raw.split(path.delimiter).filter((dir) => dir.trim() !== "" && path.isAbsolute(dir));
}

/**
 * The probe's environment, with PATH reduced to its absolute entries: npm's
 * `openclaw` bin starts with `#!/usr/bin/env node`, and `env` would otherwise
 * search the current directory for `node` too.
 */
function probeEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = { ...env };
  for (const key of Object.keys(out)) {
    if (key.toUpperCase() === "PATH") out[key] = (out[key] ?? "").split(path.delimiter).filter((dir) => dir.trim() !== "" && path.isAbsolute(dir)).join(path.delimiter);
  }
  return out;
}

function posixCommand(env: NodeJS.ProcessEnv): { command: string; args: string[] } | undefined {
  for (const dir of pathDirs(env)) {
    const candidate = path.join(dir, "openclaw");
    if (!isFile(candidate)) continue;
    try {
      accessSync(candidate, constants.X_OK);
    } catch {
      continue;
    }
    return { command: candidate, args: ["--version"] };
  }
  return undefined;
}

// Windows' default PATHEXT, used when the environment does not set one.
const defaultPathExt = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC";

function envValue(env: NodeJS.ProcessEnv, name: string): string | undefined {
  // Windows environment names are case-insensitive.
  const key = Object.keys(env).find((candidate) => candidate.toUpperCase() === name);
  return key === undefined ? undefined : env[key];
}

function windowsPackageVersion(env: NodeJS.ProcessEnv): string | undefined {
  const extensions = (envValue(env, "PATHEXT") ?? defaultPathExt)
    .split(";")
    .map((ext) => ext.trim().toLowerCase())
    .filter((ext) => ext.startsWith("."));
  for (const dir of pathDirs(env)) {
    // `openclaw` runs the first PATH folder holding openclaw<ext> for an
    // extension in PATHEXT. Only an npm .cmd shim there can be read without
    // running OpenClaw; anything else that would run first (an .exe, .com,
    // .bat, ...) means the installed version cannot be established: unknown.
    const launchers = extensions.filter((ext) => isFile(path.join(dir, `openclaw${ext}`)));
    if (launchers.length === 0) continue;
    if (launchers.length !== 1 || launchers[0] !== ".cmd") return undefined;
    const shim = path.join(dir, "openclaw.cmd");
    let text: string;
    try {
      text = readFileSync(shim, "utf8");
    } catch {
      return undefined;
    }
    const script = npmShimScript(text, dir);
    if (!script || !isFile(script)) return undefined;
    try {
      const packageRoot = path.dirname(script);
      const pkg = JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8")) as {
        name?: unknown;
        version?: unknown;
      };
      if (pkg.name !== "openclaw") return undefined;
      try {
        const build = JSON.parse(readFileSync(path.join(packageRoot, "dist", "build-info.json"), "utf8")) as {
          version?: unknown;
        };
        if (typeof build.version === "string" && build.version.trim() !== "") return build.version.trim();
      } catch {
        // OpenClaw's launcher falls back to package.json when build metadata is absent or unreadable.
      }
      return typeof pkg.version === "string" && pkg.version.trim() !== "" ? pkg.version.trim() : undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export function probeOpenClawVersion(options: VersionProbeOptions): Promise<string | undefined> {
  const platform = options.platform ?? process.platform;
  const posix = platform !== "win32";
  if (!posix) return Promise.resolve(windowsPackageVersion(options.env));
  const target = posixCommand(options.env);
  if (!target) return Promise.resolve(undefined);

  return new Promise((resolve) => {
    let settled = false;
    let bytes = 0;
    const chunks: Buffer[] = [];
    const child = spawn(target.command, target.args, {
      env: probeEnv(options.env),
      shell: false,
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
      // Its own process group, so a timeout can kill its descendants too.
      detached: posix,
    });
    const running = () => child.exitCode === null && child.signalCode === null;
    const finish = (value: string | undefined) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (child.pid !== undefined) {
        // The probe's own process group: whatever it started ends with it,
        // whether it succeeded or not. The group id cannot be reused while
        // any member is alive.
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {
          // The group is already gone.
        }
      }
      if (running()) child.kill("SIGKILL");
      child.stdout?.destroy();
      // A descendant holding the pipe open must not keep nova-guard running.
      child.unref();
      resolve(value);
    };
    const timer = setTimeout(() => finish(undefined), options.timeoutMs ?? defaultTimeoutMs);
    child.on("error", () => finish(undefined));
    child.stdout?.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > maxOutputBytes) finish(undefined);
      else chunks.push(chunk);
    });
    child.on("exit", (code) => {
      if (code !== 0) finish(undefined);
    });
    child.stdout?.on("end", () => {
      // Output is complete once stdout ends and the process exited cleanly.
      const check = () => {
        if (child.exitCode === 0) finish(Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, ""));
        else if (child.exitCode !== null || child.signalCode !== null) finish(undefined);
        else child.once("exit", check);
      };
      check();
    });
  });
}
