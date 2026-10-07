import { spawn } from "node:child_process";
import { accessSync, constants, readFileSync, statSync } from "node:fs";
import path from "node:path";

/**
 * Runs `openclaw --version`, the documented local version probe, and returns
 * its standard output, or undefined when it cannot be trusted: not found,
 * non-zero exit, oversized output, or no exit before the hard timeout (the
 * process is killed and partial output is discarded). No shell is ever used.
 *
 * Only absolute PATH entries are searched (an empty or relative entry would
 * mean the current directory), and the absolute path found is what runs. On
 * POSIX the probe gets its own process group, so a timeout kills everything it
 * started; on Windows the system taskkill.exe (by absolute path, /T) does the
 * same for the process tree. On Windows, npm installs `openclaw.cmd`, which only a shell can
 * run, so its script is read from npm's shim and run directly with this Node
 * binary. `openclaw --version` is OpenClaw's own code; nova-guard writes
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

function windowsCommand(env: NodeJS.ProcessEnv): { command: string; args: string[] } | undefined {
  for (const dir of pathDirs(env)) {
    const exe = path.join(dir, "openclaw.exe");
    if (isFile(exe)) return { command: exe, args: ["--version"] };
    const shim = path.join(dir, "openclaw.cmd");
    if (isFile(shim)) {
      let text: string;
      try {
        text = readFileSync(shim, "utf8");
      } catch {
        return undefined;
      }
      const script = npmShimScript(text, dir);
      return script && isFile(script) ? { command: process.execPath, args: [script, "--version"] } : undefined;
    }
  }
  return undefined;
}

/** The system taskkill.exe that ends a process tree, or undefined without an absolute SystemRoot. */
export function windowsTreeKillCommand(
  pid: number,
  env: NodeJS.ProcessEnv,
): { command: string; args: string[] } | undefined {
  const systemRoot = (env.SystemRoot ?? env.SYSTEMROOT ?? "").trim();
  if (!systemRoot || !path.win32.isAbsolute(systemRoot)) return undefined;
  return {
    command: path.win32.join(systemRoot, "System32", "taskkill.exe"),
    args: ["/PID", String(pid), "/T", "/F"],
  };
}

/** Whether a trusted absolute system taskkill path is available before a Windows probe starts. */
export function windowsTreeKillAvailable(
  env: NodeJS.ProcessEnv,
  fallbackEnv: NodeJS.ProcessEnv = process.env,
  fileExists: (file: string) => boolean = isFile,
): boolean {
  return trustedWindowsTreeKillCommand(1, env, fallbackEnv, fileExists) !== undefined;
}

function trustedWindowsTreeKillCommand(
  pid: number,
  env: NodeJS.ProcessEnv,
  fallbackEnv: NodeJS.ProcessEnv = process.env,
  fileExists: (file: string) => boolean = isFile,
): { command: string; args: string[] } | undefined {
  for (const candidate of [windowsTreeKillCommand(pid, env), windowsTreeKillCommand(pid, fallbackEnv)]) {
    if (candidate && fileExists(candidate.command)) return candidate;
  }
  return undefined;
}

/** Ends the probe's whole process tree on Windows; resolves when done or after 3 seconds. */
function killWindowsTree(pid: number, env: NodeJS.ProcessEnv): Promise<void> {
  const tree = trustedWindowsTreeKillCommand(pid, env);
  if (!tree) return Promise.resolve();
  return new Promise((done) => {
    const killer = spawn(tree.command, tree.args, { shell: false, stdio: "ignore", windowsHide: true });
    const timer = setTimeout(done, 3000);
    const end = () => {
      clearTimeout(timer);
      done();
    };
    killer.on("exit", end);
    killer.on("error", end);
  });
}

export function probeOpenClawVersion(options: VersionProbeOptions): Promise<string | undefined> {
  const platform = options.platform ?? process.platform;
  const posix = platform !== "win32";
  // A Windows timeout is safe only when the whole process tree can be ended.
  // Refuse to start rather than risk leaving descendants behind.
  if (!posix && !windowsTreeKillAvailable(options.env)) return Promise.resolve(undefined);
  const target = posix ? posixCommand(options.env) : windowsCommand(options.env);
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
      let treeKilled: Promise<void> = Promise.resolve();
      if (child.pid !== undefined) {
        if (posix) {
          // The probe's own process group: whatever it started ends with it,
          // whether it succeeded or not. The group id cannot be reused while
          // any member is alive.
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {
            // The group is already gone.
          }
        } else if (value === undefined && running()) {
          // taskkill /T must find the parent alive to walk its tree, so it runs
          // first; while the child runs, its PID cannot have been reused.
          // After a clean exit nothing is killed: the PID may be reused.
          treeKilled = killWindowsTree(child.pid, options.env);
        }
      }
      void treeKilled.then(() => {
        if (running()) child.kill("SIGKILL");
        child.stdout?.destroy();
        // A descendant holding the pipe open must not keep nova-guard running.
        child.unref();
        resolve(value);
      });
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
