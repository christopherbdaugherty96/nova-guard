import { spawn } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import path from "node:path";

/**
 * Runs `openclaw --version`, the documented local version probe, and returns
 * its standard output, or undefined when it cannot be trusted: not found,
 * non-zero exit, oversized output, or no exit before the hard timeout (the
 * process is killed and partial output is discarded). No shell is ever used.
 *
 * On Windows, npm installs `openclaw.cmd`, which only a shell can run, so its
 * script is read from npm's shim and run directly with this Node binary.
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
  const relative = path.relative(shimDir, script);
  if (relative.startsWith("..") || path.isAbsolute(relative)) return undefined;
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

export function probeOpenClawVersion(options: VersionProbeOptions): Promise<string | undefined> {
  const platform = options.platform ?? process.platform;
  const target =
    platform === "win32" ? windowsCommand(options.env) : { command: "openclaw", args: ["--version"] };
  if (!target) return Promise.resolve(undefined);

  return new Promise((resolve) => {
    let settled = false;
    let bytes = 0;
    const chunks: Buffer[] = [];
    const child = spawn(target.command, target.args, {
      env: options.env,
      shell: false,
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
    });
    const finish = (value: string | undefined) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
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
