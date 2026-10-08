import { spawn } from "node:child_process";
import { accessSync, closeSync, constants, fstatSync, openSync, readSync, statSync } from "node:fs";
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
 * OpenClaw. When npm's `openclaw.cmd` shim is the openclaw Windows would run
 * (first in PATH/PATHEXT order, no other openclaw launcher in the way), it reads
 * the adjacent dist/build-info.json version, else package.json; otherwise the
 * version is unknown. On POSIX, `openclaw --version` is OpenClaw's own code;
 * nova-guard writes nothing, but cannot vouch for what OpenClaw does when
 * asked its version.
 */

const defaultTimeoutMs = 10_000;
const maxOutputBytes = 4096;

export interface VersionProbeOptions {
  env: NodeJS.ProcessEnv;
  timeoutMs?: number;
  platform?: NodeJS.Platform;
}

// The exact openclaw.cmd npm's cmd-shim writes for a `#!/usr/bin/env node`
// bin (OpenClaw's openclaw.mjs), with the script path as the only variable.
const npmCmdShimPattern = new RegExp(
  "^" +
    [
      "@ECHO off",
      "GOTO start",
      ":find_dp0",
      "SET dp0=%~dp0",
      "EXIT /b",
      ":start",
      "SETLOCAL",
      "CALL :find_dp0",
      "",
      'IF EXIST "%dp0%\\node.exe" (',
      '  SET "_prog=%dp0%\\node.exe"',
      ") ELSE (",
      '  SET "_prog=node"',
      "  SET PATHEXT=%PATHEXT:;.JS;=;%",
      ")",
      "",
      'endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\\',
    ]
      .join("\r\n")
      .replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
    '([^"%\\r\\n]+\\.(?:m?js|cjs))" %\\*\\r\\n$',
);

/**
 * The exact openclaw.ps1 npm's cmd-shim writes beside the .cmd for the same
 * bin; `target` is the script path relative to the shim folder, as in the
 * .cmd. PowerShell runs this .ps1 rather than the .cmd.
 */
function npmPs1Shim(target: string): string {
  const t = `"$basedir/${target.split("\\").join("/")}"`;
  return [
    "#!/usr/bin/env pwsh",
    "$basedir=Split-Path $MyInvocation.MyCommand.Definition -Parent",
    "",
    '$exe=""',
    'if ($PSVersionTable.PSVersion -lt "6.0" -or $IsWindows) {',
    "  # Fix case when both the Windows and Linux builds of Node",
    "  # are installed in the same directory",
    '  $exe=".exe"',
    "}",
    "$ret=0",
    'if (Test-Path "$basedir/node$exe") {',
    "  # Support pipeline input",
    "  if ($MyInvocation.ExpectingInput) {",
    `    $input | & "$basedir/node$exe"  ${t} $args`,
    "  } else {",
    `    & "$basedir/node$exe"  ${t} $args`,
    "  }",
    "  $ret=$LASTEXITCODE",
    "} else {",
    "  # Support pipeline input",
    "  if ($MyInvocation.ExpectingInput) {",
    `    $input | & "node$exe"  ${t} $args`,
    "  } else {",
    `    & "node$exe"  ${t} $args`,
    "  }",
    "  $ret=$LASTEXITCODE",
    "}",
    "exit $ret",
    "",
  ].join("\n");
}

/**
 * The script an npm `.cmd` shim runs, if the shim is exactly what npm's
 * cmd-shim writes and its script lies under its own directory (or, for a
 * project's node_modules/.bin shim, in node_modules). Anything else could run
 * something other than the script whose metadata would be read.
 */
export function npmShimScript(shimText: string, shimDir: string): string | undefined {
  return npmShimTarget(shimText, shimDir)?.script;
}

function npmShimTarget(shimText: string, shimDir: string): { target: string; script: string } | undefined {
  const match = npmCmdShimPattern.exec(shimText);
  if (!match?.[1]) return undefined;
  const script = path.resolve(shimDir, ...match[1].split("\\"));
  // A global shim's script lives under its own directory; a project-local
  // shim in node_modules/.bin points at its sibling package in node_modules.
  const root = path.basename(shimDir).toLowerCase() === ".bin" ? path.dirname(shimDir) : shimDir;
  const relative = path.relative(root, script);
  if (relative === "" || relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    return undefined;
  }
  return { target: match[1], script };
}

// Shims and metadata are small; anything larger is not read (unknown), so a
// corrupt or hostile file cannot exhaust memory.
const maxMetadataBytes = 1024 * 1024;

class MetadataTooLarge extends Error {}

// Opens the file once without blocking (a FIFO would otherwise wait for a
// writer), checks that descriptor is a regular file, and reads at most the
// limit plus one byte, so a file swapped or grown after any check is still
// bounded.
function readSmallText(file: string): string {
  const nonBlocking = (constants as { O_NONBLOCK?: number }).O_NONBLOCK ?? 0;
  const fd = openSync(file, constants.O_RDONLY | nonBlocking);
  try {
    if (!fstatSync(fd).isFile()) throw new Error("metadata is not a regular file");
    const buffer = Buffer.alloc(maxMetadataBytes + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = readSync(fd, buffer, length, buffer.length - length, null);
      if (read === 0) break;
      length += read;
    }
    if (length > maxMetadataBytes) throw new MetadataTooLarge();
    return buffer.toString("utf8", 0, length);
  } finally {
    closeSync(fd);
  }
}

function isFile(file: string): boolean {
  try {
    return statSync(file).isFile();
  } catch {
    return false;
  }
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
  // POSIX environment names are case-sensitive: only PATH is the search path.
  for (const dir of (env.PATH ?? "").split(path.delimiter)) {
    // An empty or relative entry means a working directory; the gateway's is
    // unknown, so an openclaw found after one may not be the one that runs.
    if (dir.trim() === "" || !path.isAbsolute(dir)) return undefined;
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
  const extensions = [
    ...new Set(
      (envValue(env, "PATHEXT") ?? defaultPathExt)
        .split(";")
        .map((ext) => ext.trim().toLowerCase())
        .filter((ext) => ext.startsWith(".")),
    ),
  ];
  // cmd.exe and PowerShell strip quotes from PATH entries and skip empty ones.
  const entries = (envValue(env, "PATH") ?? "")
    .split(path.delimiter)
    .map((entry) => entry.trim().replace(/^"(.*)"$/, "$1").trim())
    .filter((entry) => entry !== "");
  // Callers that start a process directly (CreateProcess, Node's spawn) never
  // run a .cmd; they would find an openclaw.exe/.com anywhere on PATH instead.
  if (entries.some((entry) => path.win32.isAbsolute(entry) && [".exe", ".com"].some((ext) => isFile(path.join(entry, `openclaw${ext}`))))) {
    return undefined;
  }
  for (const dir of entries) {
    // A relative entry resolves against a working directory nova-guard cannot know.
    if (!path.win32.isAbsolute(dir)) return undefined;
    // `openclaw` runs the first PATH folder holding openclaw<ext> for an
    // extension in PATHEXT, or openclaw.ps1 for PowerShell. Only an npm .cmd
    // shim (with npm's own .ps1 beside it) can be read without running
    // OpenClaw; anything else that could run first means the installed
    // version cannot be established: unknown.
    const launchers = [...extensions, ".ps1"].filter((ext) => isFile(path.join(dir, `openclaw${ext}`)));
    if (launchers.length === 0) continue;
    if (!launchers.includes(".cmd") || launchers.some((ext) => ext !== ".cmd" && ext !== ".ps1")) return undefined;
    const shim = path.join(dir, "openclaw.cmd");
    let text: string;
    try {
      text = readSmallText(shim);
    } catch {
      return undefined;
    }
    const shimTarget = npmShimTarget(text, dir);
    if (!shimTarget || !isFile(shimTarget.script)) return undefined;
    const { script } = shimTarget;
    if (launchers.includes(".ps1")) {
      // PowerShell runs openclaw.ps1 instead: it must be npm's own for the same script.
      let ps1: string;
      try {
        ps1 = readSmallText(path.join(dir, "openclaw.ps1"));
      } catch {
        return undefined;
      }
      if (ps1 !== npmPs1Shim(shimTarget.target)) return undefined;
    }
    try {
      const packageRoot = path.dirname(script);
      const pkg = JSON.parse(readSmallText(path.join(packageRoot, "package.json"))) as {
        name?: unknown;
        version?: unknown;
      };
      if (pkg.name !== "openclaw") return undefined;
      // OpenClaw's launcher would read an oversized build-info.json; it cannot be
      // read here, so the version is unknown rather than the package.json fallback.
      const buildInfo = path.join(packageRoot, "dist", "build-info.json");
      try {
        const build = JSON.parse(readSmallText(buildInfo)) as {
          version?: unknown;
        };
        if (typeof build.version === "string" && build.version.trim() !== "") return build.version.trim();
      } catch (error) {
        if (error instanceof MetadataTooLarge) return undefined;
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
