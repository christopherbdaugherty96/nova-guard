#!/usr/bin/env node
import { runCheck } from "./cli/run-check.js";
import { probeOpenClawVersion } from "./cli/version-probe.js";

const usage = `Usage: nova-guard check

Scans this machine's OpenClaw setup read-only and prints a one-page report
card. No network calls, no writes, no changes to OpenClaw.

Options:
  -h, --help   Show this help.
`;

function write(stream: NodeJS.WriteStream, text: string): Promise<void> {
  return new Promise((resolve) => stream.write(text, () => resolve()));
}

export async function main(argv: readonly string[]): Promise<number> {
  if (argv.length === 1 && (argv[0] === "-h" || argv[0] === "--help")) {
    await write(process.stdout, usage);
    return 0;
  }
  if (argv.length !== 1 || argv[0] !== "check") {
    await write(process.stderr, usage);
    return 2;
  }
  const card = await runCheck({
    env: process.env,
    probeVersion: () => probeOpenClawVersion({ env: process.env }),
  });
  await write(process.stdout, `${card}\n`);
  return 0;
}

const code = await main(process.argv.slice(2));
// Exit explicitly: a stray descendant of `openclaw --version` must not hold the process open.
process.exit(code);
