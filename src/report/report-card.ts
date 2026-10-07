import path from "node:path";

import type { GatewayExposureResult } from "../checks/gateway-exposure.js";
import type { PlaintextSecretsResult, SecretFinding } from "../checks/plaintext-secrets.js";
import type {
  RiskySkillFinding,
  RiskySkillsResult,
  SkillRootKind,
  SkillUnknownReason,
} from "../checks/risky-skills.js";
import type { VersionAdvisoryResult } from "../checks/version-advisories.js";

/**
 * The one-page report card: a pure presentation layer over the check
 * results. It adds no scanning, reads nothing, and depends on nothing but
 * its input, so the same results always render the same page.
 *
 * Redaction: values never reach the checks' results, and this layer prints
 * even less of them, because report cards are meant to be shared. Home
 * directories print as "~", a state directory outside home as "<state>",
 * agent ids in state paths as "*"; configured gateway bind/auth values are
 * never printed (only the checks' fixed summaries); risky skills print by
 * the kind of root they were found in, a per-card number, file kind, rule,
 * and line, never by any configured path, skill name, or file name.
 */

export const reportCardWidth = 80;
/** A printed US Letter or A4 page at six lines per inch. */
export const reportCardPageLines = 66;
export const waitlistUrl =
  "https://github.com/christopherbdaugherty96/nova-guard/issues/new?template=proxy-waitlist.yml";

type Grade = "pass" | "warning" | "critical" | "unknown";

export interface ReportCardInput {
  /** OpenClaw's effective home; printed as "~". */
  homeDir: string;
  /** The OS home, when it differs; also printed as "~". */
  osHomeDir?: string;
  /** Printed as "<state>" when outside home. */
  stateDir: string;
  /** The config file; its directory prints as "<config>" when outside home and state. */
  configPath?: string;
  toolVersion: string;
  advisoryDataDate: string;
  /** A check that did not run is undefined and reported as not checked. */
  gateway?: GatewayExposureResult;
  version?: VersionAdvisoryResult;
  secrets?: PlaintextSecretsResult;
  skills?: RiskySkillsResult;
}

const gradeRank: Record<Grade, number> = { pass: 0, unknown: 1, warning: 2, critical: 3 };

interface Finding {
  severity: "critical" | "warning";
  label: string;
  /** A second line: `before`, a path shortened to fit, `suffix`, then `detail`. */
  location?: { before: string; path: string; suffix: string; detail: string };
  /** A second line of fixed text, wrapped rather than shortened. */
  note?: string;
  fix: string;
}

const fixIndent = " ".repeat(10);

function sanitize(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, "");
}

/**
 * Terminal columns, measured pessimistically: any non-ASCII character counts
 * as two, the most any single character takes. Overcounting only shortens a
 * line; undercounting a wide character would overflow the page.
 */
function charColumns(char: string): number {
  return (char.codePointAt(0) ?? 0) < 0x80 ? 1 : 2;
}

function columns(text: string): number {
  let width = 0;
  for (const char of text) width += charColumns(char);
  return width;
}

/** The longest tail of `text` that fits in `width` columns. */
function tail(text: string, width: number): string {
  const chars = [...text];
  let used = 0;
  let start = chars.length;
  while (start > 0) {
    const next = charColumns(chars[start - 1] as string);
    if (used + next > width) break;
    used += next;
    start -= 1;
  }
  return chars.slice(start).join("");
}

/** Shortens a line to the page width, keeping its end (where file names are). */
function fit(line: string): string {
  if (columns(line) <= reportCardWidth) return line;
  const indent = line.match(/^\s*/)?.[0] ?? "";
  return `${indent}…${tail(line.slice(indent.length), reportCardWidth - indent.length - columns("…"))}`;
}

/** Word-wraps text to the page width, indenting continuation lines. */
function wrap(text: string, indent: string, firstIndent = indent): string[] {
  const lines: string[] = [];
  let line = firstIndent;
  let lineHasWord = false;
  for (const word of text.split(/\s+/).filter(Boolean)) {
    const candidate = lineHasWord ? `${line} ${word}` : `${line}${word}`;
    if (columns(candidate) <= reportCardWidth || !lineHasWord) {
      line = candidate;
      lineHasWord = true;
    } else {
      lines.push(line);
      line = `${indent}${word}`;
    }
  }
  lines.push(line);
  // A single word longer than the page is shortened from the left.
  return lines.map((entry) => fit(entry));
}

/**
 * The location line. The path is shortened from the left so its suffix stays
 * whole; if the detail does not leave the path room, it moves to its own line.
 */
function locationLines(location: NonNullable<Finding["location"]>, findingIndent: string): string[] {
  const minimumPath = 24;
  const head = `${findingIndent}${location.before}`;
  const withPath = (after: string): string => {
    const room = reportCardWidth - columns(head) - columns(after);
    if (columns(location.path) <= room) return `${head}${location.path}${after}`;
    return fit(`${head}…${tail(location.path, Math.max(room - columns("…"), 0))}${after}`);
  };
  const oneLine = `${location.suffix}${location.detail}`;
  if (
    columns(`${head}${location.path}${oneLine}`) <= reportCardWidth ||
    reportCardWidth - columns(head) - columns(oneLine) >= minimumPath
  ) {
    return [withPath(oneLine)];
  }
  // The detail ("key ...") keeps its label; a long value is shortened from the left.
  const detail = location.detail.replace(/^,\s*/, "");
  const [label, ...valueWords] = detail.split(" ");
  const value = valueWords.join(" ");
  const room = reportCardWidth - columns(`${findingIndent}${label} `) - columns("…");
  const detailLine =
    columns(`${findingIndent}${detail}`) <= reportCardWidth
      ? `${findingIndent}${detail}`
      : `${findingIndent}${label} …${tail(value, room)}`;
  return [withPath(location.suffix), detailLine];
}

function isInside(base: string, candidate: string): boolean {
  const relative = path.relative(base, candidate);
  return relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

export function renderReportCard(input: ReportCardInput): string {
  // A filesystem root (HOME=/ in containers) would turn every path into ~/...
  const usable = (dir: string | undefined): dir is string =>
    typeof dir === "string" && path.parse(path.resolve(dir)).root !== path.resolve(dir);
  const homes = [input.homeDir, input.osHomeDir].filter(usable).map((dir) => path.resolve(dir));
  const stateDir = path.resolve(input.stateDir);
  const agentsDir = path.join(stateDir, "agents");
  const configDir = input.configPath ? path.dirname(path.resolve(input.configPath)) : undefined;
  const bases: [string, string][] = [
    ...homes.map((home): [string, string] => [home, "~"]),
    ...(usable(stateDir) ? [[stateDir, "<state>"] as [string, string]] : []),
    ...(usable(configDir) ? [[configDir, "<config>"] as [string, string]] : []),
  ];

  const displayPath = (raw: string): string => {
    let file = path.resolve(raw);
    // Agent ids are user-chosen names: <stateDir>/agents/<id>/... -> agents/*/...
    if (file !== agentsDir && isInside(agentsDir, file)) {
      const [, ...rest] = path.relative(agentsDir, file).split(path.sep);
      file = path.join(agentsDir, "*", ...rest);
    }
    const shorten = (base: string, label: string): string | undefined => {
      if (!isInside(base, file)) return undefined;
      const relative = path.relative(base, file);
      return relative === "" ? label : [label, relative].join(path.sep);
    };
    const shortened = bases.map(([base, label]) => shorten(base, label)).find((value) => value !== undefined) ?? file;
    return sanitize(shortened);
  };

  const findings: Finding[] = [];
  const unchecked: string[] = [];

  // Gateway: only the check's fixed summary is printed, never bind/auth values.
  const gateway = input.gateway;
  if (!gateway) unchecked.push("Gateway exposure: not checked.");
  else if (gateway.grade === "unknown") unchecked.push(`Gateway exposure: ${sanitize(gateway.summary)}`);
  else if (gateway.grade !== "pass") {
    findings.push({ severity: gateway.grade, label: sanitize(gateway.summary), fix: gatewayFix(gateway.summary) });
  }

  const version = input.version;
  if (!version) unchecked.push("Version: not checked.");
  else if (version.grade === "unknown") unchecked.push(`Version: ${sanitize(version.summary)}`);
  else if (version.grade !== "pass") {
    const ids = version.advisories.map(sanitize);
    const more = ids.length > 3 ? ` and ${ids.length - 3} more` : "";
    findings.push({
      severity: version.grade,
      label: `Version: ${sanitize(version.summary)}`,
      fix:
        ids.length === 0
          ? "Upgrade OpenClaw to the latest release."
          : `Upgrade OpenClaw to the latest release (affected by ${ids.slice(0, 3).join(", ")}${more}).`,
    });
  }

  const secrets = input.secrets;
  if (!secrets) unchecked.push("Plaintext secrets: not checked.");
  else {
    for (const finding of secrets.findings) {
      findings.push({
        severity: "warning",
        label: finding.kind === "fallback" ? "Plaintext secret (as a ${VAR:-...} default)" : "Plaintext secret",
        location: {
          before: "in ",
          path: displayPath(finding.file),
          suffix: finding.line === undefined ? "" : `:${finding.line}`,
          detail: `, key ${sanitize(finding.key)}`,
        },
        fix: secretFix(finding),
      });
    }
    // One entry per check, so no check's unknowns can crowd out another's.
    const unreadable = secrets.unreadable;
    if (unreadable.length === 1) {
      unchecked.push(`Plaintext secrets: could not read ${displayPath(unreadable[0] as string)}`);
    } else if (unreadable.length > 1) {
      unchecked.push(
        `Plaintext secrets: could not read ${unreadable.length} files, including ${displayPath(unreadable[0] as string)}`,
      );
    } else if (secrets.grade === "unknown") {
      unchecked.push(`Plaintext secrets: ${sanitize(secrets.summary)}`);
    }
  }

  const skills = input.skills;
  if (!skills) unchecked.push("Risky skills: not checked.");
  else {
    findings.push(...skillFindings(skills.findings));
    if (skills.unknown.length > 0) {
      const counts = new Map<SkillUnknownReason, number>();
      for (const entry of skills.unknown) counts.set(entry.reason, (counts.get(entry.reason) ?? 0) + 1);
      const parts = [...counts]
        .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
        .map(([reason, count]) => `${count} ${reason.replaceAll("-", " ")}`);
      const total = skills.unknown.length;
      unchecked.push(`Risky skills: ${total} location${total === 1 ? "" : "s"} (${parts.join(", ")})`);
    } else if (skills.grade === "unknown") {
      unchecked.push(`Risky skills: ${sanitize(skills.summary)}`);
    }
  }

  // Severity first, then the fixed check order the findings were collected in.
  const ordered = findings
    .map((finding, index) => ({ finding, index }))
    .sort((a, b) => gradeRank[b.finding.severity] - gradeRank[a.finding.severity] || a.index - b.index)
    .map(({ finding }) => finding);

  const checkGrades: [string, Grade | undefined][] = [
    ["Gateway exposure", gateway?.grade],
    ["Version", version?.grade],
    ["Plaintext secrets", secrets?.grade],
    ["Risky skills", skills?.grade],
  ];
  const overall = checkGrades
    .map(([, grade]) => grade ?? "unknown")
    .reduce<Grade>((worst, grade) => (gradeRank[grade] > gradeRank[worst] ? grade : worst), "pass");

  const head: string[] = [
    "nova-guard report card: OpenClaw",
    `Overall: ${overall.toUpperCase()}`,
    fit(`nova-guard ${sanitize(input.toolVersion)} · advisory data as of ${sanitize(input.advisoryDataDate)}`),
    ...wrap(
      "Safer, not safe: PASS means the inspected security controls passed, not that the whole OpenClaw config is valid or that the agent, host, plugins, skills, model, or network are secure.",
      "",
    ),
    "",
    "Checks",
    ...checkGrades.map(([name, grade]) => `  ${name.padEnd(18)} ${grade ? grade.toUpperCase() : "UNKNOWN  not checked"}`),
    "  Spend              not checked (no documented local source yet)",
    "",
  ];

  const uncheckedLines = ["Could not be checked"];
  if (unchecked.length === 0) uncheckedLines.push("  Nothing.");
  for (const entry of unchecked) uncheckedLines.push(...wrap(entry, "    ", "  - "));

  const tailLines = ["", "Get notified when the nova-guard proxy ships:", waitlistUrl];

  // Findings get whatever room the page has left.
  const budget = reportCardPageLines - head.length - uncheckedLines.length - tailLines.length - 3;
  const findingLines: string[] = ["Findings (most severe first)"];
  if (ordered.length === 0) findingLines.push("  None.");
  let shown = 0;
  // Numbers are right-aligned so every label starts in the same column.
  const numberWidth = String(ordered.length).length;
  for (const [index, finding] of ordered.entries()) {
    const prefix = `  ${String(index + 1).padStart(numberWidth)}. ${finding.severity.toUpperCase().padEnd(8)}  `;
    const findingIndent = " ".repeat(prefix.length);
    const block = [
      ...wrap(finding.label, findingIndent, prefix),
      ...(finding.location ? locationLines(finding.location, findingIndent) : []),
      ...(finding.note ? wrap(finding.note, findingIndent) : []),
      ...wrap(finding.fix, fixIndent, "     Fix: "),
    ];
    const reserve = index < ordered.length - 1 ? 1 : 0;
    if (findingLines.length - 1 + block.length + reserve > budget) break;
    findingLines.push(...block);
    shown += 1;
  }
  if (shown < ordered.length) {
    const rest = ordered.length - shown;
    findingLines.push(`  ${rest} more finding${rest === 1 ? "" : "s"} not shown; fix the ones above first.`);
  }

  return [...head, ...findingLines, "", ...uncheckedLines, ...tailLines].join("\n");
}

// Every summary the gateway check can produce at warning or critical, so the
// fix always matches the exposure (src/checks/gateway-exposure.ts).
const gatewayFixes: [string, string][] = [
  [
    "Gateway is configured for non-loopback access without authentication.",
    "Turn on gateway auth (token or password), or bind the gateway to loopback.",
  ],
  [
    "Gateway is authenticated but exposed beyond loopback.",
    "Keep gateway auth on, and bind the gateway to loopback unless you need remote access.",
  ],
  [
    "Public Tailscale Funnel exposure has a non-password auth mode.",
    "Use password auth with Tailscale Funnel, or switch to Tailscale Serve.",
  ],
  [
    "Public internet exposure via Tailscale Funnel; password is not verifiable.",
    "Funnel puts the gateway on the public internet: switch to Tailscale Serve unless you need that, and make sure password auth is set.",
  ],
  [
    "Public internet exposure via Tailscale Funnel.",
    "Funnel puts the gateway on the public internet: switch to Tailscale Serve unless you need that, and keep password auth on.",
  ],
  [
    "Gateway is reachable from the tailnet via Tailscale Serve.",
    "Anyone on your tailnet can reach the gateway: keep auth on and limit who can join the tailnet.",
  ],
];

function gatewayFix(summary: string): string {
  // Combined results read "<primary> Also: <secondary>"; fix both.
  const fixes = summary
    .split(" Also: ")
    .map((part) => gatewayFixes.find(([known]) => part.trim() === known)?.[1])
    .filter((fix): fix is string => fix !== undefined);
  const unique = [...new Set(fixes)];
  return unique.length > 0
    ? unique.join(" Also: ")
    : "Review the gateway's bind and auth settings so it is reachable only where you intend.";
}

function secretFix(finding: SecretFinding): string {
  if (finding.kind === "fallback") {
    return "Remove the inline default from the ${VAR:-...} reference, then rotate the secret.";
  }
  // Only .env findings carry a line number.
  if (finding.line !== undefined) {
    return "Limit this file to your user (chmod 600), or move the secret into a secret store; rotate it if it was shared.";
  }
  return "Replace the value with a ${VAR} reference or SecretRef, then rotate the secret.";
}

const rootLabels: Record<SkillRootKind, string> = {
  managed: "the managed skills folder",
  personal: ["~", ".agents", "skills"].join(path.sep),
  workspace: "a workspace skills folder",
  "workspace-agents": "a workspace .agents/skills folder",
  extra: "a skills.load.extraDirs folder",
  workshop: "an agent workshop-skills folder",
};

const skillRuleFixes: Record<string, string> = {
  "dangerous-exec": "Runs shell commands. Review the code, or remove the skill if you do not trust its author.",
  "dynamic-code-execution": "Executes generated code (eval or new Function). Review it before use.",
  "crypto-mining": "References crypto-mining. Remove the skill unless you expect this.",
  "suspicious-network": "Connects to an unusual network port. Check where it sends data.",
  "potential-exfiltration": "Reads files and sends network requests. Check what it uploads.",
  "obfuscated-code": "Contains obfuscated code. Treat the skill as untrusted until reviewed.",
  "env-harvesting": "Reads environment variables near a network send and could leak API keys. Review or remove it.",
  "literal-secret": "Contains a credential in its text. Rotate that credential and remove it from the skill.",
  "shell-pipe-to-shell": "Pipes a download straight into a shell. Do not run it before reviewing the script.",
  "secret-exfiltration": "May send environment variables over the network. Review or remove the skill.",
  "destructive-delete": "Contains a broad rm -rf command. Make sure it cannot delete your files.",
  "unsafe-permissions": "Sets world-writable permissions (chmod 777). Use narrower permissions.",
};

function skillFindings(results: RiskySkillFinding[]): Finding[] {
  // Skills are numbered in the order the check lists them, since their names
  // and paths are not printed.
  const skillNumbers = new Map<string, number>();
  // One entry per skill, file, and rule; repeated and omitted matches are counted.
  const groups = new Map<string, { finding: RiskySkillFinding; first: number; count: number }>();
  for (const finding of results) {
    if (!skillNumbers.has(finding.skillDir)) skillNumbers.set(finding.skillDir, skillNumbers.size + 1);
    const truncated = finding.ruleId.endsWith("-truncated");
    const rule = truncated ? finding.ruleId.slice(0, -"-truncated".length) : finding.ruleId;
    const key = `${finding.skillDir}\u0000${finding.file}\u0000${rule}`;
    const matches = truncated ? (finding.omitted ?? 1) : 1;
    const group = groups.get(key);
    if (group) {
      group.count += matches;
      if (!truncated) group.first = Math.min(group.first, finding.line);
    } else {
      groups.set(key, { finding: { ...finding, ruleId: rule }, first: finding.line, count: matches });
    }
  }
  return [...groups.values()].map(({ finding, first, count }) => {
    const base = path.basename(finding.file);
    const kind = base === "SKILL.md" ? "SKILL.md" : `${sanitize(path.extname(base)) || "script"} file`;
    const more = count > 1 ? ` (+${count - 1} more)` : "";
    const number = skillNumbers.get(finding.skillDir) as number;
    return {
      severity: finding.severity === "critical" ? "critical" : "warning",
      label: `Risky skill (${sanitize(finding.ruleId)})`,
      note: `skill ${number} in ${rootLabels[finding.rootKind] ?? "a skills folder"}: ${kind} line ${first}${more}`,
      fix: skillRuleFixes[finding.ruleId] ?? "Review this skill before use.",
    } satisfies Finding;
  });
}
