import path from "node:path";

import type { GatewayExposureResult } from "../checks/gateway-exposure.js";
import type { PlaintextSecretsResult, SecretFinding } from "../checks/plaintext-secrets.js";
import type { RiskySkillFinding, RiskySkillsResult, SkillUnknownReason } from "../checks/risky-skills.js";
import type { VersionAdvisoryResult } from "../checks/version-advisories.js";

/**
 * The one-page report card: a pure presentation layer over the check
 * results. It adds no scanning, reads nothing, and depends on nothing but
 * its input, so the same results always render the same page.
 *
 * Redaction: values never reach the checks' results, and this layer prints
 * even less of them. The home directory becomes "~", agent ids in state
 * paths become "*", configured gateway bind/auth values are never printed
 * (only the checks' fixed summaries), and risky skills are shown by root,
 * file kind, rule, and line, never by skill directory or file name.
 */

export const reportCardWidth = 80;
/** A printed US Letter or A4 page at six lines per inch. */
export const reportCardPageLines = 66;
export const waitlistUrl =
  "https://github.com/christopherbdaugherty96/nova-guard/issues/new?template=proxy-waitlist.yml";

type Grade = "pass" | "warning" | "critical" | "unknown";

export interface ReportCardInput {
  homeDir: string;
  stateDir: string;
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
  /** A second line: `before`, a path shortened to fit, then `after`. */
  location?: { before: string; path: string; after: string };
  fix: string;
}

function sanitize(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, "");
}

/** Word-wraps text to the page width, indenting continuation lines. */
function wrap(text: string, indent: string, firstIndent = indent): string[] {
  const lines: string[] = [];
  let line = firstIndent;
  let lineHasWord = false;
  for (const word of text.split(/\s+/).filter(Boolean)) {
    const candidate = lineHasWord ? `${line} ${word}` : `${line}${word}`;
    if ([...candidate].length <= reportCardWidth || !lineHasWord) {
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

/** Shortens a line to the page width, keeping its end (where file names are). */
function fit(line: string): string {
  const chars = [...line];
  if (chars.length <= reportCardWidth) return line;
  const indent = line.match(/^\s*/)?.[0] ?? "";
  const keep = reportCardWidth - indent.length - 1;
  return `${indent}…${chars.slice(chars.length - keep).join("")}`;
}

export function renderReportCard(input: ReportCardInput): string {
  const home = path.resolve(input.homeDir);
  const agentsDir = path.join(path.resolve(input.stateDir), "agents");

  const displayPath = (raw: string): string => {
    let file = path.resolve(raw);
    // Agent ids are user-chosen names: <stateDir>/agents/<id>/... -> agents/*/...
    const relativeToAgents = path.relative(agentsDir, file);
    if (relativeToAgents && !relativeToAgents.startsWith("..") && !path.isAbsolute(relativeToAgents)) {
      const [, ...rest] = relativeToAgents.split(path.sep);
      file = path.join(agentsDir, "*", ...rest);
    }
    const relativeToHome = path.relative(home, file);
    if (relativeToHome === "") file = "~";
    else if (!relativeToHome.startsWith("..") && !path.isAbsolute(relativeToHome)) {
      file = ["~", relativeToHome].join(path.sep);
    }
    return sanitize(file);
  };

  const findings: Finding[] = [];
  const unchecked: string[] = [];

  // Gateway: only the check's fixed summary is printed, never bind/auth values.
  const gateway = input.gateway;
  if (!gateway) unchecked.push("Gateway exposure: not checked.");
  else if (gateway.grade === "unknown") unchecked.push(`Gateway exposure: ${sanitize(gateway.summary)}`);
  else if (gateway.grade !== "pass") {
    findings.push({ severity: gateway.grade, label: sanitize(gateway.summary), fix: gatewayFix(gateway) });
  }

  const version = input.version;
  if (!version) unchecked.push("Version: not checked.");
  else if (version.grade === "unknown") unchecked.push(`Version: ${sanitize(version.summary)}`);
  else if (version.grade !== "pass") {
    const ids = version.advisories.map(sanitize);
    const listed = ids.slice(0, 3).join(", ");
    const more = ids.length > 3 ? ` and ${ids.length - 3} more` : "";
    findings.push({
      severity: version.grade,
      label: `Version: ${sanitize(version.summary)}`,
      fix: `Upgrade OpenClaw to the latest release (affected by ${listed}${more}).`,
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
          after: `${finding.line === undefined ? "" : `:${finding.line}`}, key ${sanitize(finding.key)}`,
        },
        fix: secretFix(finding),
      });
    }
    for (const file of secrets.unreadable) unchecked.push(`Plaintext secrets: could not read ${displayPath(file)}`);
    if (secrets.grade === "unknown" && secrets.unreadable.length === 0) {
      unchecked.push(`Plaintext secrets: ${sanitize(secrets.summary)}`);
    }
  }

  const skills = input.skills;
  if (!skills) unchecked.push("Risky skills: not checked.");
  else {
    findings.push(...skillFindings(skills.findings, displayPath));
    if (skills.unknown.length > 0) {
      const counts = new Map<SkillUnknownReason, number>();
      for (const entry of skills.unknown) counts.set(entry.reason, (counts.get(entry.reason) ?? 0) + 1);
      const parts = [...counts]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .map(([reason, count]) => `${count} ${reason.replaceAll("-", " ")}`);
      const total = skills.unknown.length;
      unchecked.push(`Risky skills: ${total} location${total === 1 ? "" : "s"} (${parts.join(", ")})`);
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
      "Safer, not safe: a clean report does not guarantee that the agent, host, plugins, skills, model, or network are secure.",
      "",
    ),
    "",
    "Checks",
    ...checkGrades.map(([name, grade]) =>
      `  ${name.padEnd(18)} ${grade ? grade.toUpperCase() : "UNKNOWN  not checked"}`.trimEnd(),
    ),
    "  Spend              not checked (no documented local source yet)",
    "",
  ];

  const uncheckedLines = ["Could not be checked"];
  const maxUnchecked = 8;
  if (unchecked.length === 0) uncheckedLines.push("  Nothing.");
  for (const entry of unchecked.slice(0, maxUnchecked)) uncheckedLines.push(...wrap(entry, "    ", "  - "));
  if (unchecked.length > maxUnchecked) uncheckedLines.push(`  - ${unchecked.length - maxUnchecked} more not shown.`);

  const tail = ["", "Get notified when the nova-guard proxy ships:", waitlistUrl];

  // Findings get whatever room the page has left.
  const budget = reportCardPageLines - head.length - uncheckedLines.length - tail.length - 3;
  const findingLines: string[] = ["Findings (most severe first)"];
  if (ordered.length === 0) findingLines.push("  None.");
  let shown = 0;
  for (const [index, finding] of ordered.entries()) {
    const prefix = `  ${index + 1}. ${finding.severity.toUpperCase().padEnd(8)}  `;
    const location = finding.location;
    const block = [
      ...wrap(finding.label, "               ", prefix),
      ...(location ? [withPath(`               ${location.before}`, location.path, location.after)] : []),
      ...wrap(finding.fix, "          ", "     Fix: "),
    ];
    const remaining = ordered.length - index - 1;
    const reserve = remaining > 0 ? 1 : 0;
    if (findingLines.length - 1 + block.length + reserve > budget) break;
    findingLines.push(...block);
    shown += 1;
  }
  if (shown < ordered.length) {
    const rest = ordered.length - shown;
    findingLines.push(`  ${rest} more finding${rest === 1 ? "" : "s"} not shown; fix the ones above first.`);
  }

  return [...head, ...findingLines, "", ...uncheckedLines, ...tail].join("\n");
}

/** One line: the path is shortened from the left so the text after it stays whole. */
function withPath(before: string, file: string, after: string): string {
  const line = `${before}${file}${after}`;
  if ([...line].length <= reportCardWidth) return line;
  const room = reportCardWidth - [...before].length - [...after].length - 1;
  const chars = [...file];
  return room > 0 ? `${before}…${chars.slice(chars.length - room).join("")}${after}` : fit(line);
}

function gatewayFix(result: GatewayExposureResult): string {
  if (result.summary.startsWith("Public Tailscale Funnel")) {
    return "Use password auth with Tailscale Funnel, or switch to Tailscale Serve.";
  }
  if (result.grade === "critical") {
    return "Turn on gateway auth (token or password), or bind the gateway to loopback.";
  }
  return "Keep gateway auth on, and bind to loopback unless you need remote access.";
}

function secretFix(finding: SecretFinding): string {
  if (finding.kind === "fallback") {
    return "Remove the inline default from the ${VAR:-...} reference, then rotate the secret.";
  }
  if (/\.env$/.test(finding.file)) {
    return "Limit this file to your user (chmod 600), or move the secret into a secret store; rotate it if it was shared.";
  }
  return "Replace the value with a ${VAR} reference or SecretRef, then rotate the secret.";
}

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

function skillFindings(results: RiskySkillFinding[], displayPath: (raw: string) => string): Finding[] {
  // One entry per skill, file, and rule; repeated lines are counted.
  const groups = new Map<string, { finding: RiskySkillFinding; lines: number[] }>();
  for (const finding of results) {
    const rule = finding.ruleId.replace(/-truncated$/, "");
    const key = `${finding.skillDir}\u0000${finding.file}\u0000${rule}`;
    const group = groups.get(key);
    if (group) group.lines.push(finding.line);
    else groups.set(key, { finding: { ...finding, ruleId: rule }, lines: [finding.line] });
  }
  return [...groups.values()].map(({ finding, lines }) => {
    // Skill directory and file names are user-chosen: show the root and the
    // file's kind only.
    const base = path.basename(finding.file);
    const kind = base === "SKILL.md" ? "SKILL.md" : `${sanitize(path.extname(base)) || "script"} file`;
    const first = Math.min(...lines);
    const more = lines.length > 1 ? ` (+${lines.length - 1} more)` : "";
    return {
      severity: finding.severity === "critical" ? "critical" : "warning",
      label: `Risky skill (${sanitize(finding.ruleId)})`,
      location: {
        before: "skill ",
        path: [displayPath(finding.root), "*"].join(path.sep),
        after: `: ${kind} line ${first}${more}`,
      },
      fix: skillRuleFixes[finding.ruleId] ?? "Review this skill before use.",
    } satisfies Finding;
  });
}
