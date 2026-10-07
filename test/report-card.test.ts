import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import type { GatewayExposureResult } from "../src/checks/gateway-exposure.js";
import type { PlaintextSecretsResult } from "../src/checks/plaintext-secrets.js";
import type { RiskySkillsResult } from "../src/checks/risky-skills.js";
import type { VersionAdvisoryResult } from "../src/checks/version-advisories.js";
import {
  renderReportCard,
  reportCardPageLines,
  reportCardWidth,
  waitlistUrl,
  type ReportCardInput,
} from "../src/report/report-card.js";

const homeDir = path.resolve(path.sep, "home", "chris");
const stateDir = path.join(homeDir, ".openclaw");
const configPath = path.join(stateDir, "openclaw.json");
const managedSkills = path.join(stateDir, "skills");

const gatewayPass: GatewayExposureResult = {
  grade: "pass",
  bind: "loopback",
  auth: "token",
  summary: "Gateway uses the loopback-only default.",
};
const versionPass: VersionAdvisoryResult = {
  grade: "pass",
  version: "2026.9.8",
  advisories: [],
  summary: "OpenClaw 2026.9.8 matches no bundled advisory (data as of 2026-10-05).",
};
const secretsPass: PlaintextSecretsResult = {
  grade: "pass",
  findings: [],
  unreadable: [],
  scanned: [configPath],
  summary: "No plaintext secrets found in OpenClaw's config, .env, or models.json files.",
};
const skillsPass: RiskySkillsResult = {
  grade: "pass",
  findings: [],
  unknown: [],
  skills: 3,
  summary: "No risky patterns found in 3 skills.",
};

function input(overrides: Partial<ReportCardInput> = {}): ReportCardInput {
  return {
    homeDir,
    stateDir,
    toolVersion: "0.1.0",
    advisoryDataDate: "2026-10-05",
    gateway: gatewayPass,
    version: versionPass,
    secrets: secretsPass,
    skills: skillsPass,
    ...overrides,
  };
}

/** Terminal columns: East Asian wide characters and emoji take two. */
function columns(line: string): number {
  let width = 0;
  for (const char of line) {
    width += /[\u1100-\u115F\u2E80-\uA4CF\uAC00-\uD7A3\uF900-\uFAFF\uFE30-\uFE4F\uFF00-\uFF60\uFFE0-\uFFE6]|\p{Extended_Pictographic}/u.test(char)
      ? 2
      : /\p{Mn}|\p{Me}|\u200d/u.test(char)
        ? 0
        : 1;
  }
  return width;
}

function assertFitsOnePage(card: string) {
  const lines = card.split("\n");
  assert.ok(lines.length <= reportCardPageLines, `lines: ${lines.length}`);
  // The waitlist URL is printed whole so it stays usable; every other line fits.
  for (const line of lines) {
    if (line !== waitlistUrl) assert.ok(columns(line) <= reportCardWidth, `too wide: ${line}`);
  }
}

test("an all-pass scan grades PASS on one printable page with the waitlist link", () => {
  const card = renderReportCard(input());
  assert.match(card, /^Overall: PASS$/m);
  assert.ok(card.includes(waitlistUrl));
  assert.match(card, /Safer, not safe/);
  assertFitsOnePage(card);
});

test("the card says PASS covers only the inspected controls, not the whole OpenClaw config", () => {
  const card = renderReportCard(input()).replace(/\s+/g, " ");
  assert.match(card, /PASS means the inspected security controls passed/);
  assert.match(card, /not that the whole OpenClaw config is valid/);
});

test("spend is shown as not checked and does not affect the overall grade", () => {
  const card = renderReportCard(input());
  assert.match(card, /^ *Spend .*not checked/im);
  assert.match(card, /^Overall: PASS$/m);
});

test("the overall grade is the worst check: critical > warning > unknown > pass", () => {
  const cases: [Partial<ReportCardInput>, string][] = [
    [{ version: { ...versionPass, grade: "unknown", summary: "OpenClaw version could not be read." } }, "UNKNOWN"],
    [{ skills: { ...skillsPass, grade: "warning", findings: [] } }, "WARNING"],
    [
      {
        version: { ...versionPass, grade: "unknown", summary: "OpenClaw version could not be read." },
        gateway: { ...gatewayPass, grade: "critical", auth: "none", summary: "Gateway is configured for non-loopback access without authentication." },
      },
      "CRITICAL",
    ],
  ];
  for (const [overrides, expected] of cases) {
    assert.match(renderReportCard(input(overrides)), new RegExp(`^Overall: ${expected}$`, "m"));
  }
});

test("a check that did not run is UNKNOWN and says it was not checked", () => {
  const card = renderReportCard(input({ secrets: undefined }));
  assert.match(card, /^Overall: UNKNOWN$/m);
  assert.match(card, /^ *Plaintext secrets .*not checked/im);
});

test("findings are listed most severe first, each with a plain-language fix", () => {
  const card = renderReportCard(
    input({
      version: {
        grade: "warning",
        version: "2026.1.5",
        advisories: ["GHSA-aaaa-bbbb-cccc"],
        summary: "OpenClaw 2026.1.5 matches 1 bundled advisory (data as of 2026-10-05).",
      },
      gateway: {
        grade: "critical",
        bind: "lan",
        auth: "none",
        summary: "Gateway is configured for non-loopback access without authentication.",
      },
      secrets: {
        ...secretsPass,
        grade: "warning",
        findings: [{ kind: "plaintext", file: configPath, key: "gateway.auth.token" }],
        summary: "1 plaintext secret found in 1 file.",
      },
    }),
  );
  const order = ["CRITICAL  Gateway", "WARNING   Version", "WARNING   Plaintext secret"].map((label) =>
    card.indexOf(label),
  );
  assert.ok(order.every((index) => index >= 0), card);
  assert.deepEqual([...order].sort((a, b) => a - b), order);
  assert.ok(card.includes("GHSA-aaaa-bbbb-cccc"));
  const fixes = card.split("\n").filter((line) => /^ +Fix: /.test(line));
  assert.equal(fixes.length, 3);
});

test("secret findings show the redacted location and key path, home as ~, agent ids as *", () => {
  const agentModels = path.join(stateDir, "agents", "letmeinagent", "agent", "models.json");
  const card = renderReportCard(
    input({
      secrets: {
        grade: "warning",
        findings: [
          { kind: "plaintext", file: path.join(stateDir, ".env"), line: 3, key: "OPENAI_API_KEY" },
          { kind: "fallback", file: configPath, key: "env.vars.*" },
          { kind: "plaintext", file: agentModels, key: "providers.*.apiKey" },
        ],
        unreadable: [],
        scanned: [],
        summary: "3 plaintext secrets found in 3 files.",
      },
    }),
  );
  const home = (...parts: string[]) => ["~", ...parts].join(path.sep);
  assert.ok(card.includes(`${home(".openclaw", ".env")}:3, key OPENAI_API_KEY`), card);
  assert.ok(card.includes(`${home(".openclaw", "openclaw.json")}, key env.vars.*`), card);
  assert.ok(card.includes(`${home(".openclaw", "agents", "*", "agent", "models.json")}, key providers.*.apiKey`), card);
  assert.ok(!card.includes(homeDir));
  assert.ok(!card.includes("letmein"));
});

test("risky skills are reported by root, file kind, rule, and line, never by skill or file name", () => {
  const skillDir = path.join(managedSkills, "letmein-group", "letmein-skill");
  const card = renderReportCard(
    input({
      skills: {
        grade: "critical",
        findings: [
          { ruleId: "shell-pipe-to-shell", severity: "critical", root: managedSkills, rootKind: "managed", skillDir, file: path.join(skillDir, "SKILL.md"), line: 6 },
          { ruleId: "dangerous-exec", severity: "critical", root: managedSkills, rootKind: "managed", skillDir, file: path.join(skillDir, "lib", "letmein.js"), line: 4 },
          { ruleId: "dangerous-exec", severity: "critical", root: managedSkills, rootKind: "managed", skillDir, file: path.join(skillDir, "lib", "letmein.js"), line: 9 },
          { ruleId: "suspicious-network", severity: "warn", root: managedSkills, rootKind: "managed", skillDir, file: path.join(skillDir, "net.ts"), line: 1 },
        ],
        unknown: [],
        skills: 1,
        summary: "4 risky patterns found in 1 skill.",
      },
    }),
  );
  assert.match(card, /^Overall: CRITICAL$/m);
  assert.ok(!card.includes("letmein"), card);
  assert.ok(card.includes("skill 1 in the managed skills folder: SKILL.md line 6"), card);
  assert.ok(card.includes("skill 1 in the managed skills folder: .js file line 4 (+1 more)"), card);
  assert.ok(card.includes("skill 1 in the managed skills folder: .ts file line 1"), card);
  assert.match(card, /shell-pipe-to-shell/);
  assert.match(card, /Fix: .*pipe/i);
});

test("unknown and unavailable data are explicit; skill unknowns are counted, not named", () => {
  const card = renderReportCard(
    input({
      secrets: {
        ...secretsPass,
        grade: "unknown",
        unreadable: [path.join(stateDir, ".env")],
        summary: "1 file could not be read; plaintext secrets could not be ruled out.",
      },
      skills: {
        ...skillsPass,
        grade: "unknown",
        unknown: [
          { path: path.join(managedSkills, "letmein-skill", "SKILL.md"), reason: "too-large" },
          { path: path.join(managedSkills, "letmein-other"), reason: "unreadable" },
          { path: path.join(managedSkills, "letmein-third"), reason: "unreadable" },
        ],
        summary: "3 locations could not be checked; risky skills could not be ruled out.",
      },
      version: undefined,
    }),
  );
  assert.match(card, /^Could not be checked$/m);
  assert.ok(card.includes(`Plaintext secrets: could not read ${["~", ".openclaw", ".env"].join(path.sep)}`), card);
  assert.ok(card.includes("Risky skills: 3 locations (2 unreadable, 1 too large)"), card);
  assert.match(card, /Version: not checked/);
  assert.ok(!card.includes("letmein"));
});

test("the gateway line never echoes configured bind or auth values", () => {
  const card = renderReportCard(
    input({
      gateway: {
        grade: "unknown",
        bind: "tailscale (letmein-mode)",
        auth: "unrecognized",
        summary: "Tailscale mode is unrecognized by this scanner version.",
      },
    }),
  );
  assert.ok(!card.includes("letmein"));
  assert.match(card, /Tailscale mode is unrecognized/);
});

test("many findings still fit one page, with the remainder counted", () => {
  const findings = Array.from({ length: 40 }, (_, i) => ({
    kind: "plaintext" as const,
    file: path.join(stateDir, ".env"),
    line: i + 1,
    key: `KEY_${i}`,
  }));
  const card = renderReportCard(
    input({ secrets: { ...secretsPass, grade: "warning", findings, summary: "40 plaintext secrets found in 1 file." } }),
  );
  assertFitsOnePage(card);
  const shown = card.split("\n").filter((line) => /^ *\d+\. /.test(line)).length;
  assert.ok(shown >= 5);
  assert.ok(card.includes(`${40 - shown} more findings not shown`), card);
});

test("long paths are shortened to fit the page width", () => {
  const deep = path.join(stateDir, ...Array.from({ length: 30 }, () => "nested-directory"), "openclaw.json");
  const card = renderReportCard(
    input({
      secrets: {
        ...secretsPass,
        grade: "warning",
        findings: [{ kind: "plaintext", file: deep, key: "gateway.auth.token" }],
        summary: "1 plaintext secret found in 1 file.",
      },
    }),
  );
  assertFitsOnePage(card);
  assert.ok(card.includes("openclaw.json, key gateway.auth.token"), card);
});

test("rendering is deterministic and control characters are stripped", () => {
  const evil = path.join(stateDir, "a\u001b[31mb‮c.env");
  const value = input({
    secrets: {
      ...secretsPass,
      grade: "warning",
      findings: [{ kind: "plaintext", file: evil, key: "K" }],
      summary: "1 plaintext secret found in 1 file.",
    },
  });
  const first = renderReportCard(value);
  assert.equal(renderReportCard(structuredClone(value)), first);
  assert.ok(!/[\u0000-\u0008\u000b-\u001f\u007f‮]/.test(first));
});

const skillHit = (overrides: Partial<RiskySkillsResult["findings"][number]>): RiskySkillsResult["findings"][number] => ({
  ruleId: "shell-pipe-to-shell",
  severity: "critical",
  root: managedSkills,
  rootKind: "managed",
  skillDir: path.join(managedSkills, "a"),
  file: path.join(managedSkills, "a", "SKILL.md"),
  line: 1,
  ...overrides,
});
const skillsWith = (findings: RiskySkillsResult["findings"]): RiskySkillsResult => ({
  grade: "critical",
  findings,
  unknown: [],
  skills: findings.length,
  summary: "risky",
});

test("skill roots print by kind, never by their configured or agent-named path", () => {
  const workspace = path.join(stateDir, "workspace-letmein-client", "skills");
  const extra = path.resolve(path.sep, "srv", "letmein-private", "skills");
  const card = renderReportCard(
    input({
      skills: skillsWith([
        skillHit({ root: workspace, rootKind: "workspace", skillDir: path.join(workspace, "x"), file: path.join(workspace, "x", "SKILL.md") }),
        skillHit({ root: extra, rootKind: "extra", skillDir: path.join(extra, "y"), file: path.join(extra, "y", "SKILL.md") }),
        skillHit({ root: path.join(homeDir, ".agents", "skills"), rootKind: "personal", skillDir: path.join(homeDir, ".agents", "skills", "z"), file: path.join(homeDir, ".agents", "skills", "z", "SKILL.md") }),
      ]),
    }),
  );
  assert.ok(!card.includes("letmein"), card);
  assert.ok(card.includes("in a workspace skills folder: SKILL.md line 1"), card);
  assert.ok(card.includes("in a skills.load.extraDirs folder: SKILL.md line 1"), card);
  assert.ok(card.includes(`in ${["~", ".agents", "skills"].join(path.sep)}: SKILL.md line 1`), card);
});

test("different skills under one root are numbered apart, and omitted matches are counted", () => {
  const card = renderReportCard(
    input({
      skills: skillsWith([
        skillHit({ skillDir: path.join(managedSkills, "a"), file: path.join(managedSkills, "a", "SKILL.md") }),
        skillHit({ skillDir: path.join(managedSkills, "b"), file: path.join(managedSkills, "b", "SKILL.md") }),
        ...Array.from({ length: 32 }, (_, i) =>
          skillHit({ ruleId: "dangerous-exec", skillDir: path.join(managedSkills, "b"), file: path.join(managedSkills, "b", "x.js"), line: i + 1 }),
        ),
        skillHit({ ruleId: "dangerous-exec-truncated", skillDir: path.join(managedSkills, "b"), file: path.join(managedSkills, "b", "x.js"), line: 40, omitted: 8 }),
      ]),
    }),
  );
  assert.ok(card.includes("skill 1 in the managed skills folder: SKILL.md line 1"), card);
  assert.ok(card.includes("skill 2 in the managed skills folder: SKILL.md line 1"), card);
  assert.ok(card.includes("skill 2 in the managed skills folder: .js file line 1 (+39 more)"), card);
});

test("home, OS home, and state directories are shortened even for ..-prefixed names", () => {
  const osHomeDir = path.resolve(path.sep, "Users", "letmein-os");
  const outsideState = path.resolve(path.sep, "srv", "letmein-state");
  const card = renderReportCard(
    input({
      osHomeDir,
      stateDir: outsideState,
      secrets: {
        ...secretsPass,
        grade: "warning",
        findings: [
          { kind: "plaintext", file: path.join(homeDir, "..hidden", "openclaw.json"), key: "a" },
          { kind: "plaintext", file: path.join(outsideState, "agents", "..acme", "agent", "models.json"), key: "b" },
          { kind: "plaintext", file: path.join(osHomeDir, ".config", "openclaw", "gateway.env"), line: 1, key: "C" },
        ],
        summary: "3 plaintext secrets found in 3 files.",
      },
    }),
  );
  assert.ok(!card.includes(homeDir) && !card.includes("letmein") && !card.includes("acme"), card);
  assert.ok(card.includes(["~", "..hidden", "openclaw.json"].join(path.sep)), card);
  assert.ok(card.includes(["<state>", "agents", "*", "agent", "models.json"].join(path.sep)), card);
  assert.ok(card.includes(["~", ".config", "openclaw", "gateway.env"].join(path.sep)), card);
});

test("wide characters are measured in columns, so lines still fit", () => {
  const wide = path.join(homeDir, ...Array.from({ length: 6 }, () => "设置文件目录名称"), "openclaw.json");
  const card = renderReportCard(
    input({
      secrets: {
        ...secretsPass,
        grade: "unknown",
        findings: [{ kind: "plaintext", file: wide, key: "gateway.auth.token" }],
        unreadable: [wide],
        summary: "x",
      },
    }),
  );
  assertFitsOnePage(card);
  assert.ok(card.includes("openclaw.json"));
});

test("gateway fixes match the exposure they describe", () => {
  const fixFor = (summary: string, grade: "warning" | "critical") =>
    renderReportCard(input({ gateway: { grade, bind: "x", auth: "token", summary } }))
      .split("\n")
      .filter((line) => line.startsWith("     Fix: ") || line.startsWith("          "))
      .join(" ");
  for (const summary of [
    "Public internet exposure via Tailscale Funnel.",
    "Public internet exposure via Tailscale Funnel; password is not verifiable.",
  ]) {
    const fix = fixFor(summary, "warning");
    assert.match(fix, /Serve/, summary);
    assert.doesNotMatch(fix, /bind (the gateway )?to loopback/, summary);
  }
  const serve = fixFor("Gateway is reachable from the tailnet via Tailscale Serve.", "warning");
  assert.match(serve, /tailnet/);
  assert.doesNotMatch(serve, /bind (the gateway )?to loopback/);
  const combined = fixFor(
    "Public Tailscale Funnel exposure has a non-password auth mode. Also: Gateway is authenticated but exposed beyond loopback.",
    "critical",
  );
  assert.match(combined, /password/);
  assert.match(combined, /loopback/);
});

test("one check's unreadable files cannot crowd out another check's unknowns", () => {
  const unreadable = Array.from({ length: 13 }, (_, i) => path.join(stateDir, `inc${i}.json5`));
  const card = renderReportCard(
    input({
      secrets: { ...secretsPass, grade: "unknown", unreadable, summary: "x" },
      skills: { ...skillsPass, grade: "unknown", unknown: [{ path: "scan", reason: "time-limit" }], summary: "x" },
    }),
  );
  assert.ok(card.includes("Plaintext secrets: could not read 13 files"), card);
  assert.ok(card.includes("Risky skills: 1 location (1 time limit)"), card);
  assertFitsOnePage(card);
});

test("a long key never pushes the file location off the line", () => {
  const card = renderReportCard(
    input({
      secrets: {
        ...secretsPass,
        grade: "warning",
        findings: [{ kind: "plaintext", file: configPath, key: `${"*.".repeat(60)}token` }],
        summary: "1",
      },
    }),
  );
  assertFitsOnePage(card);
  assert.ok(card.includes(`in ${["~", ".openclaw", "openclaw.json"].join(path.sep)}`), card);
  assert.ok(card.includes("*.token"), card);
});

test("version and secret fixes fit the evidence", () => {
  const noIds = renderReportCard(
    input({ version: { grade: "warning", version: "2026.1.1", advisories: [], summary: "OpenClaw 2026.1.1 matches 1 bundled advisory." } }),
  );
  assert.ok(noIds.includes("Fix: Upgrade OpenClaw to the latest release."), noIds);
  assert.ok(!noIds.includes("affected by"));
  const include = renderReportCard(
    input({
      secrets: {
        ...secretsPass,
        grade: "warning",
        findings: [{ kind: "plaintext", file: path.join(stateDir, "secrets.env"), key: "gateway.auth.token" }],
        summary: "1",
      },
    }),
  );
  assert.match(include, /SecretRef/);
  assert.doesNotMatch(include, /chmod/);
});

test("skill root labels are never cut, even with large numbers", () => {
  const ws = path.join(stateDir, "workspace", ".agents", "skills");
  // Skill 10 is the only critical one, so it is listed first.
  const many = Array.from({ length: 10 }, (_, i) =>
    skillHit({
      ruleId: i === 9 ? "dangerous-exec" : "suspicious-network",
      severity: i === 9 ? "critical" : "warn",
      root: ws,
      rootKind: "workspace-agents",
      skillDir: path.join(ws, `s${i}`),
      file: path.join(ws, `s${i}`, "x.tsx"),
      line: 123456,
    }),
  );
  const card = renderReportCard(input({ skills: skillsWith([...many, { ...(many[9] as RiskySkillsResult["findings"][number]), line: 999999 }]) }));
  assertFitsOnePage(card);
  assert.ok(card.includes("skill 10 in a workspace .agents/skills folder"), card);
  assert.ok(!card.includes("…"), card);
});

test("a home directory of / is not used to shorten paths", () => {
  const varState = path.resolve(path.sep, "var", "lib", "openclaw");
  const etc = path.resolve(path.sep, "etc", "oc", "openclaw.json");
  const card = renderReportCard(
    input({
      homeDir: path.parse(process.cwd()).root,
      stateDir: varState,
      secrets: {
        ...secretsPass,
        grade: "warning",
        findings: [
          { kind: "plaintext", file: path.join(varState, "agents", "a", "agent", "models.json"), key: "k" },
          { kind: "plaintext", file: etc, key: "k" },
        ],
        summary: "2",
      },
    }),
  );
  assert.ok(card.includes(`in ${["<state>", "agents", "*", "agent", "models.json"].join(path.sep)}`), card);
  assert.ok(card.includes(`in ${etc}`), card);
  assert.ok(!card.includes(`~${path.sep}`), card);
});

test("a config directory outside home and state prints as <config>", () => {
  const configDir = path.resolve(path.sep, "data", "letmein-private");
  const card = renderReportCard(
    input({
      configPath: path.join(configDir, "openclaw.json"),
      secrets: {
        ...secretsPass,
        grade: "warning",
        findings: [{ kind: "plaintext", file: path.join(configDir, "openclaw.json"), key: "k" }],
        summary: "1",
      },
    }),
  );
  assert.ok(card.includes(`in ${["<config>", "openclaw.json"].join(path.sep)}`), card);
  assert.ok(!card.includes("letmein"), card);
});

test("rarer wide characters cannot push a line past the page width", () => {
  const odd = path.resolve(path.sep, "opt", "\u{1B000}".repeat(60), "c.json");
  const card = renderReportCard(input({ secrets: { ...secretsPass, grade: "unknown", unreadable: [odd], summary: "x" } }));
  // Columns are measured pessimistically here too: any non-ASCII character as two.
  for (const line of card.split("\n")) {
    if (line === waitlistUrl) continue;
    let width = 0;
    for (const char of line) width += char.charCodeAt(0) < 0x80 ? 1 : 2;
    assert.ok(width <= reportCardWidth, line);
  }
});

test("a long key keeps its label when it moves to its own line", () => {
  const card = renderReportCard(
    input({
      secrets: {
        ...secretsPass,
        grade: "warning",
        findings: [{ kind: "plaintext", file: path.join(stateDir, ".env"), line: 2, key: `${"X".repeat(70)}_TOKEN` }],
        summary: "1",
      },
    }),
  );
  assert.ok(card.split("\n").some((line) => /^ +key …X+_TOKEN$/.test(line)), card);
});

test("labels and continuation lines align when there are ten or more findings", () => {
  const findings = Array.from({ length: 12 }, (_, i) => ({ kind: "plaintext" as const, file: configPath, key: `k${i}` }));
  const lines = renderReportCard(input({ secrets: { ...secretsPass, grade: "warning", findings, summary: "12" } })).split("\n");
  const first = lines.findIndex((line) => / 1\. WARNING/.test(line));
  const tenth = lines.findIndex((line) => /10\. WARNING/.test(line));
  assert.ok(first >= 0 && tenth >= 0);
  for (const index of [first, tenth]) {
    const labelColumn = (lines[index] as string).indexOf("Plaintext");
    const next = lines[index + 1] as string;
    assert.equal(next.length - next.trimStart().length, labelColumn, `${lines[index]}\n${next}`);
  }
});

test("the most specific base wins, so an agent directory never exposes a narrower private name", () => {
  const outside = path.resolve(path.sep, "srv", "x");
  const secretIn = (file: string): PlaintextSecretsResult => ({
    grade: "warning",
    findings: [{ kind: "plaintext", file, key: "OPENAI_API_KEY" }],
    unreadable: [],
    scanned: [file],
    summary: "Plaintext secrets found.",
  });
  const cases: [Partial<ReportCardInput>, string, string][] = [
    // Nested agent directories: the inner one is used.
    [{ agentDirs: [path.join(homeDir, "teamdirs"), path.join(homeDir, "teamdirs", "acme-secret-client")] },
      path.join(homeDir, "teamdirs", "acme-secret-client", "models.json"), ["<agent-dir>", "models.json"].join(path.sep)],
    // An agent directory containing the config directory: <config> is used.
    [{ agentDirs: [outside], configPath: path.join(outside, "clients", "acme-corp", "openclaw.json") },
      path.join(outside, "clients", "acme-corp", ".env"), ["<config>", ".env"].join(path.sep)],
    // An agent directory containing the state directory: <state> is used.
    [{ agentDirs: [outside], stateDir: path.join(outside, "acme-state") },
      path.join(outside, "acme-state", ".env"), ["<state>", ".env"].join(path.sep)],
    // An agent directory inside home: <agent-dir> is used, not ~/<name>.
    [{ agentDirs: [path.join(homeDir, "acme-agent")] },
      path.join(homeDir, "acme-agent", "models.json"), ["<agent-dir>", "models.json"].join(path.sep)],
  ];
  for (const [overrides, file, shown] of cases) {
    const card = renderReportCard(input({ ...overrides, secrets: secretIn(file) }));
    assert.ok(card.includes(`in ${shown}`), card);
    assert.doesNotMatch(card, /acme/, card);
  }
});
