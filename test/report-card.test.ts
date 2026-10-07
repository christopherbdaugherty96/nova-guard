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

function assertFitsOnePage(card: string) {
  const lines = card.split("\n");
  assert.ok(lines.length <= reportCardPageLines, `lines: ${lines.length}`);
  // The waitlist URL is printed whole so it stays usable; every other line fits.
  for (const line of lines) {
    if (line !== waitlistUrl) assert.ok([...line].length <= reportCardWidth, `too wide: ${line}`);
  }
}

test("an all-pass scan grades PASS on one printable page with the waitlist link", () => {
  const card = renderReportCard(input());
  assert.match(card, /^Overall: PASS$/m);
  assert.ok(card.includes(waitlistUrl));
  assert.match(card, /Safer, not safe/);
  assertFitsOnePage(card);
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
  assert.ok(card.includes(`${home(".openclaw", ".env")}:3  OPENAI_API_KEY`), card);
  assert.ok(card.includes(`${home(".openclaw", "openclaw.json")}  env.vars.*`), card);
  assert.ok(card.includes(`${home(".openclaw", "agents", "*", "agent", "models.json")}  providers.*.apiKey`), card);
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
          { ruleId: "shell-pipe-to-shell", severity: "critical", root: managedSkills, skillDir, file: path.join(skillDir, "SKILL.md"), line: 6 },
          { ruleId: "dangerous-exec", severity: "critical", root: managedSkills, skillDir, file: path.join(skillDir, "lib", "letmein.js"), line: 4 },
          { ruleId: "dangerous-exec", severity: "critical", root: managedSkills, skillDir, file: path.join(skillDir, "lib", "letmein.js"), line: 9 },
          { ruleId: "suspicious-network", severity: "warn", root: managedSkills, skillDir, file: path.join(skillDir, "net.ts"), line: 1 },
        ],
        unknown: [],
        skills: 1,
        summary: "4 risky patterns found in 1 skill.",
      },
    }),
  );
  assert.match(card, /^Overall: CRITICAL$/m);
  assert.ok(!card.includes("letmein"), card);
  const root = ["~", ".openclaw", "skills", "*"].join(path.sep);
  assert.ok(card.includes(`skill ${root}: SKILL.md line 6`), card);
  assert.ok(card.includes(`skill ${root}: .js file line 4 (+1 more)`), card);
  assert.ok(card.includes(`skill ${root}: .ts file line 1`), card);
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
  assert.ok(card.includes("openclaw.json  gateway.auth.token"), card);
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
