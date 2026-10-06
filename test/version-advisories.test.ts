import assert from "node:assert/strict";
import test from "node:test";

import semver from "semver";

import {
  advisoryDataDate,
  bundledAdvisories,
} from "../src/data/openclaw-advisories.js";
import {
  assessOpenClawVersion as assessWithBundle,
  type BundledAdvisory,
} from "../src/checks/version-advisories.js";

const g8p2 = "GHSA-g8p2-7wf7-98mq";
const fixture: readonly BundledAdvisory[] = [
  {
    ghsa: g8p2,
    package: "clawdbot",
    severity: "high",
    vulnerableVersions: "<=2026.1.28",
    title: "Fixture: token exfiltration (CVE-2026-25253)",
  },
  {
    ghsa: "GHSA-0000-0000-0002",
    package: "openclaw",
    severity: "high",
    vulnerableVersions: ">=2026.4.7 <2026.4.9",
    title: "Fixture: issue introduced in 2026.4.7",
  },
  {
    ghsa: "GHSA-0000-0000-0003",
    package: "openclaw",
    severity: "high",
    vulnerableVersions: ">=2026.5.1 <=2026.5.3-1",
    title: "Fixture: fixed in hotfix 2026.5.3-2",
  },
  {
    ghsa: "GHSA-0000-0000-0004",
    package: "openclaw",
    severity: "high",
    vulnerableVersions: ">=2026.7.1 <=2026.7.2",
    title: "Fixture: inclusive bound on a release",
  },
  {
    ghsa: "GHSA-0000-0000-0005",
    package: "openclaw",
    severity: "high",
    vulnerableVersions: ">=2026.8.1-0 <2026.8.3",
    title: "Fixture: SemVer lowest-prerelease lower bound",
  },
  {
    ghsa: "GHSA-0000-0000-0001",
    package: "openclaw",
    severity: "low",
    vulnerableVersions: ">=2026.6.1 <2026.6.5",
    title: "Fixture: low-severity issue",
  },
];
const assessOpenClawVersion = (output: string | undefined) =>
  assessWithBundle(output, fixture, "2026-10-06");
const notRecognized = {
  grade: "unknown",
  version: null,
  advisories: [],
  summary: "OpenClaw version output was not recognized.",
} as const;

// Formats verified against OpenClaw source:
// - v2026.1.24 (clawdbot) to v2026.1.30: commander prints the bare version.
// - current main (entry.version-fast-path.ts, cli/program/help.ts):
//   "OpenClaw <version>" or "OpenClaw <version> (<7-hex commit>)".

test("a release matching a high-severity advisory is critical", () => {
  assert.deepEqual(assessOpenClawVersion("2026.1.28\n"), {
    grade: "critical",
    version: "2026.1.28",
    advisories: [g8p2],
    summary:
      "OpenClaw 2026.1.28 matches 1 known advisory (1 critical or high); upgrade to a current release.",
  });
});

test("a release matching only low or moderate advisories is a warning", () => {
  assert.deepEqual(assessOpenClawVersion("OpenClaw 2026.6.3"), {
    grade: "warning",
    version: "2026.6.3",
    advisories: ["GHSA-0000-0000-0001"],
    summary:
      "OpenClaw 2026.6.3 matches 1 known advisory (moderate or low); upgrade to a current release.",
  });
});

test("clawdbot-era bare prerelease-style version is critical", () => {
  const result = assessOpenClawVersion("2026.1.24-0\n");
  assert.equal(result.grade, "critical");
  assert.equal(result.version, "2026.1.24-0");
});

test("a release outside every advisory range passes with the data date", () => {
  assert.deepEqual(assessOpenClawVersion("2026.1.29"), {
    grade: "pass",
    version: "2026.1.29",
    advisories: [],
    summary: "OpenClaw 2026.1.29 matches no bundled advisory (data as of 2026-10-06).",
  });
});

test("current CLI format with commit is recognized", () => {
  const result = assessOpenClawVersion("OpenClaw 2026.9.2 (282f796)\n");
  assert.equal(result.grade, "pass");
  assert.equal(result.version, "2026.9.2");
});

test("current CLI format without commit is recognized", () => {
  const result = assessOpenClawVersion("OpenClaw 2026.1.28\r\n");
  assert.equal(result.grade, "critical");
  assert.equal(result.version, "2026.1.28");
});

test("an earlier year is affected", () => {
  assert.equal(assessOpenClawVersion("2025.12.31").grade, "critical");
});

test("prereleases are judged by SemVer precedence, not skipped", () => {
  const result = assessOpenClawVersion("OpenClaw 2026.1.28-beta.1");
  assert.equal(result.grade, "critical");
  assert.equal(result.version, "2026.1.28-beta.1");
  assert.equal(assessOpenClawVersion("2026.6.5-beta.1").grade, "warning");
});

test("a numeric hotfix suffix is graded at least as severely as its release", () => {
  // OpenClaw publishes X-1, X-2 after X, but SemVer orders them before X.
  const hotfix = assessOpenClawVersion("2026.4.7-1");
  assert.equal(hotfix.grade, "critical");
  assert.deepEqual(hotfix.advisories, ["GHSA-0000-0000-0002"]);
  assert.equal(hotfix.version, "2026.4.7-1");
  assert.equal(assessOpenClawVersion("2026.4.7-beta.1").grade, "pass");
});

test("a release precedes its own numeric hotfixes in advisory ranges", () => {
  // >=2026.5.1 <=2026.5.3-1 covers 2026.5.3 and 2026.5.3-1 but not the fixed 2026.5.3-2.
  assert.equal(assessOpenClawVersion("2026.5.3").grade, "critical");
  assert.equal(assessOpenClawVersion("OpenClaw 2026.5.3-1").grade, "critical");
  assert.equal(assessOpenClawVersion("2026.5.3-2").grade, "pass");
  assert.equal(assessOpenClawVersion("2026.5.3-beta.1").grade, "critical");
  assert.equal(assessOpenClawVersion("2026.5.1-beta.1").grade, "pass");
});

test("a hotfix published after a fixed release is not affected", () => {
  // >=2026.4.7 <2026.4.9: the fix shipped in 2026.4.9, before 2026.4.9-1.
  assert.equal(assessOpenClawVersion("2026.4.9-1").grade, "pass");
  assert.equal(assessOpenClawVersion("2026.4.9-beta.1").grade, "critical");
});

test("an inclusive bound on a release still covers that release's hotfixes", () => {
  // <=2026.7.2 does not say whether 2026.7.2-1 carried the fix.
  assert.equal(assessOpenClawVersion("2026.7.2-1").grade, "critical");
  assert.equal(assessOpenClawVersion("2026.7.3").grade, "pass");
});

test("a -0 lower bound keeps its SemVer meaning of every prerelease", () => {
  assert.equal(assessOpenClawVersion("2026.8.1").grade, "critical");
  assert.equal(assessOpenClawVersion("2026.8.1-beta.1").grade, "critical");
  assert.equal(assessOpenClawVersion("2026.7.31").grade, "pass");
});

test("ANSI and other terminal escapes do not hide the version", () => {
  for (const input of ["\x1b[32m2026.1.28\x1b[0m", "\x1b[2KOpenClaw 2026.1.28"]) {
    const result = assessOpenClawVersion(input);
    assert.equal(result.grade, "critical", JSON.stringify(input));
    assert.equal(result.version, "2026.1.28");
  }
});

test("build metadata is accepted but not part of the version label", () => {
  assert.equal(assessOpenClawVersion("2026.1.28+abc123").version, "2026.1.28");
});

test("Extended Stable maintenance counters above 31 are valid releases", () => {
  // Official tags such as v2026.6.35 use the third component as a counter.
  const result = assessOpenClawVersion("OpenClaw 2026.6.35 (a1b2c3d)");
  assert.equal(result.grade, "pass");
  assert.equal(result.version, "2026.6.35");
});

test("maintenance counters are not limited to two digits", () => {
  assert.equal(assessOpenClawVersion("2026.6.100").grade, "pass");
  assert.equal(assessOpenClawVersion("2025.12.100").grade, "critical");
});

test("counters too large to compare with advisory ranges are unknown", () => {
  for (const input of [`2026.6.${"9".repeat(400)}`, "2026.1.9007199254740993"]) {
    assert.deepEqual(assessOpenClawVersion(input), notRecognized, input);
  }
});

test("output that does not say it is the installed version is unknown", () => {
  for (const input of [
    "openclaw: version unavailable; built 2026.9.2",
    "error-2026.9.2",
    "failed at 2026.9.2",
    "[openclaw] Failed to resolve version: built 2026.9.2",
    "Version 2026.9.2.",
    "openclaw-2026.9.2",
    "v2026.9.2",
    "OpenClaw 2026.9.2 (not-a-commit)",
    "OpenClaw 2026.9.2 — tagline",
    "2026.9.2 2026.9.2",
    "OpenClaw 2026.9.2 (282f796a)",
    "OpenClaw 2026.9.2 (282f796dfa057e1e21fcdd0f3686712578b0c0e9)",
    "2026.01.029",
    "2026.1.30-01",
    "OpenClaw 2026.1.30-beta.01",
    "0999.1.1",
  ]) {
    assert.deepEqual(assessOpenClawVersion(input), notRecognized, JSON.stringify(input));
  }
});

test("a malformed or truncated version cannot be bypassed by another date", () => {
  for (const input of [
    "openclaw 2026.1.28_1 (built 2026.2.3)",
    "openclaw 2026.1.28.1 (released 2026.10.1)",
    "openclaw_2026.1.28 (built 2026.2.3)",
    "２０２６.１.２８ built 2026.2.3",
    "openclaw 2026. (built 2026.9.2)",
    "2026.1.28\nUpdate available: 2026.9.2",
    "2026.1.9007199254740992 2026.1.9007199254740993",
  ]) {
    assert.equal(assessOpenClawVersion(input).grade, "unknown", JSON.stringify(input));
  }
});

test("impossible month or zero components are unknown, not pass", () => {
  for (const input of ["2026.13.1", "2026.99.99", "2026.0.1", "2026.1.0"]) {
    assert.deepEqual(assessOpenClawVersion(input), notRecognized, input);
  }
});

test("oversized version output is unknown", () => {
  const tooLong = {
    grade: "unknown",
    version: null,
    advisories: [],
    summary: "OpenClaw version output was too long to trust.",
  };
  assert.deepEqual(assessOpenClawVersion(`2026.9.2 ${"x".repeat(5_000)}`), tooLong);
  // 1,400 CJK characters are about 4.2 KiB of UTF-8 but only 1,400 UTF-16 units.
  const hidden = `\x1b]0;${"\u6f22".repeat(1_400)}\x07OpenClaw 2026.9.2`;
  assert.deepEqual(assessOpenClawVersion(hidden), tooLong);
});

test("pathological input is handled in linear time", () => {
  for (const input of [
    `2026.1.1${".".repeat(4_000)}x`,
    "1".repeat(4_000),
    `2026.1.1-${"a.".repeat(2_000)}!`,
  ]) {
    const started = performance.now();
    assessOpenClawVersion(input);
    assert.ok(performance.now() - started < 250);
  }
});

test("missing version output is unknown, not pass", () => {
  for (const input of [undefined, "", "   \n"]) {
    assert.deepEqual(assessOpenClawVersion(input), {
      grade: "unknown",
      version: null,
      advisories: [],
      summary: "OpenClaw version could not be read.",
    });
  }
});

test("bundled data is dated, well-formed, and parseable", () => {
  assert.match(advisoryDataDate, /^\d{4}-\d{2}-\d{2}$/);
  assert.ok(bundledAdvisories.length > 0);
  for (const advisory of bundledAdvisories) {
    assert.match(advisory.ghsa, /^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/);
    assert.ok(["openclaw", "clawdbot", "moltbot"].includes(advisory.package));
    assert.ok(["critical", "high", "moderate", "low"].includes(advisory.severity));
    assert.ok(semver.validRange(advisory.vulnerableVersions), advisory.vulnerableVersions);
  }
});

test("bundled data includes CVE-2026-25253 and the 2026.2.1 authorization bypass", () => {
  const critical = assessWithBundle("2026.1.28");
  assert.equal(critical.grade, "critical");
  assert.ok(critical.advisories.includes(g8p2));
  const later = assessWithBundle("OpenClaw 2026.1.30");
  assert.equal(later.grade, "critical");
  assert.ok(later.advisories.includes("GHSA-fhvm-j76f-qmjv"));
});

test("a current release passes against the bundled data", () => {
  assert.equal(assessWithBundle("OpenClaw 2026.9.8 (282f796)").grade, "pass");
});
