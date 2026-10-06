import assert from "node:assert/strict";
import test from "node:test";

import {
  advisoryDataDate,
  assessOpenClawVersion,
} from "../src/checks/version-advisories.js";

const cve = "CVE-2026-25253";
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

test("last affected release is critical for CVE-2026-25253", () => {
  assert.deepEqual(assessOpenClawVersion("2026.1.28\n"), {
    grade: "critical",
    version: "2026.1.28",
    advisories: [cve],
    summary: `OpenClaw 2026.1.28 is affected by ${cve}; upgrade to 2026.1.29 or later.`,
  });
});

test("clawdbot-era bare prerelease-style version is critical", () => {
  const result = assessOpenClawVersion("2026.1.24-0\n");
  assert.equal(result.grade, "critical");
  assert.equal(result.version, "2026.1.24-0");
});

test("first patched release passes against bundled advisories", () => {
  assert.deepEqual(assessOpenClawVersion("2026.1.29"), {
    grade: "pass",
    version: "2026.1.29",
    advisories: [],
    summary: `OpenClaw 2026.1.29 matches no bundled advisory (data as of ${advisoryDataDate}).`,
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

test("a prerelease of an affected release is affected", () => {
  const result = assessOpenClawVersion("OpenClaw 2026.1.28-beta.1");
  assert.equal(result.grade, "critical");
  assert.equal(result.version, "2026.1.28-beta.1");
});

test("a prerelease of the first patched release is unknown", () => {
  assert.deepEqual(assessOpenClawVersion("2026.1.29-beta.1"), {
    grade: "unknown",
    version: "2026.1.29-beta.1",
    advisories: [],
    summary: `OpenClaw 2026.1.29-beta.1 is a prerelease of the first release patched for ${cve}; the fix cannot be confirmed.`,
  });
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

test("very long counters are compared without precision loss", () => {
  const long = `2026.6.${"9".repeat(400)}`;
  const result = assessOpenClawVersion(long);
  assert.equal(result.grade, "pass");
  assert.equal(result.version, long);
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
  assert.deepEqual(assessOpenClawVersion(`2026.9.2 ${"x".repeat(5_000)}`), {
    grade: "unknown",
    version: null,
    advisories: [],
    summary: "OpenClaw version output was too long to trust.",
  });
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
