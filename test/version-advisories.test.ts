import assert from "node:assert/strict";
import test from "node:test";

import {
  advisoryDataDate,
  assessOpenClawVersion,
} from "../src/checks/version-advisories.js";

const cve = "CVE-2026-25253";

test("last affected release is critical for CVE-2026-25253", () => {
  assert.deepEqual(assessOpenClawVersion("2026.1.28"), {
    grade: "critical",
    version: "2026.1.28",
    advisories: [cve],
    summary: `OpenClaw 2026.1.28 is affected by ${cve}; upgrade to 2026.1.29 or later.`,
  });
});

test("first patched release passes against bundled advisories", () => {
  assert.deepEqual(assessOpenClawVersion("2026.1.29"), {
    grade: "pass",
    version: "2026.1.29",
    advisories: [],
    summary: `OpenClaw 2026.1.29 matches no bundled advisory (data as of ${advisoryDataDate}).`,
  });
});

test("version is extracted from surrounding CLI output", () => {
  const result = assessOpenClawVersion("openclaw 2026.9.2 (abc1234)\n");
  assert.equal(result.grade, "pass");
  assert.equal(result.version, "2026.9.2");
});

test("a v-prefixed affected version is still recognized", () => {
  const result = assessOpenClawVersion("v2026.1.28");
  assert.equal(result.grade, "critical");
  assert.equal(result.version, "2026.1.28");
});

test("an earlier year is affected", () => {
  assert.equal(assessOpenClawVersion("2025.12.31").grade, "critical");
});

test("a prerelease of an affected release is affected", () => {
  const result = assessOpenClawVersion("2026.1.28-beta.1");
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

test("an unparseable version token cannot be bypassed by another date", () => {
  for (const input of [
    "openclaw 2026.1.28_1 (built 2026.2.3)",
    "openclaw 2026.1.28.1 (released 2026.10.1)",
  ]) {
    assert.equal(assessOpenClawVersion(input).grade, "unknown", input);
  }
});

test("a version glued to other text cannot be bypassed by another date", () => {
  for (const input of [
    "openclaw_2026.1.28 (built 2026.2.3)",
    "openclaw.2026.1.28 built 2026.2.3",
    "openclawv2026.1.28 built 2026.2.3",
    "12026.1.28 built 2026.2.3",
    "\x1b[2K2026.1.28 built 2026.2.3",
    "\uff12\uff10\uff12\uff16.\uff11.\uff12\uff18 built 2026.2.3",
    "openclaw 2026.1 built 2026.2.3",
  ]) {
    assert.equal(assessOpenClawVersion(input).grade, "unknown", JSON.stringify(input));
  }
});

test("long runs of dots are handled in linear time", () => {
  const started = performance.now();
  assessOpenClawVersion(`2026.1.1${".".repeat(50_000)}x`);
  assert.ok(performance.now() - started < 250);
});

test("long digit runs are handled in linear time", () => {
  const started = performance.now();
  assessOpenClawVersion("1".repeat(4_000));
  assert.ok(performance.now() - started < 250);
});

test("oversized version output is unknown", () => {
  assert.deepEqual(assessOpenClawVersion(`2026.9.2 ${"x".repeat(5_000)}`), {
    grade: "unknown",
    version: null,
    advisories: [],
    summary: "OpenClaw version output was too long to trust.",
  });
});

test("a hyphenated package-name prefix is recognized", () => {
  const result = assessOpenClawVersion("openclaw-2026.1.28");
  assert.equal(result.grade, "critical");
  assert.equal(result.version, "2026.1.28");
});

test("ANSI color codes do not hide the version", () => {
  const result = assessOpenClawVersion("\x1b[32m2026.1.28\x1b[0m");
  assert.equal(result.grade, "critical");
  assert.equal(result.version, "2026.1.28");
});

test("CRLF, build metadata, and sentence punctuation are tolerated", () => {
  assert.equal(assessOpenClawVersion("openclaw 2026.1.28\r\n").grade, "critical");
  assert.equal(assessOpenClawVersion("2026.1.28+abc123").version, "2026.1.28");
  assert.equal(assessOpenClawVersion("Version 2026.9.2.").grade, "pass");
});

test("leading zeros and repeated identical versions are one version", () => {
  const result = assessOpenClawVersion("2026.01.28 (2026.1.28)");
  assert.equal(result.grade, "critical");
  assert.equal(result.version, "2026.1.28");
});

test("an update notice alongside the installed version is unknown", () => {
  assert.equal(
    assessOpenClawVersion("2026.1.28\nUpdate available: 2026.9.2").grade,
    "unknown",
  );
});

test("impossible calendar dates are unknown, not pass", () => {
  for (const input of ["2026.13.1", "2026.99.99", "2026.0.1", "2026.2.30", "2026.1.0"]) {
    assert.deepEqual(
      assessOpenClawVersion(input),
      {
        grade: "unknown",
        version: null,
        advisories: [],
        summary: "OpenClaw version output was not recognized.",
      },
      input,
    );
  }
  assert.equal(assessOpenClawVersion("2028.2.29").grade, "pass");
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

test("unrecognized version output is unknown", () => {
  assert.deepEqual(assessOpenClawVersion("command not found: openclaw"), {
    grade: "unknown",
    version: null,
    advisories: [],
    summary: "OpenClaw version output was not recognized.",
  });
});

test("conflicting versions in the output are unknown", () => {
  assert.deepEqual(assessOpenClawVersion("cli 2026.1.28 gateway 2026.9.2"), {
    grade: "unknown",
    version: null,
    advisories: [],
    summary: "OpenClaw version output contained conflicting versions.",
  });
});

test("a longer dotted number is not mistaken for a version", () => {
  assert.equal(assessOpenClawVersion("10.2026.1.28.5").grade, "unknown");
});
