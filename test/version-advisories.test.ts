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

test("a prerelease of the patched release follows the advisory range", () => {
  assert.equal(assessOpenClawVersion("2026.1.29-beta.1").grade, "pass");
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
