import assert from "node:assert/strict";
import test from "node:test";

import type { BundledAdvisory } from "../src/checks/version-advisories.js";
import {
  buildBundle,
  fetchPackageVersions,
  type RawAdvisory,
} from "../src/tooling/advisory-bundle.js";

const packages = ["openclaw", "clawdbot"] as const;
const raw = (ghsa: string, overrides: Partial<RawAdvisory> = {}): RawAdvisory => ({
  url: `https://github.com/advisories/${ghsa}`,
  severity: "high",
  vulnerable_versions: "<2026.2.1",
  title: `Advisory ${ghsa}`,
  ...overrides,
});
const bundled = (ghsa: string, pkg: BundledAdvisory["package"]): BundledAdvisory => ({
  ghsa,
  package: pkg,
  severity: "high",
  vulnerableVersions: "<2026.2.1",
  title: `Advisory ${ghsa}`,
});

const fullResponse = {
  openclaw: [raw("GHSA-aaaa-aaaa-aaaa"), raw("GHSA-bbbb-bbbb-bbbb")],
  clawdbot: [raw("GHSA-cccc-cccc-cccc")],
};
const previous = [
  bundled("GHSA-aaaa-aaaa-aaaa", "openclaw"),
  bundled("GHSA-bbbb-bbbb-bbbb", "openclaw"),
  bundled("GHSA-cccc-cccc-cccc", "clawdbot"),
];

test("a complete response rebuilds the bundle in stable order", () => {
  const bundle = buildBundle(fullResponse, packages, previous);
  assert.deepEqual(
    bundle.map((advisory) => `${advisory.package}:${advisory.ghsa}`),
    ["openclaw:GHSA-aaaa-aaaa-aaaa", "openclaw:GHSA-bbbb-bbbb-bbbb", "clawdbot:GHSA-cccc-cccc-cccc"],
  );
});

test("a partial response that drops existing advisories is refused", () => {
  const partial = { openclaw: [raw("GHSA-aaaa-aaaa-aaaa")], clawdbot: fullResponse.clawdbot };
  assert.throws(
    () => buildBundle(partial, packages, previous),
    /1 bundled advisory would be removed.*openclaw:GHSA-bbbb-bbbb-bbbb.*--allow-removals/s,
  );
});

test("removals are allowed only with explicit acknowledgement", () => {
  const partial = { openclaw: [raw("GHSA-aaaa-aaaa-aaaa")], clawdbot: fullResponse.clawdbot };
  const bundle = buildBundle(partial, packages, previous, { allowRemovals: true });
  assert.equal(bundle.length, 2);
});

test("new advisories are added without acknowledgement", () => {
  const grown = {
    ...fullResponse,
    clawdbot: [...fullResponse.clawdbot, raw("GHSA-dddd-dddd-dddd")],
  };
  assert.equal(buildBundle(grown, packages, previous).length, 4);
});

test("an empty or missing package list is refused even with acknowledgement", () => {
  for (const body of [{ openclaw: fullResponse.openclaw, clawdbot: [] }, { openclaw: fullResponse.openclaw }]) {
    assert.throws(
      () => buildBundle(body, packages, previous, { allowRemovals: true }),
      /No advisories returned for clawdbot/,
    );
  }
});

test("unknown severities and unsupported ranges are refused", () => {
  for (const bad of [
    raw("GHSA-aaaa-aaaa-aaaa", { severity: "severe" }),
    raw("GHSA-aaaa-aaaa-aaaa", { vulnerable_versions: "2026.1.1 - 2026.2.1" }),
    raw("GHSA-aaaa-aaaa-aaaa", { vulnerable_versions: "not a range" }),
  ]) {
    assert.throws(() =>
      buildBundle({ ...fullResponse, openclaw: [bad] }, packages, [], { allowRemovals: true }),
    );
  }
});

test("package versions come from the registry over HTTP, not a child process", async () => {
  const requested: string[] = [];
  const fakeFetch = async (url: string | URL | Request) => {
    requested.push(String(url));
    return new Response(JSON.stringify({ versions: { "2026.1.29": {}, "2026.9.8": {} } }));
  };
  const versions = await fetchPackageVersions("openclaw", fakeFetch as typeof fetch);
  assert.deepEqual(versions, ["2026.1.29", "2026.9.8"]);
  assert.deepEqual(requested, ["https://registry.npmjs.org/openclaw"]);
});

test("a failed registry request is an error, not an empty version list", async () => {
  const failing = async () => new Response("unavailable", { status: 503 });
  await assert.rejects(
    fetchPackageVersions("openclaw", failing as typeof fetch),
    /openclaw versions: HTTP 503/,
  );
});
