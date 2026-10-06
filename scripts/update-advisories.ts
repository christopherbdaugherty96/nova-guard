// Maintainer tool: regenerates src/data/openclaw-advisories.ts from npm's bulk
// advisory endpoint (the GitHub-reviewed data `npm audit` uses). Runs the same
// on Windows, macOS, and Linux; it spawns no child processes.
//
//   npm run update-advisories
//   npm run update-advisories -- --allow-removals   (only if removals are intended)
import { writeFileSync } from "node:fs";

import { bundledAdvisories } from "../src/data/openclaw-advisories.js";
import type { BundledAdvisory } from "../src/checks/version-advisories.js";
import {
  buildBundle,
  bulkAdvisoryEndpoint,
  fetchBulkAdvisories,
  fetchPackageVersions,
  renderBundle,
} from "../src/tooling/advisory-bundle.js";

const packages: BundledAdvisory["package"][] = ["openclaw", "clawdbot", "moltbot"];
const allowRemovals = process.argv.includes("--allow-removals");

const request: Record<string, string[]> = {};
for (const name of packages) {
  request[name] = await fetchPackageVersions(name);
}
const body = await fetchBulkAdvisories(request);
const advisories = buildBundle(body, packages, bundledAdvisories, { allowRemovals });

const kept = new Set(advisories.map((advisory) => `${advisory.package}:${advisory.ghsa}`));
const removed = bundledAdvisories.filter(
  (advisory) => !kept.has(`${advisory.package}:${advisory.ghsa}`),
);
if (removed.length > 0) {
  console.warn(`Removed ${removed.length} advisories (--allow-removals):`);
  for (const advisory of removed) console.warn(`  ${advisory.package}:${advisory.ghsa}`);
}

const dataDate = new Date().toISOString().slice(0, 10);
const source = `${bulkAdvisoryEndpoint} (${packages.join(", ")})`;
writeFileSync(
  new URL("../src/data/openclaw-advisories.ts", import.meta.url),
  renderBundle(advisories, dataDate, source),
);
console.log(`Wrote ${advisories.length} advisories dated ${dataDate}.`);
