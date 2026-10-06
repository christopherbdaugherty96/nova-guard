export interface VersionAdvisory {
  cve: string;
  ghsa: string;
  /** Highest affected release, inclusive, as published in the advisory. */
  affectedThrough: string;
  patched: string;
  source: string;
}

export interface VersionAdvisoryResult {
  grade: "pass" | "critical" | "unknown";
  version: string | null;
  advisories: string[];
  summary: string;
}

/** Date the bundled advisory list was last reviewed. Scans never fetch it. */
export const advisoryDataDate = "2026-10-05";

export const bundledAdvisories: readonly VersionAdvisory[] = [
  {
    cve: "CVE-2026-25253",
    ghsa: "GHSA-g8p2-7wf7-98mq",
    affectedThrough: "2026.1.28",
    patched: "2026.1.29",
    source: "https://github.com/advisories/GHSA-g8p2-7wf7-98mq",
  },
];

const versionPattern =
  /(?<![\w.])v?(\d{4})\.(\d{1,2})\.(\d{1,2})(?:-([0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*))?(?![\w-]|\.\d)/g;

type Core = [number, number, number];

export function assessOpenClawVersion(
  versionOutput: string | undefined,
): VersionAdvisoryResult {
  if (versionOutput === undefined || versionOutput.trim().length === 0) {
    return unknown("OpenClaw version could not be read.");
  }

  const found = new Map<string, Core>();
  for (const match of versionOutput.matchAll(versionPattern)) {
    const [, year, month, day, prerelease] = match;
    const core: Core = [Number(year), Number(month), Number(day)];
    const label = `${core.join(".")}${prerelease ? `-${prerelease}` : ""}`;
    found.set(label, core);
  }

  if (found.size === 0) {
    return unknown("OpenClaw version output was not recognized.");
  }
  if (found.size > 1) {
    return unknown("OpenClaw version output contained conflicting versions.");
  }

  const [[version, core]] = found;
  // An inclusive upper bound covers prereleases of that release and earlier;
  // prereleases of later releases sort above it.
  const matched = bundledAdvisories.filter(
    (advisory) => compareCore(core, parseCore(advisory.affectedThrough)) <= 0,
  );

  if (matched.length === 0) {
    return {
      grade: "pass",
      version,
      advisories: [],
      summary: `OpenClaw ${version} matches no bundled advisory (data as of ${advisoryDataDate}).`,
    };
  }

  const ids = matched.map((advisory) => advisory.cve);
  const upgradeTo = matched
    .map((advisory) => advisory.patched)
    .sort((a, b) => compareCore(parseCore(b), parseCore(a)))[0];
  return {
    grade: "critical",
    version,
    advisories: ids,
    summary: `OpenClaw ${version} is affected by ${ids.join(", ")}; upgrade to ${upgradeTo} or later.`,
  };
}

function unknown(summary: string): VersionAdvisoryResult {
  return { grade: "unknown", version: null, advisories: [], summary };
}

function parseCore(value: string): Core {
  const [year, month, day] = value.split(".").map(Number);
  return [year, month, day];
}

function compareCore(a: Core, b: Core): number {
  for (let i = 0; i < 3; i += 1) {
    if (a[i] !== b[i]) {
      return a[i] - b[i];
    }
  }
  return 0;
}
