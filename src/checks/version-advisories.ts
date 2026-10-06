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

/** Version output is one short line; more than 4 KiB of UTF-8 is not trusted. */
const maxOutputBytes = 4096;
// CSI sequences (colors, cursor and line control) and OSC sequences.
const terminalEscape = /\x1b\[[0-?]*[ -\/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g;
// SemVer-canonical numbers: no leading zeros in the year, month, counter, or
// numeric prerelease identifiers (build metadata may have them).
const prereleaseIdentifier = "(?:0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*)";
const versionPattern =
  `([1-9]\\d{3})\\.([1-9]|1[0-2])\\.([1-9]\\d*)` +
  `(?:-(${prereleaseIdentifier}(?:\\.${prereleaseIdentifier})*))?` +
  `(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?`;
/**
 * The whole output must be one of the line shapes OpenClaw is verified to
 * print for `--version`, so no other date-like text can stand in for it:
 * - the bare version (commander default, clawdbot through 2026.1.x);
 * - `OpenClaw <version>` or `OpenClaw <version> (<commit>)` (current CLI),
 *   where the CLI truncates the commit to seven lowercase hex digits.
 */
const versionLine = new RegExp(
  `^(?:${versionPattern}|OpenClaw ${versionPattern}(?: \\([0-9a-f]{7}\\))?)$`,
);

// BigInt keeps arbitrarily long maintenance counters exact.
type Core = [bigint, bigint, bigint];

export function assessOpenClawVersion(
  versionOutput: string | undefined,
): VersionAdvisoryResult {
  if (versionOutput === undefined || versionOutput.trim().length === 0) {
    return unknown("OpenClaw version could not be read.");
  }
  if (Buffer.byteLength(versionOutput, "utf8") > maxOutputBytes) {
    return unknown("OpenClaw version output was too long to trust.");
  }

  const line = versionOutput.replace(terminalEscape, "").trim();
  const match = versionLine.exec(line);
  if (!match) {
    return unknown("OpenClaw version output was not recognized.");
  }
  // Groups 1-4 hold the bare form; groups 5-8 hold the "OpenClaw" form.
  const [year, month, counter, prereleaseTag] =
    match[1] !== undefined ? match.slice(1, 5) : match.slice(5, 9);
  const core: Core = [BigInt(year), BigInt(month), BigInt(counter)];
  if (!isReleaseVersion(core)) {
    return unknown("OpenClaw version output was not recognized.");
  }
  const prerelease = prereleaseTag !== undefined;
  const version = `${core.join(".")}${prerelease ? `-${prereleaseTag}` : ""}`;

  // An inclusive upper bound covers prereleases of that release and earlier.
  const matched = bundledAdvisories.filter(
    (advisory) => compareCore(core, parseCore(advisory.affectedThrough)) <= 0,
  );

  // A prerelease of the first patched release may predate the fix.
  const unconfirmed = prerelease
    ? bundledAdvisories.filter(
        (advisory) =>
          !matched.includes(advisory) &&
          compareCore(core, parseCore(advisory.patched)) === 0,
      )
    : [];
  if (matched.length === 0 && unconfirmed.length > 0) {
    return {
      grade: "unknown",
      version,
      advisories: [],
      summary: `OpenClaw ${version} is a prerelease of the first release patched for ${unconfirmed
        .map((advisory) => advisory.cve)
        .join(", ")}; the fix cannot be confirmed.`,
    };
  }

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

/**
 * OpenClaw versions are year.month.N. N is usually the day but Extended Stable
 * releases use it as a maintenance counter (for example v2026.6.35), so only
 * the month range and a non-zero counter are enforced.
 */
function isReleaseVersion([, month, counter]: Core): boolean {
  return month >= 1n && month <= 12n && counter >= 1n;
}

function parseCore(value: string): Core {
  const [year, month, counter] = value.split(".").map((part) => BigInt(part));
  return [year, month, counter];
}

function compareCore(a: Core, b: Core): number {
  for (let i = 0; i < 3; i += 1) {
    if (a[i] !== b[i]) {
      return a[i] < b[i] ? -1 : 1;
    }
  }
  return 0;
}
