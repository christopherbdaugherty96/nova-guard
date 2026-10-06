import semver from "semver";

import {
  advisoryDataDate as bundledDataDate,
  bundledAdvisories,
} from "../data/openclaw-advisories.js";

export interface BundledAdvisory {
  ghsa: string;
  package: "openclaw" | "clawdbot" | "moltbot";
  severity: "critical" | "high" | "moderate" | "low";
  /** npm range from the GitHub-reviewed advisory, e.g. "<2026.2.1". */
  vulnerableVersions: string;
  title: string;
}

export interface VersionAdvisoryResult {
  grade: "pass" | "warning" | "critical" | "unknown";
  version: string | null;
  /** GHSA ids of matching advisories, critical and high first. */
  advisories: string[];
  summary: string;
}

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

const severe = new Set<BundledAdvisory["severity"]>(["critical", "high"]);

/**
 * Grades `openclaw --version` output against the bundled, dated advisory list.
 * Ranges are evaluated with npm's semver, as `npm audit` does, but prereleases
 * are always included so a prerelease is judged by precedence, not skipped.
 * The version line does not name its package, so every package's advisories
 * apply: they share one calendar version line (clawdbot, moltbot, openclaw).
 */
export function assessOpenClawVersion(
  versionOutput: string | undefined,
  advisories: readonly BundledAdvisory[] = bundledAdvisories,
  dataDate: string = bundledDataDate,
): VersionAdvisoryResult {
  if (versionOutput === undefined || versionOutput.trim().length === 0) {
    return unknown("OpenClaw version could not be read.");
  }
  if (Buffer.byteLength(versionOutput, "utf8") > maxOutputBytes) {
    return unknown("OpenClaw version output was too long to trust.");
  }

  const match = versionLine.exec(versionOutput.replace(terminalEscape, "").trim());
  if (!match) {
    return unknown("OpenClaw version output was not recognized.");
  }
  // Groups 1-4 hold the bare form; groups 5-8 hold the "OpenClaw" form.
  const [year, month, counter, prerelease] =
    match[1] !== undefined ? match.slice(1, 5) : match.slice(5, 9);
  const version = `${year}.${month}.${counter}${prerelease ? `-${prerelease}` : ""}`;
  // semver rejects components beyond Number.MAX_SAFE_INTEGER; such a version
  // cannot be compared with the advisory ranges, so it is not graded.
  if (semver.valid(version) === null) {
    return unknown("OpenClaw version output was not recognized.");
  }

  const ordered = toReleaseOrder(version);
  const matched = advisories.filter((advisory) =>
    semver.satisfies(ordered, rangeInReleaseOrder(advisory.vulnerableVersions), {
      includePrerelease: true,
    }),
  );
  if (matched.length === 0) {
    return {
      grade: "pass",
      version,
      advisories: [],
      summary: `OpenClaw ${version} matches no bundled advisory (data as of ${dataDate}).`,
    };
  }

  const ids = [
    ...new Set(
      [...matched]
        .sort(
          (a, b) =>
            Number(severe.has(b.severity)) - Number(severe.has(a.severity)) ||
            a.ghsa.localeCompare(b.ghsa),
        )
        .map((advisory) => advisory.ghsa),
    ),
  ];
  const severeCount = new Set(
    matched.filter((advisory) => severe.has(advisory.severity)).map((advisory) => advisory.ghsa),
  ).size;
  const noun = ids.length === 1 ? "advisory" : "advisories";
  return {
    grade: severeCount > 0 ? "critical" : "warning",
    version,
    advisories: ids,
    summary: `OpenClaw ${version} matches ${ids.length} known ${noun} (${
      severeCount > 0 ? `${severeCount} critical or high` : "moderate or low"
    }); upgrade to a current release.`,
  };
}

/**
 * OpenClaw publishes numeric hotfixes after their release (X, then X-1, X-2),
 * but SemVer orders X-1 before X. Versions and range bounds are mapped to an
 * order that matches publication:
 *   X-beta.1 < X (X-zz) < X-1 (X-zzhotfix.1) < X-2 < next release.
 * "zz" sorts after any alphabetic prerelease tag OpenClaw uses (alpha, beta).
 */
const numericHotfix = /^\d+$/;
const versionToken = /(\d+\.\d+\.\d+)(?:-([0-9A-Za-z.-]+))?/g;

function toReleaseOrder(version: string): string {
  return version.replace(versionToken, (_match, core: string, prerelease?: string) => {
    if (prerelease === undefined) {
      return `${core}-zz`;
    }
    return numericHotfix.test(prerelease) ? `${core}-zzhotfix.${prerelease}` : `${core}-${prerelease}`;
  });
}

const comparatorToken = /(<=|>=|<|>|=)?(\d+\.\d+\.\d+)(?:-([0-9A-Za-z.-]+))?/g;
const lastHotfix = "zzhotfix.999999999";
const orderedRanges = new Map<string, string>();

/**
 * Maps every comparator in a range into release order. Two bounds keep a
 * conservative meaning: "<=X" also covers X's hotfixes, because the advisory
 * does not say a hotfix carried the fix, and "-0" stays SemVer's idiom for
 * "every prerelease of X" (OpenClaw has never published an X-0 hotfix).
 */
function rangeInReleaseOrder(range: string): string {
  let ordered = orderedRanges.get(range);
  if (ordered === undefined) {
    ordered = range.replace(
      comparatorToken,
      (_match, operator: string | undefined, core: string, prerelease?: string) => {
        const op = operator ?? "";
        if (prerelease === undefined) {
          return op === "<=" ? `${op}${core}-${lastHotfix}` : `${op}${core}-zz`;
        }
        if (prerelease === "0") {
          return `${op}${core}-0`;
        }
        return numericHotfix.test(prerelease)
          ? `${op}${core}-zzhotfix.${prerelease}`
          : `${op}${core}-${prerelease}`;
      },
    );
    orderedRanges.set(range, ordered);
  }
  return ordered;
}

function unknown(summary: string): VersionAdvisoryResult {
  return { grade: "unknown", version: null, advisories: [], summary };
}
