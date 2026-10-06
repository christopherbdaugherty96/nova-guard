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

// The output is split into words of letters, digits (any script), and version
// punctuation. Any word that looks like a calendar version must parse strictly
// as a whole, so a real version glued to other text, written in other digits,
// or truncated can never be skipped in favour of another date in the output.
const wordPattern = /[\p{L}\p{N}\p{M}_.+-]+/gu;
const looksLikeVersion = /(?<!\p{Nd})\p{Nd}{4,}\.\p{Nd}/u;
/** Version output is one short line; anything far larger is not trusted. */
const maxOutputLength = 4096;
const strictVersion =
  /^(?:[A-Za-z][A-Za-z0-9]*-)?v?(\d{4})\.(\d{1,2})\.(\d{1,2})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
// CSI sequences (colors, cursor and line control) and OSC sequences.
const terminalEscape = /\x1b\[[0-?]*[ -\/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g;

type Core = [number, number, number];

export function assessOpenClawVersion(
  versionOutput: string | undefined,
): VersionAdvisoryResult {
  if (versionOutput === undefined || versionOutput.trim().length === 0) {
    return unknown("OpenClaw version could not be read.");
  }
  if (versionOutput.length > maxOutputLength) {
    return unknown("OpenClaw version output was too long to trust.");
  }

  const found = new Map<string, { core: Core; prerelease: boolean }>();
  const text = versionOutput.replace(terminalEscape, "");
  for (const [word] of text.matchAll(wordPattern)) {
    if (!looksLikeVersion.test(word)) {
      continue;
    }
    const match = strictVersion.exec(trimTrailingDots(word));
    if (!match) {
      return unknown("OpenClaw version output was not recognized.");
    }
    const [, year, month, day, prerelease] = match;
    const core: Core = [Number(year), Number(month), Number(day)];
    if (!isCalendarDate(core)) {
      return unknown("OpenClaw version output was not recognized.");
    }
    const label = `${core.join(".")}${prerelease ? `-${prerelease}` : ""}`;
    found.set(label, { core, prerelease: prerelease !== undefined });
  }

  if (found.size === 0) {
    return unknown("OpenClaw version output was not recognized.");
  }
  if (found.size > 1) {
    return unknown("OpenClaw version output contained conflicting versions.");
  }

  const [[version, { core, prerelease }]] = found;
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

function isCalendarDate([year, month, day]: Core): boolean {
  const date = new Date(Date.UTC(year, month - 1, day));
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

function trimTrailingDots(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === ".") {
    end -= 1;
  }
  return value.slice(0, end);
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
