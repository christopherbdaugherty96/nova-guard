# nova-guard

`nova-guard check` is a free, open-source, read-only local scanner for people
running self-hosted AI agents. OpenClaw is the first supported target.

> Safer, not safe. A clean report is not a guarantee that an agent, host,
> plugin, skill, model, or network is secure.

## Product contract

- Local-only by default.
- No telemetry.
- Read-only: checks must not repair, reconfigure, quarantine, or delete.
- No network calls during a scan. A future version lookup may be offered only
  as an explicit, clearly labelled, disableable option.
- Secret values are never printed or included in reports.

## v0.1 target

```text
npx nova-guard check
```

The command will produce a one-page, printable report card with a grade,
redacted findings, and a plain-language fix for each finding. Its first checks
cover OpenClaw gateway exposure and authentication, installed version against
a bundled vulnerability list, plaintext secret locations, risky skill
patterns, and locally available recent usage or spend. When spend cannot be
established from a documented local source, the report says `unknown`.

The report card (`renderReportCard`) is a deterministic presentation layer
over the check results: an overall grade (the worst check: critical, warning,
unknown, pass), findings most severe first, each with a plain-language fix, and
an explicit "Could not be checked" section. It fits one printed page (80
columns, 66 lines; the waitlist link is printed whole). For sharing, it is
redacted further than the checks: the home directory prints as `~`, agent ids
in paths as `*`, risky skills by root, file kind, rule, and line only (never a
skill or file name), and configured gateway values are never printed. Spend is
shown as not checked until a documented local source exists.

Implementation will land as small reviewed pull requests. Each scanner check
must begin with a regression test that demonstrably fails before the fix.

## Verified OpenClaw assumptions

The scanner contract is based on current OpenClaw primary sources. The exact
paths, settings, precedence, and version facts are recorded in
[docs/verified-openclaw-contract.md](docs/verified-openclaw-contract.md).

## 30-day market test

At day 30, the product will be judged on three signals:

1. GitHub stars.
2. Waitlist sign-ups.
3. Report cards users deliberately share.

Missing two of the three targets means the experiment did not validate enough
demand and NovaLIS resumes at its provider-neutral Data-Out/custody gate. The
numeric targets will be fixed before public launch rather than revised after
results arrive.

[Tell me when the proxy ships](https://github.com/christopherbdaugherty96/nova-guard/issues/new?template=proxy-waitlist.yml)

## Status

Foundation only. The scanner is not usable yet.

## License

[MIT](LICENSE)
