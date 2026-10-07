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
redacted further than the checks: home directories print as `~`, a state
directory outside home as `<state>`, a config directory outside both as
`<config>` (a home of `/` is not used), agent ids in paths as `*`, risky skills by
the kind of root they were found in, a per-card number, file kind, rule, and
line only (never a configured path, skill name, or file name), and configured
gateway values are never printed. Spend is
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

## Running it

```text
npm ci && npm run build
node dist/cli.js check        # or: npx nova-guard check, once published
```

`nova-guard check` finds OpenClaw the way OpenClaw does (`OPENCLAW_HOME`,
`OPENCLAW_STATE_DIR`, `OPENCLAW_CONFIG_PATH`, `OPENCLAW_WORKSPACE_DIR`,
`OPENCLAW_PROFILE`, `OPENCLAW_INCLUDE_ROOTS`, else `~/.openclaw`), reads the
config and its `$include` files, runs `openclaw --version` (no shell, only
from absolute `PATH` entries and with only those in its `PATH`, at most 10
seconds, then killed with anything it started), runs the four checks, and prints the report card. nova-guard makes no
network calls and writes nothing; `openclaw --version` is OpenClaw's own code.
Anything it cannot verify (no OpenClaw state directory, a config or include
OpenClaw would reject in the fields the checks read, no version output) is
reported as unknown, never as pass. It does not reimplement OpenClaw's whole
config schema, so an invalid value elsewhere is not detected. The gateway grade reads the config only: an omitted `gateway.bind` is
unknown unless nova-guard itself runs in a container, and a `--bind` flag
passed to the gateway (as OpenClaw's Docker setup does) is not visible to it.
The exit code is 0 whenever a card is printed and 2 for a usage error.

## Status

Early: the four v0.1 checks and the report card run locally; spend is not
checked yet. `--profile` is not supported: OpenClaw's `--profile` sets
`OPENCLAW_STATE_DIR` and `OPENCLAW_CONFIG_PATH`, so set those two (as
`~/.openclaw-<profile>` and its `openclaw.json`) to scan a profile.

## License

[MIT](LICENSE)
