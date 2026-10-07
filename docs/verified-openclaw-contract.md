# Verified OpenClaw contract

Verified on 2026-10-05 against OpenClaw's official documentation, source
repository, and GitHub's reviewed advisory database. These are discovery
inputs, not claims that every historical or customized installation follows
the defaults.

## Config and state

- The explicit config path is `OPENCLAW_CONFIG_PATH`.
- Otherwise config resolves from `OPENCLAW_STATE_DIR/openclaw.json`, normally
  `~/.openclaw/openclaw.json`.
- The config accepts JSON5.
- The default state directory also contains the global `.env`, credentials,
  managed skills, workspaces, and agent state. Alternate profiles and explicit
  environment overrides must be respected.

Sources:

- <https://docs.openclaw.ai/configuration>
- <https://docs.openclaw.ai/help/environment>
- <https://github.com/openclaw/openclaw/blob/main/src/config/paths.ts>

## Paths, config loading, and the check command

Verified against OpenClaw source at `b8324c64acf5979602711163cb4b5c01ea557388`
(`src/config/paths.ts`, `src/config/state-dir.ts`, `src/infra/home-dir.ts`,
`packages/normalization-core/src/home-dir.ts`, `src/cli/profile.ts`,
`src/config/includes.ts`, `src/infra/deep-merge.ts`,
`src/infra/container-environment.ts`).

- Home: `OPENCLAW_HOME` (a leading `~` means the OS home), else `HOME`, else
  `USERPROFILE`, else the OS home directory; blank, `undefined`, and `null`
  count as unset. OpenClaw resolves a path still relative after `~` expansion
  (home, `OPENCLAW_STATE_DIR`, `OPENCLAW_CONFIG_PATH`, `OPENCLAW_WORKSPACE_DIR`,
  which gets no `~` expansion, and include roots) against its own working
  directory, which nova-guard cannot know: such paths are not trusted, and what
  depends on them is unknown (relative include roots are dropped). An absolute
  `OPENCLAW_HOME` is used even when the OS home is unset or relative; only the
  personal skills root under the OS home (`~/.agents/skills`) is then unknown.
- State: `OPENCLAW_STATE_DIR` (leading `~` expanded to OpenClaw's home), else
  `<home>/.openclaw`. Config: `OPENCLAW_CONFIG_PATH`, else
  `<state>/openclaw.json`. The CLI's `--profile` sets these variables; a
  `--profile` flag for nova-guard is not supported yet.
- Default workspace: `OPENCLAW_WORKSPACE_DIR`, else `<state>/workspace` when
  `OPENCLAW_STATE_DIR` is set, else `<home>/.openclaw-<profile>/workspace` for
  a non-default `OPENCLAW_PROFILE`, else `<home>/.openclaw/workspace`.
- `$include`: a string or array of strings; resolved against the including
  file; confined lexically and after symlinks to the config directory or an
  `OPENCLAW_INCLUDE_ROOTS` root; at most ten deep; cycles rejected; several
  includes deep-merge in order (arrays concatenate, objects merge, other values
  replace) and sibling keys merge over them (included content must then be an
  object). Any rejection makes OpenClaw refuse the config, so the check command
  treats the whole config as unreadable. Prototype keys are dropped. More than
  256 include loads is also treated as unreadable.
- Container detection (for the gateway's default bind): Fly.io machine
  variables, `/.dockerenv`, `/run/.containerenv`, `/var/run/.containerenv`, or
  a container cgroup for PID 1, evaluated on the host where nova-guard runs.
  A detected container settles an omitted bind (`auto`); outside one the
  gateway may still run in a container (OpenClaw's `docker-compose.yml`
  mounts the host's `~/.openclaw` and passes `--bind lan`), so an omitted bind
  is unknown. Command-line `--bind` flags are never visible to a config scan.
- The merged config must be an object, and `gateway`, `gateway.auth`,
  `gateway.tailscale`, `agents`, `skills`, and `skills.load` must be objects
  when present; `agents.list` an array of objects and `agents.entries` values
  objects, with string `id`, `workspace`, and `agentDir`;
  `agents.defaults.workspace` a string; `skills.load.extraDirs` and
  `allowSymlinkTargets` arrays of strings; and every gateway field the gateway
  check reads must be valid: `bind` one of `auto`, `loopback`, `lan`, `tailnet`,
  `custom`; `customBindHost` a string; `trustedProxies` an array of strings;
  `tailscale.mode` one of `off`, `serve`, `funnel`; `auth.mode` one of `none`,
  `token`, `password`, `trusted-proxy`; `auth.token`/`auth.password` a string
  or a SecretRef with exactly `source` (`env`, `file`, `exec`, `store`),
  `provider` (`/^[a-z][a-z0-9_-]{0,63}$/`), and an `id` valid for its source
  (src/secrets/ref-contract.ts); `auth.trustedProxy.userHeader` a string.
  Otherwise OpenClaw refuses it and so does the check command.
- If the resolved state directory does not exist, every check still runs (an
  explicit `OPENCLAW_CONFIG_PATH`, `~/.agents/skills`, `OPENCLAW_WORKSPACE_DIR`,
  and `~/.config/openclaw/gateway.env` are still read) and keeps its findings,
  but a check that would pass is reported unknown.
  Hardlinked include files are refused, as OpenClaw's guarded open does, and
  include merges that would copy more than 2,000,000 entries are treated as
  unreadable. Outside include merges only `__proto__` is dropped.
- Gateway credentials count as available only when `OPENCLAW_GATEWAY_TOKEN` or
  `OPENCLAW_GATEWAY_PASSWORD` is set in one of the `.env` files OpenClaw loads
  (`~/.config/openclaw/gateway.env` only with the default state directory);
  only presence is checked, never the value.
- An invalid `OPENCLAW_PROFILE` makes OpenClaw refuse to resolve the default
  workspace, so risky skills are then unknown.
- `openclaw --version` is run without a shell from the first absolute `PATH`
  entry holding an executable `openclaw` (empty or relative entries would mean
  the current directory), and its environment's `PATH` keeps only absolute
  entries (npm's bin runs `#!/usr/bin/env node`). Standard output is capped at
  4 KiB, with a 10-second hard timeout. On POSIX it runs in its own process
  group, which is killed whenever the probe ends, so nothing it started
  survives. On Windows a timed-out probe's tree is ended with
  `%SystemRoot%\System32\taskkill.exe /T /F` (absolute path, no shell) while
  the probe still runs, before anything else; after a clean exit nothing is
  killed, since its PID may already be reused. On Windows, npm's `openclaw.cmd` shim (global, or a project's
  `node_modules/.bin` shim pointing at its sibling package) is resolved to its
  script, which is run with Node.

## Gateway

- `gateway.bind` accepts `auto`, `loopback`, `lan`, `tailnet`, or `custom`.
- On bare-metal and VM hosts, `loopback` is the default. In a detected
  container, an omitted bind defaults to `auto`, which resolves to `0.0.0.0`
  for port-forwarding compatibility.
- `lan` binds to `0.0.0.0`.
- `gateway.tailscale.mode: "serve"` exposes the gateway to the tailnet through
  Tailscale Serve even though the process stays bound to loopback.
- `gateway.tailscale.mode: "funnel"` exposes the gateway to the public internet
  through Tailscale Funnel while the process stays bound to loopback. OpenClaw
  requires password authentication for this mode and refuses to start without
  it.
- Non-loopback exposure requires a valid token, password, or trusted-proxy
  authentication path and should be constrained by a firewall.
- The default gateway port is `18789`; command-line and environment overrides
  can change it.

Sources:

- <https://docs.openclaw.ai/gateway/config-gateway>
- <https://docs.openclaw.ai/gateway/security/network-exposure>
- <https://docs.openclaw.ai/gateway/tailscale>
- <https://docs.openclaw.ai/help/faq/config-basics>

## Version

- `openclaw --version` is a documented local version probe.
- The vulnerability list is bundled and dated in
  `src/data/openclaw-advisories.ts`. It holds every GitHub-reviewed advisory
  for the `openclaw`, `clawdbot`, and `moltbot` npm packages, as served by
  npm's bulk advisory endpoint (the data `npm audit` uses). For example,
  CVE-2026-25253 (GHSA-g8p2-7wf7-98mq) affects `clawdbot <=2026.1.28`, and
  GHSA-fhvm-j76f-qmjv affects `openclaw <2026.2.1`. A scan never fetches it;
  maintainers regenerate it with `npm run update-advisories`.
- Ranges are evaluated with npm's `semver`, with prereleases always included.
  The version line does not name its package, so every package's advisories
  apply to the shared calendar version line. A match with any critical or high
  advisory grades `critical`; only moderate or low grades `warning`.
- OpenClaw publishes numeric hotfixes (`X-1`, `X-2`) after release `X`, but
  SemVer orders them before `X`. Versions and range bounds are therefore
  mapped to publication order (`X-beta.1` < `X` < `X-1` < `X-2` < next release)
  before matching. Every non-hotfix prerelease is placed in its own namespace,
  so no prerelease name can collide with the ordering markers. Two bounds stay conservative: `<=X` also covers `X`'s
  hotfixes (the advisory does not say a hotfix carried the fix), and a `-0`
  bound keeps SemVer's meaning of every prerelease of `X` (no `X-0` hotfix has
  been published). An installed `-0` version (clawdbot's `v2026.1.24` tag
  carries `2026.1.24-0`) is graded as both `X`'s lowest prerelease and `X`.
  Against every published version this drops only matches
  where a hotfix follows the release that fixed the issue, and no grade falls.
- Only plain comparator sets (for example `>=2026.1.5 <=2026.5.3-1`) are
  supported. Hyphen ranges, `||`, `^`, `~`, and x-ranges would be expanded by
  `semver` after the mapping, so the generator refuses them and the scanner
  reports `unknown` if bundled data ever contains one.
  The generator reads versions and advisories from the registry over HTTP
  (no child processes, so it runs the same on Windows). It refuses to write a
  bundle with an empty package list, an unknown severity, or a range `semver`
  cannot parse, and it refuses any refresh that would drop an existing
  advisory unless run with `--allow-removals`, which lists every removal.
- `openclaw --version` prints one line on stdout. Older releases print the
  bare version (verified at `v2026.1.24`, published as `clawdbot`
  `2026.1.24-0`, and at `v2026.1.29` and `v2026.1.30`). Current `main` prints `OpenClaw <version>` or
  `OpenClaw <version> (<7-hex commit>)` (the CLI truncates the commit to seven
  lowercase hex digits); on failure they write to stderr and
  exit 1. The scanner grades only output whose entire trimmed text, after
  stripping terminal escapes, is one of these shapes. Anything else, including
  other date-like text, is `unknown`. Output over 4 KiB of UTF-8 (measured
  before escapes are stripped) is `unknown`.
- Versions are `YYYY.M.N`. `N` is usually the day, but Extended Stable releases
  use it as a maintenance counter (official tags `v2026.6.33` to `v2026.8.35`),
  so the scanner enforces only month 1-12 and a non-zero `N`. A component
  too large for `semver` to compare is `unknown`.
- Numbers must be SemVer-canonical (no leading zeros in the version or in
  numeric prerelease identifiers), so `2026.01.029` or `2026.1.30-01` is
  `unknown`.

Sources:

- <https://github.com/openclaw/openclaw/blob/main/docs/platforms/windows.md>
- <https://github.com/openclaw/openclaw/blob/main/src/entry.version-fast-path.ts>
- <https://github.com/openclaw/openclaw/blob/v2026.1.24/src/cli/program/help.ts>
- <https://github.com/openclaw/openclaw/blob/main/src/infra/git-commit.ts>
- <https://semver.org/spec/v2.0.0.html>
- <https://github.com/advisories/GHSA-g8p2-7wf7-98mq>
- <https://github.com/advisories/GHSA-fhvm-j76f-qmjv>
- <https://docs.npmjs.com/cli/commands/npm-audit>

## Secrets

- OpenClaw may read provider credentials from the gateway process or service
  environment, the state-directory `.env`, config `env.vars`, supported
  SecretRefs, and credential files.
- File scanning can identify likely plaintext assignments and locations but
  cannot prove which process-only secrets exist.
- Reports must emit the file path and key name only, never the value.

Verified against OpenClaw `main` at `282f796d` (2026-10-05), whose own
`openclaw secrets audit` (`src/secrets/audit.ts`) scans the same files. The
scanner reads, never writes:

- `.env` files: `<stateDir>/.env`, `<configDir>/.env`, and
  `~/.config/openclaw/gateway.env` (`src/secrets/storage-scan.ts`,
  `src/infra/dotenv-global-core.ts`). OpenClaw parses them with `dotenv`
  `parse()`; the scanner uses a port of that function (dotenv 18.0.3,
  BSD-2-Clause) so it loads no `child_process` code, and a test checks the
  port against `dotenv` itself. That covers multiline quoted values, CR line
  endings, `KEY: value`, and dotted or dashed keys. A secret-like `KEY` with a
  non-empty value is reported as `file:line KEY`; the last assignment wins.
- `openclaw.json` (JSON5): any string under a secret-like key that is a
  literal, not a `${VAR}` reference or SecretRef object, is reported by dotted
  path. This covers `env.vars.*` and `env.*`
  (`src/config/config-env-values.ts`). A non-empty `${VAR:-fallback}` is a
  plaintext secret when either the key or `VAR` is secret-like, because the
  fallback is config text (docs: config-secrets-env). `$${VAR}` is an escaped
  literal, and only upper-case names are substituted.
- Files pulled in by `$include` (a string or array of strings anywhere in a
  config document) are scanned the same way, following OpenClaw's rules
  (`src/config/includes.ts`, `src/config/includes-scan.ts`): paths resolve
  against the including file, must stay inside the config directory or an
  `OPENCLAW_INCLUDE_ROOTS` root, and nest at most 10 deep. Included content
  sits at its include site, so it inherits that site's logical path and
  governing key (an included bare string under `token` is a token); findings
  name the included file and the logical path. A file included at two sites
  is checked under each. A visit is redone only when a shallower include
  reaches it, so cycles end and coverage does not depend on traversal order.
  Anything OpenClaw would refuse or cannot load (an include outside the roots,
  a malformed `$include` value, a missing, unreadable, unparseable, or
  too-deep target) makes the result `unknown`; refused targets are never read.
  The containment check is lexical; OpenClaw's extra symlink-realpath check is
  not repeated, so an in-root symlink may be scanned even if OpenClaw would
  refuse it. Include file paths are reported as locations.
- `<stateDir>/agents/*/agent/models.json` (always including `main`):
  `providers.*.apiKey` unless it is one of OpenClaw's non-secret markers
  (`src/agents/model-auth-markers.ts`), and `providers.*.headers.*` whose name
  is sensitive (`src/secrets/model-provider-header-policy.ts`). If the
  `agents` directory exists but cannot be listed, the result is `unknown`,
  because other agents' files could not be checked.
- Secret-like names use OpenClaw's own conservative fragments (`api-key`,
  `apikey`, `token`, `secret`, `password`, `credential`, plus
  `authorization`), plus credential fields from OpenClaw's SecretRef
  credential surface whose names carry no such fragment (`encryptKey`,
  `serviceAccount`, `authTag`, `passphrase`), after camelCase and `_`/`.` are normalized to dashes, so
  `privateKey`, `accessKey`, and `apiKeys` match. Array items take the name of
  the enclosing key. Names ending in `file`, `path`, `env`, `ref`, `url`, or
  `uri` point elsewhere and are skipped. Counts such as `maxTokens` are not
  credentials.
- A value is exempt only when it is made entirely of references (optionally
  after `Bearer`, `Basic`, or `Token`); literal text beside a reference is
  still plaintext. Upper-case env-var-name markers such as `OPENAI_API_KEY`
  are exempt only in `apiKey` fields.
- Reported paths are schema-safe. A segment is shown only if it is an array
  position (tracked structurally, so a digit-only map key is still `*`) or one of nova-guard's trusted OpenClaw schema field names (config
  sections, fixed channel ids, and secret field names, all public
  vocabulary). Every user-controlled map key (provider ids, header names,
  `env.vars` names, token map keys) is reported as `*`, so findings read
  `models.providers.*.apiKey`, `models.providers.*.headers.*`, or
  `gateway.tokens.*.token`, never a name that could itself be sensitive. A
  field name missing from the list also becomes `*`, which costs detail, never
  secrecy. A `.env` variable name is the key name itself and is shown unless
  it looks like a credential (a 12-character run mixing letters and digits, or
  over 64 characters), in which case it is `*`.
- Every `.env` assignment with a value is reported, including one a later
  line overrides, because the earlier secret is still on disk. OpenClaw's
  `apiKey` placeholders exempt only `apiKey` fields; SecretRef markers
  (`secretref-managed`, and `secretref-env:NAME` when nothing follows the
  variable name) are exempt anywhere. Numbers are
  reported under password, secret, token, key, and PIN names.
- Include expansion stops after 256 file visits (one file included under
  many keys, many levels deep, otherwise grows exponentially); files not
  scanned past that limit are reported as `unknown` by path.
- Files over 1 MiB, non-regular files (a FIFO is never opened, so it cannot
  block), unreadable files, and unparseable JSON are reported as `unknown` by
  path only; parser messages, which can quote file bytes, are never surfaced.
  Findings never include values, fragments, lengths, or hashes.
- Not scanned in v0.1: auth-profile SQLite stores, the live process or service
  environment, and archived legacy auth files. Known limits: a secret in a
  duplicate JSON5 key that a later key overrides, or inside a comment, is not
  seen (JSON5 keeps the last value; `.env` duplicates are all reported); a
  secret nested in an object under a secret name (`token: { value: … }`), a
  literal under an indirect name such as `tokenEnv`, and secret-bearing URLs
  such as webhook URLs are not reported; `apiKey` values starting with
  `oauth:` are treated as OpenClaw's OAuth marker.

Sources:

- <https://docs.openclaw.ai/help/environment>
- <https://docs.openclaw.ai/gateway/config-secrets-env>
- <https://docs.openclaw.ai/setup>
- <https://github.com/openclaw/openclaw/blob/main/src/secrets/audit.ts>
- <https://github.com/openclaw/openclaw/blob/main/src/secrets/storage-scan.ts>
- <https://github.com/openclaw/openclaw/blob/main/src/agents/model-auth-markers.ts>

## Skills

Verified against OpenClaw source at `b8324c64acf5979602711163cb4b5c01ea557388`
(`src/skills/loading/*`, `src/skills/security/scanner.ts`,
`src/security/audit.deep.runtime.ts`, `src/agents/agent-scope-config.ts`).

Skill roots (`workspace-skill-sources.ts`), all scanned:

- `<workspace>/skills` and `<workspace>/.agents/skills` for every agent
  workspace. A workspace is the agent entry's `workspace`, else
  `<agents.defaults.workspace>/<agentId>`, else `<stateDir>/workspace-<agentId>`;
  the default agent may use `agents.defaults.workspace` itself or the default
  workspace (`OPENCLAW_WORKSPACE_DIR`, else `<stateDir>/workspace`). Rosters are
  `agents.entries` (keys are ids) or `agents.list` (entries carry `id`); with no
  roster the agent is `main`. Every candidate is scanned.
- `<stateDir>/skills` (managed) and `~/.agents/skills` (personal). OpenClaw
  loads the personal root only with the default state directory, from the OS
  home; nova-guard always scans it, under both the OS home and OpenClaw's
  effective home (`OPENCLAW_HOME`), which is the home `~` in config expands to.
- `skills.load.extraDirs`.
- Each agent's `<agentDir>/workshop-skills`, where `agentDir` is the entry's
  `agentDir` or `<stateDir>/agents/<agentId>/agent`; every existing
  `<stateDir>/agents/*/agent` is included too. Workshop roots are containers:
  their own `SKILL.md` never hides the skills inside them. Any object in
  `agents.list` is an agent; one without an `id` is `main`.
- Not scanned in v0.1: bundled skills (OpenClaw's audit skips them too) and
  plugin-provided skills (OpenClaw audits those as plugin code).

A skill is a directory with `SKILL.md`. A root can itself be a skill, may hold
a nested `skills/` directory, and may group skills up to six levels deep (up to
eight levels below the root in all; nova-guard looks nine deep);
dot-entries and `node_modules` are skipped. Managed and personal roots follow
symlinks anywhere; other roots follow a symlink only when its real target stays
inside the root or inside `skills.load.allowSymlinkTargets` (workshop roots
allow no targets). A skill reached by two routes is scanned once.

Rules: OpenClaw's installed-skill code-safety scan (`skills.code_safety`, run
by `openclaw security audit --deep`), ported unchanged with attribution in
`src/checks/skill-scan-rules.ts`:

- Script files (`.js .ts .mjs .cjs .mts .cts .jsx .tsx`) and `SKILL.md`:
  `dangerous-exec` (child_process calls, with OpenClaw's import-provenance
  rules), `dynamic-code-execution`, `crypto-mining`, `env-harvesting`
  (critical); `suspicious-network`, `potential-exfiltration`,
  `obfuscated-code` (warn).
- `SKILL.md` text only: `literal-secret`, `shell-pipe-to-shell`,
  `secret-exfiltration` (critical); `destructive-delete`, `unsafe-permissions`
  (warn).
- At most 32 hits per rule per file (then one `<rule>-truncated` hit), 500
  script files per skill, 100,000 directory entries per skill; symlinks inside
  a skill are not followed. OpenClaw matches `child_process` aliases with one
  regular expression per alias per line; nova-guard finds the same calls in
  one pass, so a file with thousands of aliases cannot stall the scan.
- A file reached through several skills (nested skills, symlinks into the same
  tree) is read and scanned once, and roots resolving to the same directory are
  walked once. Discovery visits at most 20,000 directories per root and 200,000
  in all, and resolves at most 20,000 symlinks in all (each also charged by its target's
  depth squared, so links into very deep trees exhaust the budget sooner) and
  spends at most 30 seconds resolving them, failed resolutions included.
  Walks run on resolved real paths, so a root behind a long symlink chain does
  not slow every call; reports keep the discovered paths. The whole check stops
  after 120 seconds and reports the rest as `unknown` (`time-limit`), never
  `pass`. OpenClaw's `literal-secret` pattern, kept unchanged for parity, can
  take tens of seconds on a hostile 256,000-byte `SKILL.md`; such a scan
  cannot be interrupted, so the worst case can overrun the limit by that much; script-file walks stop after 1,000,000 directory entries across all
  skills; whatever is left is unknown.

Reports give the skill directory, file, line, rule id, and severity only:
never the matched text (OpenClaw shows it as evidence) and never the skill's
`name`. Grades: `critical` if any critical rule matches, `warning` if only warn
rules match, `unknown` if anything could not be evaluated, else `pass`.
Unknown, where OpenClaw silently skips or fails: a `SKILL.md` over 256,000
bytes or a script file over 1 MiB, more than 500 script files, an unreadable
root, directory, or file, a non-regular `SKILL.md`, any scan limit or the time
limit being reached, a relative configured path
(OpenClaw resolves it against its own working directory), and an unreadable
config. Missing roots are not unknown.

Sources:

- <https://docs.openclaw.ai/skills>
- <https://docs.openclaw.ai/tools/skills-config>
- <https://docs.openclaw.ai/gateway/security/audit-checks>
- <https://github.com/openclaw/openclaw/blob/b8324c64acf5979602711163cb4b5c01ea557388/src/skills/security/scanner.ts>
- <https://github.com/openclaw/openclaw/blob/b8324c64acf5979602711163cb4b5c01ea557388/src/skills/loading/workspace-skill-sources.ts>
- <https://github.com/openclaw/openclaw/blob/b8324c64acf5979602711163cb4b5c01ea557388/src/skills/loading/skill-root-discovery.ts>

## Spend and usage

No reviewed primary source establishes one universal local OpenClaw spend
ledger. v0.1 therefore reports `unknown` unless a documented local source is
found and parsed. It must not infer cost from provider keys or make a network
request.
