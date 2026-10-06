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
  `authorization`), after camelCase and `_`/`.` are normalized to dashes, so
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
  (`secretref-managed`, `secretref-env:NAME`) are exempt anywhere. Numbers are
  reported under password, secret, token, key, and PIN names.
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

Relevant file-backed roots include:

- `<workspace>/skills`
- `<workspace>/.agents/skills`
- `~/.agents/skills`
- `<state-dir>/skills`
- directories named by `skills.load.extraDirs`

Each skill is a directory with `SKILL.md`. Symlink and precedence rules mean a
scanner must report the resolved root and avoid following arbitrary filesystem
links outside the discovered roots.

Sources:

- <https://docs.openclaw.ai/skills>
- <https://docs.openclaw.ai/tools/skills-config>
- <https://docs.openclaw.ai/cli/skills>

## Spend and usage

No reviewed primary source establishes one universal local OpenClaw spend
ledger. v0.1 therefore reports `unknown` unless a documented local source is
found and parsed. It must not infer cost from provider keys or make a network
request.
