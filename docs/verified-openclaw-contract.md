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
- GitHub's reviewed advisory for CVE-2026-25253 lists `clawdbot <= 2026.1.28`
  as affected and `2026.1.29` as patched.
- The vulnerability list will be bundled and dated. A local scan does not need
  live advisory access.
- The exact `openclaw --version` output format is not documented, so the
  scanner extracts a single `YYYY.M.D[-prerelease]` token and reports
  `unknown` when none, or more than one distinct version, is present.

Sources:

- <https://github.com/openclaw/openclaw/blob/main/docs/platforms/windows.md>
- <https://github.com/advisories/GHSA-g8p2-7wf7-98mq>

## Secrets

- OpenClaw may read provider credentials from the gateway process or service
  environment, the state-directory `.env`, config `env.vars`, supported
  SecretRefs, and credential files.
- File scanning can identify likely plaintext assignments and locations but
  cannot prove which process-only secrets exist.
- Reports must emit the file path and key name only, never the value.

Sources:

- <https://docs.openclaw.ai/help/environment>
- <https://docs.openclaw.ai/gateway/config-secrets-env>
- <https://docs.openclaw.ai/setup>

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
