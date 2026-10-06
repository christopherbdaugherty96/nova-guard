import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import dotenv from "dotenv";

import {
  assessPlaintextSecrets,
  nodeSecretFileReader,
  parseDotEnv,
  type PlaintextSecretsResult,
  type SecretFileReader,
} from "../src/checks/plaintext-secrets.js";

const home = path.join(path.sep, "home", "chris");
const stateDir = path.join(home, ".openclaw");
const configPath = path.join(stateDir, "openclaw.json");
const stateEnv = path.join(stateDir, ".env");
const gatewayEnv = path.join(home, ".config", "openclaw", "gateway.env");
const mainModels = path.join(stateDir, "agents", "main", "agent", "models.json");
const workModels = path.join(stateDir, "agents", "work", "agent", "models.json");
const locations = { stateDir, configPath, homeDir: home };

// Distinctive values so any leaked fragment is detectable.
const SECRET_A = "zq9XvB7pLm2Wk4Rt";
const SECRET_B = "Hy6TnQ3sDf8Jc1Vb";
const SECRET_C = "Wp4Ks9Ge2Ux7Nm5A";
const SECRET_D = "Rb8Ct1Lz6Mv3Qj0E";
const SECRETS = [SECRET_A, SECRET_B, SECRET_C, SECRET_D];

function fakeReader(
  files: Record<string, string | "UNREADABLE">,
  directories: Record<string, string[] | "unreadable"> = {},
): SecretFileReader {
  return {
    readText(file) {
      const content = files[file];
      if (content === undefined) return { status: "missing" };
      if (content === "UNREADABLE") return { status: "unreadable" };
      return { status: "ok", text: content };
    },
    listDirectories(dir) {
      return directories[dir] ?? [];
    },
  };
}

/** No value, and no 5-character window of any value, may appear in a result. */
function assertNoLeak(result: PlaintextSecretsResult, secrets = SECRETS) {
  const serialized = JSON.stringify(result);
  for (const secret of secrets) {
    for (let i = 0; i + 5 <= secret.length; i += 1) {
      const fragment = secret.slice(i, i + 5);
      assert.ok(!serialized.includes(fragment), `result leaks fragment ${fragment}`);
    }
  }
}

function keys(result: PlaintextSecretsResult) {
  return result.findings.map((finding) => `${finding.kind} ${finding.file}${finding.line ? `:${finding.line}` : ""} ${finding.key}`);
}

test("nothing to scan passes with no findings", () => {
  const result = assessPlaintextSecrets(locations, fakeReader({}));
  assert.equal(result.grade, "pass");
  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.unreadable, []);
});

test("secret-like .env assignments are reported by file, line, and key only", () => {
  const result = assessPlaintextSecrets(
    locations,
    fakeReader({
      [stateEnv]: [
        "# comment",
        `OPENAI_API_KEY=${SECRET_A}`,
        "LOG_LEVEL=debug",
        `export DISCORD_BOT_TOKEN="${SECRET_B}"`,
        "EMPTY_API_KEY=",
        "QUOTED_EMPTY_TOKEN=''",
        `GATEWAY_PASSWORD = '${SECRET_C}'`,
        `not an assignment ${SECRET_D}`,
      ].join("\r\n"),
      [gatewayEnv]: `ANTHROPIC_API_KEY=${SECRET_D}\n`,
    }),
  );
  assert.equal(result.grade, "warning");
  assert.deepEqual(keys(result), [
    `plaintext ${stateEnv}:2 OPENAI_API_KEY`,
    `plaintext ${stateEnv}:4 DISCORD_BOT_TOKEN`,
    `plaintext ${stateEnv}:7 GATEWAY_PASSWORD`,
    `plaintext ${gatewayEnv}:1 ANTHROPIC_API_KEY`,
  ]);
  assertNoLeak(result);
});

test("a .env next to a non-default config path is scanned once", () => {
  const otherConfig = path.join(home, "cfg", "openclaw.json");
  const otherEnv = path.join(home, "cfg", ".env");
  const result = assessPlaintextSecrets(
    { ...locations, configPath: otherConfig },
    fakeReader({ [otherEnv]: `SLACK_TOKEN=${SECRET_A}`, [stateEnv]: `SLACK_TOKEN=${SECRET_A}` }),
  );
  assert.deepEqual(keys(result), [
    `plaintext ${stateEnv}:1 SLACK_TOKEN`,
    `plaintext ${otherEnv}:1 SLACK_TOKEN`,
  ]);
  assertNoLeak(result);
});

test("literal config secrets are reported by JSON path, and references are not", () => {
  const config = `{
    // JSON5 comments and trailing commas are accepted.
    gateway: {
      auth: { mode: "token", token: "${SECRET_A}", password: "\${OPENCLAW_GATEWAY_PASSWORD}" },
    },
    models: {
      providers: {
        openai: { apiKey: { source: "env", provider: "default", id: "OPENAI_API_KEY" } },
        local: { apiKey: "ollama-local", baseUrl: "http://127.0.0.1:11434" },
        custom: { apiKey: "${SECRET_B}", headers: { Authorization: "Bearer \${CUSTOM_TOKEN}" } },
      },
    },
    channels: { discord: { token: "${SECRET_C}", tokenFile: "/run/secrets/discord" } },
    agents: { defaults: { maxTokens: 4096, model: "gpt" } },
  }`;
  const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.equal(result.grade, "warning");
  assert.deepEqual(keys(result), [
    `plaintext ${configPath} gateway.auth.token`,
    `plaintext ${configPath} models.providers.custom.apiKey`,
    `plaintext ${configPath} channels.discord.token`,
  ]);
  assertNoLeak(result);
});

test("config env vars with secret-like names are reported", () => {
  const config = JSON.stringify({
    env: {
      vars: { OPENAI_API_KEY: SECRET_A, HTTP_PROXY: "http://proxy:3128" },
      GITHUB_TOKEN: SECRET_B,
      shellEnv: { enabled: true },
    },
  });
  const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.deepEqual(keys(result), [
    `plaintext ${configPath} env.vars.OPENAI_API_KEY`,
    `plaintext ${configPath} env.GITHUB_TOKEN`,
  ]);
  assertNoLeak(result);
});

test("non-empty ${VAR:-fallback} defaults are plaintext secrets (issue #2c)", () => {
  const config = JSON.stringify({
    gateway: {
      auth: { mode: "token", token: `\${OPENCLAW_GATEWAY_TOKEN:-${SECRET_A}}` },
      port: "${OPENCLAW_GATEWAY_PORT:-18789}",
    },
    tools: { search: { endpoint: `https://api.example/?key=\${SEARCH_API_KEY:-${SECRET_B}}` } },
    channels: { slack: { botToken: "${SLACK_BOT_TOKEN:-}" } },
  });
  const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.deepEqual(keys(result), [
    `fallback ${configPath} gateway.auth.token`,
    `fallback ${configPath} tools.search.endpoint`,
  ]);
  assertNoLeak(result);
});

test("an escaped $${VAR} is literal text, not a reference", () => {
  const config = JSON.stringify({ gateway: { auth: { password: "$${NOT_A_REF}" } } });
  const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.deepEqual(keys(result), [`plaintext ${configPath} gateway.auth.password`]);
});

test("models.json provider keys and sensitive headers are reported per agent", () => {
  const models = (secret: string) =>
    JSON.stringify({
      providers: {
        openai: { apiKey: secret, headers: { "X-Title": "nova", "x-api-key": SECRET_D } },
        bedrock: { apiKey: "AWS_PROFILE" },
        managed: { apiKey: "secretref-managed", headers: { Authorization: "secretref-env:TOKEN" } },
        oauth: { apiKey: "oauth:openai-codex" },
      },
    });
  const result = assessPlaintextSecrets(
    locations,
    fakeReader(
      { [mainModels]: models(SECRET_A), [workModels]: models(SECRET_B) },
      { [path.join(stateDir, "agents")]: ["main", "work"] },
    ),
  );
  assert.deepEqual(keys(result), [
    `plaintext ${mainModels} providers.openai.apiKey`,
    `plaintext ${mainModels} providers.openai.headers.x-api-key`,
    `plaintext ${workModels} providers.openai.apiKey`,
    `plaintext ${workModels} providers.openai.headers.x-api-key`,
  ]);
  assertNoLeak(result);
});

test("the main agent's models.json is scanned even if the agents directory is not listed", () => {
  const result = assessPlaintextSecrets(
    locations,
    fakeReader({ [mainModels]: JSON.stringify({ providers: { x: { apiKey: SECRET_A } } }) }),
  );
  assert.deepEqual(keys(result), [`plaintext ${mainModels} providers.x.apiKey`]);
});

test("unreadable or unparseable files are unknown and never echo their contents", () => {
  const result = assessPlaintextSecrets(
    locations,
    fakeReader({
      [configPath]: `{ gateway: { auth: { token: "${SECRET_A}" `,
      [stateEnv]: "UNREADABLE",
      [mainModels]: `{"providers": {"x": {"apiKey": "${SECRET_B}"}`,
    }),
  );
  assert.equal(result.grade, "unknown");
  assert.deepEqual(result.unreadable, [stateEnv, configPath, mainModels]);
  assert.deepEqual(result.findings, []);
  assertNoLeak(result);
});

test("findings outrank unreadable files, which are still listed", () => {
  const result = assessPlaintextSecrets(
    locations,
    fakeReader({ [stateEnv]: `OPENAI_API_KEY=${SECRET_A}`, [configPath]: "UNREADABLE" }),
  );
  assert.equal(result.grade, "warning");
  assert.deepEqual(result.unreadable, [configPath]);
  assert.match(result.summary, /1 plaintext secret/);
  assert.match(result.summary, /1 file could not be read/);
  assertNoLeak(result);
});

test("reported keys are sanitized and bounded", () => {
  const config = JSON.stringify({ channels: { ["evil\u001b[2J\nname"]: { token: SECRET_A } } });
  const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.equal(result.findings.length, 1);
  assert.ok(!/[\u0000-\u001f\u007f]/.test(result.findings[0]!.key));
  assert.ok(result.findings[0]!.key.length <= 200);
  assertNoLeak(result);
});

test(".env files are parsed the way OpenClaw's dotenv parser reads them", () => {
  const result = assessPlaintextSecrets(
    locations,
    fakeReader({
      [stateEnv]: [
        `OPENAI_API_KEY="`,
        SECRET_A,
        `"`,
        `PLAIN=1\rDISCORD_BOT_TOKEN=${SECRET_B}\r`,
        `SLACK_TOKEN: ${SECRET_C}`,
        `openai.api-key=${SECRET_D}`,
        "QUOTED_EMPTY_TOKEN=''",
      ].join("\n"),
    }),
  );
  assert.deepEqual(keys(result), [
    `plaintext ${stateEnv}:1 OPENAI_API_KEY`,
    `plaintext ${stateEnv}:5 DISCORD_BOT_TOKEN`,
    `plaintext ${stateEnv}:6 SLACK_TOKEN`,
    `plaintext ${stateEnv}:7 openai.api-key`,
  ]);
  assertNoLeak(result);
});

test("camelCase secret names and arrays under secret names are reported", () => {
  const config = JSON.stringify({
    ssh: { privateKey: SECRET_A, publicKey: "ssh-ed25519 AAAA" },
    cloud: { accessKey: SECRET_B },
    providers: { o: { apiKeys: [SECRET_C, "${OTHER_API_KEY}"] } },
  });
  const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.deepEqual(keys(result), [
    `plaintext ${configPath} ssh.privateKey`,
    `plaintext ${configPath} cloud.accessKey`,
    `plaintext ${configPath} providers.o.apiKeys.0`,
  ]);
  assertNoLeak(result);
});

test("literal text around a reference is still plaintext; a bare reference is not", () => {
  const config = JSON.stringify({
    a: { apiKey: `\${X}${SECRET_A}` },
    b: { apiKey: `${SECRET_B}\${OPENAI_API_KEY}` },
    c: { apiKey: `\${X:-}${SECRET_C}` },
    d: { headers: { Authorization: "Bearer ${CUSTOM_TOKEN}" } },
    e: { apiKey: "  ${OPENAI_API_KEY}  " },
  });
  const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.deepEqual(keys(result), [
    `plaintext ${configPath} a.apiKey`,
    `plaintext ${configPath} b.apiKey`,
    `plaintext ${configPath} c.apiKey`,
  ]);
  assertNoLeak(result);
});

test("numeric passwords are plaintext; numeric token counts are not", () => {
  const config = "{ db: { password: 918273645 }, agents: { defaults: { maxTokens: 4096 } } }";
  const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.deepEqual(keys(result), [`plaintext ${configPath} db.password`]);
  assertNoLeak(result, ["918273645"]);
});

test("env-var-name markers are exempt only in apiKey fields", () => {
  const config = JSON.stringify({
    gateway: { auth: { token: "OPENCLAW_GATEWAY_TOKEN" } },
    models: { providers: { openai: { apiKey: "OPENAI_API_KEY" } } },
  });
  const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.deepEqual(keys(result), [`plaintext ${configPath} gateway.auth.token`]);
});

test("a models.json apiKey that is only a reference is not plaintext", () => {
  const result = assessPlaintextSecrets(
    locations,
    fakeReader({ [mainModels]: JSON.stringify({ providers: { o: { apiKey: "${OPENAI_API_KEY}" } } }) }),
  );
  assert.equal(result.grade, "pass");
});

test("a path segment that looks like a credential is redacted, not reported", () => {
  const keyLike = "sk-ant-api03-Qz7Lm2Wk4RtHy6TnQ3sDf8Jc1Vb";
  const config = JSON.stringify({ gateway: { tokens: { [keyLike]: { apiKey: SECRET_A } } } });
  const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.deepEqual(keys(result), [`plaintext ${configPath} gateway.tokens.<redacted>.apiKey`]);
  assertNoLeak(result, [...SECRETS, keyLike]);
});

test("user-chosen map keys never reach a report unless they are plain words", () => {
  const keysThatAreSecrets = [
    "hunter2",
    "Tr0ub4dor&3",
    "abcdefgh1jk-abcdefgh1jk",
    "ghp_abc1-def2-ghi3-jkl4",
    "xoxb-1234-5678-abcdEFGH",
    "sk-REALSECRETVALUE",
    "pa55w0rd!",
  ];
  for (const mapKey of keysThatAreSecrets) {
    const config = JSON.stringify({ gateway: { tokens: { [mapKey]: { token: SECRET_A } } } });
    const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
    assert.deepEqual(keys(result), [`plaintext ${configPath} gateway.tokens.<redacted>.token`], mapKey);
    assert.ok(!JSON.stringify(result).includes(mapKey), mapKey);
  }
  const named = JSON.stringify({ models: { providers: { "openai-codex": { apiKey: SECRET_B } } } });
  assert.deepEqual(keys(assessPlaintextSecrets(locations, fakeReader({ [configPath]: named }))), [
    `plaintext ${configPath} models.providers.openai-codex.apiKey`,
  ]);
});

test("long descriptive names are reported in full", () => {
  const result = assessPlaintextSecrets(
    locations,
    fakeReader({
      [stateEnv]: `ANTHROPIC_OAUTH_REFRESH_TOKEN=${SECRET_A}`,
      [configPath]: JSON.stringify({ a: { anthropicOauthRefreshToken: SECRET_B } }),
    }),
  );
  assert.deepEqual(keys(result), [
    `plaintext ${stateEnv}:1 ANTHROPIC_OAUTH_REFRESH_TOKEN`,
    `plaintext ${configPath} a.anthropicOauthRefreshToken`,
  ]);
});

test("an earlier .env secret is reported even when a later line overrides it", () => {
  const result = assessPlaintextSecrets(
    locations,
    fakeReader({ [stateEnv]: `OPENAI_API_KEY=${SECRET_A}\nOPENAI_API_KEY=\nGITHUB_TOKEN=${SECRET_B}\nGITHUB_TOKEN=${SECRET_C}` }),
  );
  assert.deepEqual(keys(result), [
    `plaintext ${stateEnv}:1 OPENAI_API_KEY`,
    `plaintext ${stateEnv}:3 GITHUB_TOKEN`,
    `plaintext ${stateEnv}:4 GITHUB_TOKEN`,
  ]);
  assertNoLeak(result);
});

test("apiKey markers do not exempt other secret fields", () => {
  const config = JSON.stringify({
    a: { password: "oauth:hunter2" },
    b: { token: "ollama-local" },
    c: { apiKey: "oauth:openai-codex" },
    d: { token: "secretref-env:GATEWAY_TOKEN" },
  });
  const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.deepEqual(keys(result), [`plaintext ${configPath} a.password`, `plaintext ${configPath} b.token`]);
});

test("numeric credentials under token, key, and pin names are plaintext", () => {
  const config =
    "{ a: { token: 1234567890 }, b: { apiKey: 987654321 }, c: { pin: 1234 }, " +
    "d: { maxTokens: 4096, tokenLimit: 100, keyCount: 3 } }";
  const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.deepEqual(keys(result), [
    `plaintext ${configPath} a.token`,
    `plaintext ${configPath} b.apiKey`,
    `plaintext ${configPath} c.pin`,
  ]);
});

test("a header built only from references and separators is not plaintext", () => {
  const config = JSON.stringify({ h: { Authorization: "Basic ${USER_NAME}:${USER_PASSWORD}" } });
  assert.equal(assessPlaintextSecrets(locations, fakeReader({ [configPath]: config })).grade, "pass");
});

test("an unlistable agents directory makes the result unknown, not pass", () => {
  const agentsRoot = path.join(stateDir, "agents");
  const result = assessPlaintextSecrets(
    locations,
    fakeReader({ [mainModels]: JSON.stringify({ providers: {} }) }, { [agentsRoot]: "unreadable" }),
  );
  assert.equal(result.grade, "unknown");
  assert.deepEqual(result.unreadable, [agentsRoot]);
});

test("a fallback longer than 512 characters is still a plaintext fallback", () => {
  const longJwt = `eyJ${"a".repeat(2000)}`;
  const config = JSON.stringify({ tools: { search: { endpoint: `\${SEARCH_API_KEY:-${longJwt}}` } } });
  const result = assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.deepEqual(keys(result), [`fallback ${configPath} tools.search.endpoint`]);
  assertNoLeak(result, [longJwt.slice(0, 40)]);
});

test("models.json findings keep the fallback kind", () => {
  const models = JSON.stringify({
    providers: {
      o: { apiKey: `\${OPENAI_API_KEY:-${SECRET_A}}`, headers: { "x-api-key": `\${X_KEY:-${SECRET_B}}` } },
    },
  });
  const result = assessPlaintextSecrets(locations, fakeReader({ [mainModels]: models }));
  assert.deepEqual(keys(result), [
    `fallback ${mainModels} providers.o.apiKey`,
    `fallback ${mainModels} providers.o.headers.x-api-key`,
  ]);
  assertNoLeak(result);
});

test("config files referenced by $include are scanned with OpenClaw's rules", () => {
  const gatewayFile = path.join(stateDir, "gateway.json5");
  const channelsDir = path.join(stateDir, "parts");
  const discordFile = path.join(channelsDir, "discord.json5");
  const slackFile = path.join(channelsDir, "slack.json5");
  const result = assessPlaintextSecrets(
    locations,
    fakeReader({
      [configPath]: `{ gateway: { $include: "./gateway.json5" }, channels: { $include: ["parts/discord.json5", "${slackFile}"] } }`,
      [gatewayFile]: `{ auth: { mode: "token", token: "${SECRET_A}" } }`,
      // Nested includes resolve relative to the including file.
      [discordFile]: `{ discord: { token: "${SECRET_B}" }, $include: "./slack.json5" }`,
      [slackFile]: `{ slack: { botToken: "${SECRET_C}" } }`,
    }),
  );
  assert.deepEqual(keys(result), [
    `plaintext ${gatewayFile} auth.token`,
    `plaintext ${discordFile} discord.token`,
    `plaintext ${slackFile} slack.botToken`,
  ]);
  assertNoLeak(result);
});

test("$include cycles terminate and paths outside the config roots are not read", () => {
  const a = path.join(stateDir, "a.json5");
  const b = path.join(stateDir, "b.json5");
  const outside = path.join(home, "outside.json5");
  const sharedRoot = path.join(home, "shared");
  const shared = path.join(sharedRoot, "keys.json5");
  const requested: string[] = [];
  const base = fakeReader({
    [configPath]: `{ $include: ["./a.json5", "../outside.json5", "${shared}"] }`,
    [a]: `{ $include: "./b.json5" }`,
    [b]: `{ $include: "./a.json5", x: { token: "${SECRET_A}" } }`,
    [outside]: `{ token: "${SECRET_B}" }`,
    [shared]: `{ token: "${SECRET_C}" }`,
  });
  const reader: SecretFileReader = {
    readText(file) {
      requested.push(file);
      return base.readText(file);
    },
    listDirectories: base.listDirectories,
  };
  const withoutRoot = assessPlaintextSecrets(locations, reader);
  assert.deepEqual(keys(withoutRoot), [`plaintext ${b} x.token`]);
  assert.ok(!requested.includes(outside));
  assert.ok(!requested.includes(shared));

  const withRoot = assessPlaintextSecrets({ ...locations, includeRoots: [sharedRoot] }, reader);
  assert.deepEqual(keys(withRoot), [`plaintext ${b} x.token`, `plaintext ${shared} token`]);
  assertNoLeak(withRoot);
});

test("missing, unparseable, or too deeply nested includes are unknown", () => {
  const missing = path.join(stateDir, "missing.json5");
  const broken = path.join(stateDir, "broken.json5");
  const result = assessPlaintextSecrets(
    locations,
    fakeReader({
      [configPath]: `{ $include: ["./missing.json5", "./broken.json5"] }`,
      [broken]: `{ token: "${SECRET_A}" `,
    }),
  );
  assert.equal(result.grade, "unknown");
  assert.deepEqual(result.unreadable, [missing, broken]);
  assertNoLeak(result);

  const chain: Record<string, string> = { [configPath]: `{ $include: "./d1.json5" }` };
  for (let depth = 1; depth <= 11; depth += 1) {
    chain[path.join(stateDir, `d${depth}.json5`)] = `{ $include: "./d${depth + 1}.json5" }`;
  }
  const deep = assessPlaintextSecrets(locations, fakeReader(chain));
  assert.equal(deep.grade, "unknown");
});

test("crafted unterminated references are handled in linear time", () => {
  const config = JSON.stringify({ p: { apiKey: "${A:-".repeat(40_000) } });
  const started = performance.now();
  assessPlaintextSecrets(locations, fakeReader({ [configPath]: config }));
  assert.ok(performance.now() - started < 500);
});

test("a FIFO or other non-regular file is unknown and never blocks the scan", { skip: process.platform === "win32" }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), "nova-guard-fifo-"));
  try {
    const fifo = path.join(dir, ".env");
    execFileSync("mkfifo", [fifo]);
    // A blocking open would hang this process, so read in a child with a timeout.
    const moduleUrl = new URL("../src/checks/plaintext-secrets.ts", import.meta.url).href;
    const output = execFileSync(
      process.execPath,
      [
        "--import",
        "tsx",
        "--input-type=module",
        "-e",
        `const { nodeSecretFileReader } = await import(${JSON.stringify(moduleUrl)});
         process.stdout.write(JSON.stringify(nodeSecretFileReader.readText(${JSON.stringify(fifo)})));`,
      ],
      { timeout: 5000, encoding: "utf8" },
    );
    assert.deepEqual(JSON.parse(output), { status: "unreadable" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the .env parser matches dotenv, the parser OpenClaw uses", () => {
  const corpus = [
    "A=1\nB = 2\n export C=3\nD: 4\ne.f-g=5",
    "Q='single # not comment'\nR=\"double\\nnewline\"\nS=`back`\nT=x # comment\nU=",
    'M="\nmulti\nline\n"\nN=after',
    "X=1\rY=2\r\nZ=3",
    "DUP=first\nDUP=second",
    "# only comment\n\n   \nnot an assignment\n=novalue",
    "K='unterminated\nL=2",
    "\ufeffBOM_KEY=1",
  ];
  for (const text of corpus) {
    const ours = Object.fromEntries([...parseDotEnv(text)].map(([key, { value }]) => [key, value]));
    assert.deepEqual(ours, dotenv.parse(text), JSON.stringify(text));
  }
});

test("line numbers follow the assignment, including after blank lines", () => {
  assert.deepEqual(
    [...parseDotEnv("\n\n  OPENAI_API_KEY=x\nDUP=1\n\nDUP=2\n")].map(([key, { line }]) => [key, line]),
    [["OPENAI_API_KEY", 3], ["DUP", 6]],
  );
});

test("large .env files are parsed in linear time", () => {
  const started = performance.now();
  assert.equal(parseDotEnv("A=1\n".repeat(60_000)).size, 1);
  assert.ok(performance.now() - started < 500);
});

test("the real file reader is read-only and reports missing, ok, and oversized files", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "nova-guard-secrets-"));
  try {
    const agentDir = path.join(dir, "agents", "main", "agent");
    mkdirSync(agentDir, { recursive: true });
    writeFileSync(path.join(dir, ".env"), `OPENAI_API_KEY=${SECRET_A}\n`);
    writeFileSync(path.join(dir, "big.json"), "x".repeat(2 * 1024 * 1024));
    assert.deepEqual(nodeSecretFileReader.readText(path.join(dir, "absent")), { status: "missing" });
    assert.equal(nodeSecretFileReader.readText(path.join(dir, ".env")).status, "ok");
    assert.deepEqual(nodeSecretFileReader.readText(path.join(dir, "big.json")), { status: "unreadable" });
    assert.deepEqual(nodeSecretFileReader.listDirectories(path.join(dir, "agents")), ["main"]);
    assert.deepEqual(nodeSecretFileReader.listDirectories(path.join(dir, "nope")), []);

    const result = assessPlaintextSecrets(
      { stateDir: dir, configPath: path.join(dir, "openclaw.json"), homeDir: dir },
      nodeSecretFileReader,
    );
    assert.deepEqual(keys(result), [`plaintext ${path.join(dir, ".env")}:1 OPENAI_API_KEY`]);
    assertNoLeak(result);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
