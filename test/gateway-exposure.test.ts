import assert from "node:assert/strict";
import test from "node:test";

import { assessGatewayExposure } from "../src/checks/gateway-exposure.js";

test("default gateway configuration is loopback-only on a known host", () => {
  assert.deepEqual(assessGatewayExposure({}, { isContainer: false }), {
    grade: "pass",
    bind: "loopback",
    auth: "default",
    summary: "Gateway uses the loopback-only default.",
  });
});

test("unauthenticated LAN binding is critical", () => {
  assert.deepEqual(
    assessGatewayExposure({
      gateway: { bind: "lan", auth: { mode: "none" } },
    }),
    {
      grade: "critical",
      bind: "lan",
      auth: "none",
      summary: "Gateway is configured for non-loopback access without authentication.",
    },
  );
});

test("authenticated LAN binding still reports expanded exposure", () => {
  assert.deepEqual(
    assessGatewayExposure({
      gateway: { bind: "lan", auth: { mode: "token", token: "configured" } },
    }),
    {
      grade: "warning",
      bind: "lan",
      auth: "token",
      summary: "Gateway is authenticated but exposed beyond loopback.",
    },
  );
});

test("omitted bind is unknown when the runtime environment is unknown", () => {
  assert.deepEqual(assessGatewayExposure({}), {
    grade: "unknown",
    bind: "default",
    auth: "default",
    summary: "Gateway default binding depends on the runtime environment.",
  });
});

test("omitted bind in a container is not reported as loopback", () => {
  assert.deepEqual(assessGatewayExposure({}, { isContainer: true }), {
    grade: "unknown",
    bind: "auto (container default)",
    auth: "default",
    summary: "Gateway auto binding depends on the host network at runtime.",
  });
});

test("auth mode without its credential remains unknown", () => {
  assert.deepEqual(
    assessGatewayExposure({
      gateway: { bind: "lan", auth: { mode: "token" } },
    }),
    {
      grade: "unknown",
      bind: "lan",
      auth: "token",
      summary: "Gateway is exposed beyond loopback and authentication could not be verified.",
    },
  );
});

test("custom loopback address remains local", () => {
  assert.deepEqual(
    assessGatewayExposure({
      gateway: {
        bind: "custom",
        customBindHost: "127.0.0.2",
        auth: { mode: "none" },
      },
    }),
    {
      grade: "pass",
      bind: "custom (127.0.0.2)",
      auth: "none",
      summary: "Gateway custom binding is a literal loopback address.",
    },
  );
});

test("custom host is trimmed before loopback classification", () => {
  assert.deepEqual(
    assessGatewayExposure({
      gateway: {
        bind: "custom",
        customBindHost: " 127.0.0.1 ",
        auth: { mode: "none" },
      },
    }),
    {
      grade: "pass",
      bind: "custom (127.0.0.1)",
      auth: "none",
      summary: "Gateway custom binding is a literal loopback address.",
    },
  );
});

test("auto binding is unknown rather than assumed safe", () => {
  assert.deepEqual(
    assessGatewayExposure({ gateway: { bind: "auto" } }),
    {
      grade: "unknown",
      bind: "auto",
      auth: "default",
      summary: "Gateway auto binding depends on the host network at runtime.",
    },
  );
});

test("implicit loopback with Tailscale Funnel reports public exposure", () => {
  assert.deepEqual(
    assessGatewayExposure({
      gateway: {
        tailscale: { mode: "funnel" },
        auth: { mode: "password", password: "configured" },
      },
    }),
    {
      grade: "warning",
      bind: "tailscale funnel (public)",
      auth: "password",
      summary: "Public internet exposure via Tailscale Funnel.",
    },
  );
});

test("explicit loopback with Tailscale Funnel still reports public exposure", () => {
  assert.deepEqual(
    assessGatewayExposure({
      gateway: {
        bind: "loopback",
        tailscale: { mode: "funnel" },
        auth: { mode: "password", password: "configured" },
      },
    }),
    {
      grade: "warning",
      bind: "tailscale funnel (public)",
      auth: "password",
      summary: "Public internet exposure via Tailscale Funnel.",
    },
  );
});

test("Tailscale Funnel without evidenced password auth is warning", () => {
  assert.deepEqual(
    assessGatewayExposure({
      gateway: {
        tailscale: { mode: "funnel" },
        auth: { mode: "password" },
      },
    }),
    {
      grade: "warning",
      bind: "tailscale funnel (public)",
      auth: "password",
      summary: "Public internet exposure via Tailscale Funnel; password is not verifiable.",
    },
  );
});

test("Tailscale Serve reports tailnet exposure", () => {
  assert.deepEqual(
    assessGatewayExposure({
      gateway: { tailscale: { mode: "serve" } },
    }),
    {
      grade: "warning",
      bind: "tailscale serve (tailnet)",
      auth: "default",
      summary: "Gateway is reachable from the tailnet via Tailscale Serve.",
    },
  );
});

test("unauthenticated LAN binding outranks Tailscale Serve", () => {
  const result = assessGatewayExposure({
    gateway: {
      bind: "lan",
      auth: { mode: "none" },
      tailscale: { mode: "serve" },
    },
  });
  assert.equal(result.grade, "critical");
  assert.match(result.summary, /LAN|non-loopback/i);
  assert.match(result.summary, /tailnet|Serve/i);
});

test("unauthenticated wildcard custom binding outranks Tailscale Serve", () => {
  const result = assessGatewayExposure({
    gateway: {
      bind: "custom",
      customBindHost: "0.0.0.0",
      auth: { mode: "none" },
      tailscale: { mode: "serve" },
    },
  });
  assert.equal(result.grade, "critical");
  assert.match(result.summary, /custom|non-loopback/i);
  assert.match(result.summary, /tailnet|Serve/i);
});

test("Funnel with an environment reference is warning, not critical", () => {
  const result = assessGatewayExposure({
    gateway: {
      tailscale: { mode: "funnel" },
      auth: { mode: "password", password: "${OPENCLAW_GATEWAY_PASSWORD}" },
    },
  });
  assert.equal(result.grade, "warning");
  assert.match(result.summary, /password.*not verifiable/i);
});

test("Funnel with default auth mode is warning, not critical", () => {
  const result = assessGatewayExposure({
    gateway: { tailscale: { mode: "funnel" } },
  });
  assert.equal(result.grade, "warning");
  assert.match(result.summary, /password.*not verifiable/i);
});

test("Funnel with an explicitly non-password mode is critical", () => {
  const result = assessGatewayExposure({
    gateway: {
      tailscale: { mode: "funnel" },
      auth: { mode: "token", token: "configured" },
    },
  });
  assert.equal(result.grade, "critical");
});

test("unrecognized Tailscale mode is unknown", () => {
  const result = assessGatewayExposure({
    gateway: { tailscale: { mode: "FUNNEL" } },
  });
  assert.equal(result.grade, "unknown");
  assert.match(result.summary, /Tailscale|unrecognized/i);
});

test("omitted auth mode resolves to token when a token is configured", () => {
  const result = assessGatewayExposure({
    gateway: { bind: "lan", auth: { token: "configured" } },
  });
  assert.equal(result.grade, "warning");
  assert.equal(result.auth, "token");
});

test("trusted proxy requires its identity header", () => {
  const result = assessGatewayExposure({
    gateway: {
      bind: "lan",
      auth: { mode: "trusted-proxy" },
      trustedProxies: ["127.0.0.1"],
    },
  });
  assert.equal(result.grade, "unknown");
});

test("complete trusted proxy configuration is evidenced", () => {
  const result = assessGatewayExposure({
    gateway: {
      bind: "lan",
      auth: {
        mode: "trusted-proxy",
        trustedProxy: { userHeader: "x-forwarded-user" },
      },
      trustedProxies: ["127.0.0.1"],
    },
  });
  assert.equal(result.grade, "warning");
});

test("nonempty environment fallback is evidence of configured auth", () => {
  const result = assessGatewayExposure({
    gateway: {
      bind: "lan",
      auth: { mode: "token", token: "${OPENCLAW_GATEWAY_TOKEN:-configured}" },
    },
  });
  assert.equal(result.grade, "warning");
});

test("a custom bind host OpenClaw cannot bind (not IPv4) is unknown, never pass", () => {
  // OpenClaw's resolveGatewayBindHost accepts only an IPv4 custom host; startup
  // rejects anything else, so the configured exposure cannot be established.
  for (const customBindHost of ["::1", "localhost", "", undefined]) {
    const result = assessGatewayExposure({
      gateway: { bind: "custom", ...(customBindHost === undefined ? {} : { customBindHost }), auth: { mode: "none" } },
    });
    assert.equal(result.grade, "unknown", String(customBindHost));
  }
  assert.equal(assessGatewayExposure({ gateway: { bind: "custom", customBindHost: "127.0.0.1" } }).grade, "pass");
});

test("unauthenticated Tailscale Serve is critical unless Tailscale identity is allowed", () => {
  // OpenClaw's own audit (gateway.loopback_no_auth) treats Serve without
  // gateway auth or allowTailscale as unauthenticated access.
  const none = assessGatewayExposure({ gateway: { tailscale: { mode: "serve" }, auth: { mode: "none" } } });
  assert.equal(none.grade, "critical");
  const identity = assessGatewayExposure({
    gateway: { tailscale: { mode: "serve" }, auth: { mode: "none", allowTailscale: true } },
  });
  assert.equal(identity.grade, "warning");
});
