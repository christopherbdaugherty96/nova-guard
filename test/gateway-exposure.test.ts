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
