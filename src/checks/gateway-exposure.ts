import { isIP } from "node:net";

type GatewayAuthMode = "none" | "token" | "password" | "trusted-proxy";

interface OpenClawConfig {
  gateway?: {
    bind?: unknown;
    customBindHost?: unknown;
    trustedProxies?: unknown;
    tailscale?: {
      mode?: unknown;
    };
    auth?: {
      mode?: unknown;
      token?: unknown;
      password?: unknown;
    };
  };
}

export interface GatewayRuntimeContext {
  isContainer?: boolean;
  gatewayTokenAvailable?: boolean;
  gatewayPasswordAvailable?: boolean;
}

export interface GatewayExposureResult {
  grade: "pass" | "warning" | "critical" | "unknown";
  bind: string;
  auth: GatewayAuthMode | "default" | "unrecognized";
  summary: string;
}

function authMode(config: OpenClawConfig): GatewayExposureResult["auth"] {
  const value = config.gateway?.auth?.mode;
  if (value === undefined) {
    return "default";
  }
  if (
    value === "none" ||
    value === "token" ||
    value === "password" ||
    value === "trusted-proxy"
  ) {
    return value;
  }
  return "unrecognized";
}

function isLiteralLoopback(host: string): boolean {
  const ipVersion = isIP(host);
  if (ipVersion === 4) {
    return host.split(".")[0] === "127";
  }
  return ipVersion === 6 && host === "::1";
}

export function assessGatewayExposure(
  config: OpenClawConfig,
  context: GatewayRuntimeContext = {},
): GatewayExposureResult {
  const bindValue = config.gateway?.bind;
  let bind: string;
  if (typeof bindValue === "string") {
    bind = bindValue;
  } else if (
    typeof config.gateway?.tailscale?.mode === "string" &&
    config.gateway.tailscale.mode !== "off"
  ) {
    bind = "loopback";
  } else if (context.isContainer === true) {
    bind = "auto";
  } else if (context.isContainer === false) {
    bind = "loopback";
  } else {
    return {
      grade: "unknown",
      bind: "default",
      auth: authMode(config),
      summary: "Gateway default binding depends on the runtime environment.",
    };
  }
  const auth = authMode(config);

  if (bind === "loopback") {
    return {
      grade: "pass",
      bind,
      auth,
      summary: "Gateway uses the loopback-only default.",
    };
  }

  if (bind === "custom") {
    const hostValue = config.gateway?.customBindHost;
    const host = typeof hostValue === "string" ? hostValue.trim() : "unknown";
    const describedBind = `custom (${host})`;
    if (isLiteralLoopback(host)) {
      return {
        grade: "pass",
        bind: describedBind,
        auth,
        summary: "Gateway custom binding is a literal loopback address.",
      };
    }
    return exposedResult(
      describedBind,
      auth,
      hasAuthEvidence(config, context),
    );
  }

  if (bind === "auto") {
    return {
      grade: "unknown",
      bind: bindValue === undefined ? "auto (container default)" : bind,
      auth,
      summary: "Gateway auto binding depends on the host network at runtime.",
    };
  }

  if (bind === "lan" || bind === "tailnet") {
    return exposedResult(bind, auth, hasAuthEvidence(config, context));
  }

  return {
    grade: "unknown",
    bind,
    auth,
    summary: "Gateway binding is not recognized by this scanner version.",
  };
}

function exposedResult(
  bind: string,
  auth: GatewayExposureResult["auth"],
  authVerified = false,
): GatewayExposureResult {
  if (auth === "none") {
    return {
      grade: "critical",
      bind,
      auth,
      summary: "Gateway is configured for non-loopback access without authentication.",
    };
  }
  if (
    authVerified &&
    (auth === "token" || auth === "password" || auth === "trusted-proxy")
  ) {
    return {
      grade: "warning",
      bind,
      auth,
      summary: "Gateway is authenticated but exposed beyond loopback.",
    };
  }
  return {
    grade: "unknown",
    bind,
    auth,
    summary: "Gateway is exposed beyond loopback and authentication could not be verified.",
  };
}

function hasConfiguredSecret(value: unknown): boolean {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    !/^\$\{[^}]+\}$/.test(value.trim())
  );
}

function hasAuthEvidence(
  config: OpenClawConfig,
  context: GatewayRuntimeContext,
): boolean {
  const mode = authMode(config);
  if (mode === "token") {
    return (
      context.gatewayTokenAvailable === true ||
      hasConfiguredSecret(config.gateway?.auth?.token)
    );
  }
  if (mode === "password") {
    return (
      context.gatewayPasswordAvailable === true ||
      hasConfiguredSecret(config.gateway?.auth?.password)
    );
  }
  if (mode === "trusted-proxy") {
    return (
      Array.isArray(config.gateway?.trustedProxies) &&
      config.gateway.trustedProxies.length > 0
    );
  }
  return false;
}
