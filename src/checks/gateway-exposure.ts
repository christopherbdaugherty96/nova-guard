import { isIP } from "node:net";

type GatewayAuthMode = "none" | "token" | "password" | "trusted-proxy";

interface OpenClawConfig {
  gateway?: {
    bind?: unknown;
    customBindHost?: unknown;
    auth?: {
      mode?: unknown;
    };
  };
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
): GatewayExposureResult {
  const bindValue = config.gateway?.bind;
  const bind = typeof bindValue === "string" ? bindValue : "loopback";
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
    const host = typeof hostValue === "string" ? hostValue : "unknown";
    const describedBind = `custom (${host})`;
    if (isLiteralLoopback(host)) {
      return {
        grade: "pass",
        bind: describedBind,
        auth,
        summary: "Gateway custom binding is a literal loopback address.",
      };
    }
    return exposedResult(describedBind, auth);
  }

  if (bind === "auto") {
    return {
      grade: "unknown",
      bind,
      auth,
      summary: "Gateway auto binding depends on the host network at runtime.",
    };
  }

  if (bind === "lan" || bind === "tailnet") {
    return exposedResult(bind, auth);
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
): GatewayExposureResult {
  if (auth === "none") {
    return {
      grade: "critical",
      bind,
      auth,
      summary: "Gateway is configured for non-loopback access without authentication.",
    };
  }
  if (auth === "token" || auth === "password" || auth === "trusted-proxy") {
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
