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
      trustedProxy?: {
        userHeader?: unknown;
      };
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
    if (hasConfiguredShape(config.gateway?.auth?.password)) {
      return "password";
    }
    if (hasConfiguredShape(config.gateway?.auth?.token)) {
      return "token";
    }
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

// Called only for an IPv4 host: 127.0.0.0/8.
function isLiteralLoopback(host: string): boolean {
  return host.split(".")[0] === "127";
}

export function assessGatewayExposure(
  config: OpenClawConfig,
  context: GatewayRuntimeContext = {},
): GatewayExposureResult {
  const tailscaleMode = config.gateway?.tailscale?.mode;
  const auth = authMode(config);
  const tailscaleFinding = assessTailscaleExposure(tailscaleMode, auth, config, context);
  const bindConfig =
    (tailscaleMode === "serve" || tailscaleMode === "funnel") &&
    config.gateway?.bind === undefined
      ? {
          ...config,
          gateway: { ...config.gateway, bind: "loopback" },
        }
      : config;
  const bindFinding = assessBindExposure(bindConfig, context, auth);
  return combineFindings(bindFinding, tailscaleFinding);
}

function assessTailscaleExposure(
  mode: unknown,
  auth: GatewayExposureResult["auth"],
  config: OpenClawConfig,
  context: GatewayRuntimeContext,
): GatewayExposureResult | undefined {
  if (mode === undefined || mode === "off") {
    return undefined;
  }
  if (mode === "serve") {
    return {
      grade: "warning",
      bind: "tailscale serve (tailnet)",
      auth,
      summary: "Gateway is reachable from the tailnet via Tailscale Serve.",
    };
  }
  if (mode === "funnel") {
    const authModeExplicit = config.gateway?.auth?.mode !== undefined;
    if (authModeExplicit && auth !== "password") {
      return {
        grade: "critical",
        bind: "tailscale funnel (public)",
        auth,
        summary: "Public Tailscale Funnel exposure has a non-password auth mode.",
      };
    }
    return {
      grade: "warning",
      bind: "tailscale funnel (public)",
      auth,
      summary: hasAuthEvidence(config, context)
        ? "Public internet exposure via Tailscale Funnel."
        : "Public internet exposure via Tailscale Funnel; password is not verifiable.",
    };
  }
  return {
    grade: "unknown",
    bind: `tailscale (${String(mode)})`,
    auth,
    summary: "Tailscale mode is unrecognized by this scanner version.",
  };
}

function assessBindExposure(
  config: OpenClawConfig,
  context: GatewayRuntimeContext,
  auth: GatewayExposureResult["auth"],
): GatewayExposureResult {

  const bindValue = config.gateway?.bind;
  let bind: string;
  if (typeof bindValue === "string") {
    bind = bindValue;
  } else if (context.isContainer === true) {
    bind = "auto";
  } else if (context.isContainer === false) {
    bind = "loopback";
  } else {
    return {
      grade: "unknown",
      bind: "default",
      auth,
      summary: "Gateway default binding depends on the runtime environment.",
    };
  }
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
    // OpenClaw binds a custom host only when it is an IPv4 address
    // (resolveGatewayBindHost at b8324c64); startup rejects anything else, so
    // the configured exposure cannot be established.
    if (isIP(host) !== 4) {
      return {
        grade: "unknown",
        bind: describedBind,
        auth,
        summary: "Gateway custom bind host is not an IPv4 address OpenClaw can bind, so exposure is unknown.",
      };
    }
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

const gradeRank: Record<GatewayExposureResult["grade"], number> = {
  pass: 0,
  unknown: 1,
  warning: 2,
  critical: 3,
};

function combineFindings(
  bindFinding: GatewayExposureResult,
  tailscaleFinding: GatewayExposureResult | undefined,
): GatewayExposureResult {
  if (!tailscaleFinding) {
    return bindFinding;
  }
  const primary =
    gradeRank[bindFinding.grade] >= gradeRank[tailscaleFinding.grade]
      ? bindFinding
      : tailscaleFinding;
  if (bindFinding.grade === "pass") {
    return tailscaleFinding;
  }
  if (tailscaleFinding.grade === "pass") {
    return bindFinding;
  }
  return {
    ...primary,
    summary: `${primary.summary} Also: ${
      primary === bindFinding ? tailscaleFinding.summary : bindFinding.summary
    }`,
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
  const trimmed = typeof value === "string" ? value.trim() : "";
  return (
    trimmed.length > 0 &&
    (!/^\$\{[^}]+\}$/.test(trimmed) ||
      /^\$\{[^}:]+:-[^}]+\}$/.test(trimmed))
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
      config.gateway.trustedProxies.length > 0 &&
      typeof config.gateway?.auth?.trustedProxy?.userHeader === "string" &&
      config.gateway.auth.trustedProxy.userHeader.trim().length > 0
    );
  }
  return false;
}

function hasConfiguredShape(value: unknown): boolean {
  return typeof value === "string" && value.trim().length > 0;
}
