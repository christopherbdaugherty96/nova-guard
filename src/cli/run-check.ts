import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

import { assessGatewayExposure, type GatewayExposureResult } from "../checks/gateway-exposure.js";
import { assessPlaintextSecrets, nodeSecretFileReader, parseDotEnv } from "../checks/plaintext-secrets.js";
import { assessRiskySkills } from "../checks/risky-skills.js";
import { assessOpenClawVersion } from "../checks/version-advisories.js";
import { advisoryDataDate } from "../data/openclaw-advisories.js";
import { renderReportCard } from "../report/report-card.js";
import { toolVersion } from "../version.js";
import { loadOpenClawConfig } from "./config.js";
import { detectContainer } from "./container.js";
import { resolveOpenClawLocations } from "./locate.js";

export interface CheckDependencies {
  env: NodeJS.ProcessEnv;
  homedir?: () => string;
  probeVersion: () => Promise<string | undefined>;
  isContainer?: () => boolean;
}

const nodeFiles = {
  exists: (file: string) => existsSync(file),
  read: (file: string) => {
    try {
      return readFileSync(file, "utf8");
    } catch {
      return undefined;
    }
  },
};

/** Runs the four checks read-only and renders the report card. */
export async function runCheck(deps: CheckDependencies): Promise<string> {
  const versionOutput = await deps.probeVersion();
  const version = assessOpenClawVersion(versionOutput);
  const locations = resolveOpenClawLocations(deps.env, deps.homedir);
  if (!locations) {
    // Without a home, no OpenClaw path can be verified: those checks stay unknown.
    return renderReportCard({
      homeDir: path.parse(process.cwd()).root,
      stateDir: path.parse(process.cwd()).root,
      toolVersion,
      advisoryDataDate,
      version,
    });
  }

  const config = loadOpenClawConfig(locations.configPath, locations.includeRoots);

  let gateway: GatewayExposureResult;
  if (config.status === "unreadable") {
    gateway = {
      grade: "unknown",
      bind: "unknown",
      auth: "unrecognized",
      summary: "OpenClaw config could not be read, so gateway exposure is unknown.",
    };
  } else {
    // Gateway credentials count as available only when one of the .env files
    // OpenClaw loads defines them; only their presence is checked.
    const envFiles = [
      path.join(locations.stateDir, ".env"),
      path.join(path.dirname(locations.configPath), ".env"),
      path.join(locations.homeDir, ".config", "openclaw", "gateway.env"),
    ];
    const defined = (name: string) =>
      envFiles.some((file) => {
        const read = nodeSecretFileReader.readText(file);
        return read.status === "ok" && (parseDotEnv(read.text).get(name)?.value.trim() ?? "") !== "";
      });
    gateway = assessGatewayExposure(config.status === "ok" ? (config.config as object) : {}, {
      isContainer: (deps.isContainer ?? (() => detectContainer(deps.env, nodeFiles)))(),
      ...(defined("OPENCLAW_GATEWAY_TOKEN") ? { gatewayTokenAvailable: true } : {}),
      ...(defined("OPENCLAW_GATEWAY_PASSWORD") ? { gatewayPasswordAvailable: true } : {}),
    });
  }

  const secrets = assessPlaintextSecrets({
    stateDir: locations.stateDir,
    configPath: locations.configPath,
    homeDir: locations.homeDir,
    includeRoots: locations.includeRoots,
  });
  const skills = assessRiskySkills(
    {
      stateDir: locations.stateDir,
      homeDir: locations.homeDir,
      osHomeDir: locations.osHomeDir,
      workspaceDir: locations.workspaceDir,
    },
    config,
  );

  return renderReportCard({
    homeDir: locations.homeDir,
    osHomeDir: locations.osHomeDir,
    stateDir: locations.stateDir,
    configPath: locations.configPath,
    toolVersion,
    advisoryDataDate,
    gateway,
    version,
    secrets,
    skills,
  });
}
