import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import { assessGatewayExposure, type GatewayExposureResult } from "../checks/gateway-exposure.js";
import {
  assessPlaintextSecrets,
  nodeSecretFileReader,
  parseDotEnv,
  type PlaintextSecretsResult,
} from "../checks/plaintext-secrets.js";
import { assessRiskySkills, type RiskySkillsResult } from "../checks/risky-skills.js";
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

  let stateIsDirectory = false;
  try {
    stateIsDirectory = statSync(locations.stateDir).isDirectory();
  } catch {
    stateIsDirectory = false;
  }
  if (!stateIsDirectory && config.status === "missing") {
    // Nothing of OpenClaw's was found here; an empty scan must not read as pass.
    const summary = "No OpenClaw state directory was found, so this could not be checked.";
    // OpenClaw still loads ~/.config/openclaw/gateway.env, so secrets are
    // scanned too; with nothing found, the result is unknown, not pass.
    const foundSecrets = assessPlaintextSecrets({
      stateDir: locations.stateDir,
      configPath: locations.configPath,
      homeDir: locations.homeDir,
      includeRoots: locations.includeRoots,
    });
    const secrets: PlaintextSecretsResult =
      foundSecrets.grade === "pass" ? { ...foundSecrets, grade: "unknown", summary } : foundSecrets;
    // OpenClaw still loads skills from ~/.agents/skills and OPENCLAW_WORKSPACE_DIR,
    // so they are scanned; with nothing found, the result is unknown, not pass.
    const scanned = assessRiskySkills(
      {
        stateDir: locations.stateDir,
        homeDir: locations.homeDir,
        osHomeDir: locations.osHomeDir,
        ...(locations.workspaceDir === undefined ? {} : { workspaceDir: locations.workspaceDir }),
      },
      config,
    );
    const skills: RiskySkillsResult = scanned.grade === "pass" ? { ...scanned, grade: "unknown", summary } : scanned;
    return renderReportCard({
      homeDir: locations.homeDir,
      osHomeDir: locations.osHomeDir,
      stateDir: locations.stateDir,
      configPath: locations.configPath,
      toolVersion,
      advisoryDataDate,
      gateway: { grade: "unknown", bind: "unknown", auth: "unrecognized", summary },
      version,
      secrets,
      skills,
    });
  }

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
    // ~/.config/openclaw/gateway.env is loaded only with the default state dir
    // (OpenClaw's resolveGlobalDotEnvPaths).
    const envFiles = [
      path.join(locations.stateDir, ".env"),
      path.join(path.dirname(locations.configPath), ".env"),
      ...(locations.defaultStateDir ? [path.join(locations.homeDir, ".config", "openclaw", "gateway.env")] : []),
    ];
    const defined = (name: string) =>
      envFiles.some((file) => {
        const read = nodeSecretFileReader.readText(file);
        return read.status === "ok" && (parseDotEnv(read.text).get(name)?.value.trim() ?? "") !== "";
      });
    // Detection describes the host nova-guard runs on. Inside a container that
    // settles it; outside, the gateway may still run in one (OpenClaw's Docker
    // setup mounts the host's state), so an omitted bind stays unknown.
    const inContainer = (deps.isContainer ?? (() => detectContainer(deps.env, nodeFiles)))();
    gateway = assessGatewayExposure(config.status === "ok" ? (config.config as object) : {}, {
      ...(inContainer ? { isContainer: true } : {}),
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
  let skills = assessRiskySkills(
    {
      stateDir: locations.stateDir,
      homeDir: locations.homeDir,
      osHomeDir: locations.osHomeDir,
      ...(locations.workspaceDir === undefined ? {} : { workspaceDir: locations.workspaceDir }),
    },
    config,
  );
  if (locations.workspaceDir === undefined) {
    // OpenClaw refuses an invalid OPENCLAW_PROFILE, so its workspace is unknown.
    skills = {
      ...skills,
      grade: skills.grade === "pass" ? "unknown" : skills.grade,
      unknown: [...skills.unknown, { path: "OPENCLAW_PROFILE workspace", reason: "unreadable" }],
    };
  }

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
