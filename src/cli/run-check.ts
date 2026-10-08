import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import { assessGatewayExposure, type GatewayExposureResult } from "../checks/gateway-exposure.js";
import {
  assessPlaintextSecrets,
  nodeSecretFileReader,
  parseDotEnv,
  type PlaintextSecretsResult,
} from "../checks/plaintext-secrets.js";
import { assessRiskySkills, configuredAgentDirs } from "../checks/risky-skills.js";
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
function isInside(base: string, file: string): boolean {
  const relative = path.relative(base, file);
  return relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

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
  if (locations.stateDir) {
    try {
      stateIsDirectory = statSync(locations.stateDir).isDirectory();
    } catch {
      stateIsDirectory = false;
    }
  }
  // Without OpenClaw's state directory nothing here can be verified as
  // OpenClaw's: every check still runs (an explicit config, ~/.agents/skills,
  // OPENCLAW_WORKSPACE_DIR, and ~/.config/openclaw/gateway.env are still read)
  // and keeps its findings, but none of them is graded pass.
  const noState = "No OpenClaw state directory was found, so this could not be checked.";
  let gateway: GatewayExposureResult;
  if (!stateIsDirectory && config.status === "missing") {
    gateway = { grade: "unknown", bind: "unknown", auth: "unrecognized", summary: noState };
  } else if (config.status === "unreadable") {
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
      ...(locations.stateDir ? [path.join(locations.stateDir, ".env")] : []),
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

  // OpenClaw's audit also reads models.json in configured agent directories and
  // in OPENCLAW_AGENT_DIR / PI_CODING_AGENT_DIR (listAgentModelsJsonPaths).
  const agentDirs = configuredAgentDirs(locations, config);
  // Every configured directory is read (duplicates are dropped by the check);
  // the card itself leaves <stateDir>/agents paths to its own redaction.
  const extraAgentDirs = [...agentDirs.dirs];
  let unverifiableAgentDirs = agentDirs.unverifiable;
  const overrideDir = deps.env.OPENCLAW_AGENT_DIR?.trim() || deps.env.PI_CODING_AGENT_DIR?.trim();
  if (overrideDir) {
    const needsHome = /^~(?=$|[\\/])/.test(overrideDir);
    const expanded = needsHome && locations.homeDirKnown !== false
      ? overrideDir.replace(/^~(?=$|[\\/])/, () => locations.homeDir)
      : overrideDir;
    if ((!needsHome || locations.homeDirKnown !== false) && path.isAbsolute(expanded)) extraAgentDirs.push(path.resolve(expanded));
    else unverifiableAgentDirs += 1;
  }
  let secrets = assessPlaintextSecrets({
    stateDir: locations.stateDir,
    configPath: locations.configPath,
    homeDir: locations.homeDir,
    ...(locations.homeDirKnown === false ? { homeDirKnown: false as const } : {}),
    includeRoots: locations.includeRoots,
    agentDirs: extraAgentDirs,
  });
  if (locations.homeDirKnown === false) {
    const unresolvedHomeSecret = locations.stateDir
      ? path.join(locations.stateDir, "unresolved-home", "gateway.env")
      : "OpenClaw home gateway.env";
    secrets = {
      ...secrets,
      unreadable: [...secrets.unreadable, unresolvedHomeSecret],
      ...(secrets.grade === "pass"
        ? { grade: "unknown" as const, summary: "The OpenClaw home could not be resolved, so plaintext secrets could not be ruled out." }
        : {}),
    };
  }
  if (unverifiableAgentDirs > 0) {
    const unresolvedModels = Array.from({ length: unverifiableAgentDirs }, (_, index) =>
      locations.stateDir
        ? path.join(locations.stateDir, "agents", `unresolved-${index + 1}`, "models.json")
        : `OpenClaw state agent ${index + 1} models.json`,
    );
    secrets = {
      ...secrets,
      unreadable: [...secrets.unreadable, ...unresolvedModels],
      ...(secrets.grade === "pass"
        ? {
            grade: "unknown" as const,
            summary: "An agent directory could not be resolved, so plaintext secrets could not be ruled out.",
          }
        : {}),
    };
  }
  let skills = assessRiskySkills(
    {
      stateDir: locations.stateDir,
      homeDir: locations.homeDir,
      ...(locations.homeDirKnown === false ? { homeDirKnown: false as const } : {}),
      osHomeDir: locations.osHomeDir,
      ...(locations.workspaceDir === undefined ? {} : { workspaceDir: locations.workspaceDir }),
    },
    config,
  );
  if (locations.osHomeDir === undefined) {
    // OpenClaw's personal skills root is ~/.agents/skills under the OS home,
    // which could not be verified, so that root is unknown.
    skills = {
      ...skills,
      grade: skills.grade === "pass" ? "unknown" : skills.grade,
      unknown: [...skills.unknown, { path: "OS home .agents/skills", reason: "unreadable" }],
    };
  }
  if (locations.workspaceDir === undefined) {
    // OpenClaw refuses an invalid OPENCLAW_PROFILE, so its workspace is unknown.
    skills = {
      ...skills,
      grade: skills.grade === "pass" ? "unknown" : skills.grade,
      unknown: [...skills.unknown, { path: "OPENCLAW_PROFILE workspace", reason: "unreadable" }],
    };
  }

  if (!stateIsDirectory) {
    if (gateway.grade === "pass") gateway = { ...gateway, grade: "unknown", summary: noState };
    if (secrets.grade === "pass") secrets = { ...secrets, grade: "unknown", summary: noState };
    if (skills.grade === "pass") skills = { ...skills, grade: "unknown", summary: noState };
  }

  return renderReportCard({
    homeDir: locations.homeDir,
    osHomeDir: locations.osHomeDir,
    stateDir: locations.stateDir,
    configPath: locations.configPath,
    agentDirs: extraAgentDirs,
    toolVersion,
    advisoryDataDate,
    gateway,
    version,
    secrets,
    skills,
  });
}
