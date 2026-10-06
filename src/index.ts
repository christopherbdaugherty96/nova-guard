export const productName = "nova-guard";

export { assessGatewayExposure } from "./checks/gateway-exposure.js";
export type {
  GatewayExposureResult,
  GatewayRuntimeContext,
} from "./checks/gateway-exposure.js";
export { assessOpenClawVersion } from "./checks/version-advisories.js";
export type {
  BundledAdvisory,
  VersionAdvisoryResult,
} from "./checks/version-advisories.js";
export {
  advisoryDataDate,
  advisoryDataSource,
  bundledAdvisories,
} from "./data/openclaw-advisories.js";
export {
  assessPlaintextSecrets,
  isSecretLikeName,
  nodeSecretFileReader,
} from "./checks/plaintext-secrets.js";
export type {
  PlaintextSecretsResult,
  SecretFileReader,
  SecretFinding,
  SecretLocations,
} from "./checks/plaintext-secrets.js";
export { assessRiskySkills, nodeSkillFs } from "./checks/risky-skills.js";
export type {
  RiskySkillFinding,
  RiskySkillsResult,
  SkillConfigInput,
  SkillFs,
  SkillLocations,
  SkillUnknownReason,
} from "./checks/risky-skills.js";
