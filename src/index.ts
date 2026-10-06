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
