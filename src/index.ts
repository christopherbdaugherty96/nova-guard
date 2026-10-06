export const productName = "nova-guard";

export { assessGatewayExposure } from "./checks/gateway-exposure.js";
export type {
  GatewayExposureResult,
  GatewayRuntimeContext,
} from "./checks/gateway-exposure.js";
export {
  advisoryDataDate,
  assessOpenClawVersion,
  bundledAdvisories,
} from "./checks/version-advisories.js";
export type {
  VersionAdvisory,
  VersionAdvisoryResult,
} from "./checks/version-advisories.js";
