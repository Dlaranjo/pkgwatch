/**
 * Re-export API client from shared package.
 *
 * This replaces the previously duplicated code with a shared implementation.
 */
export {
  // Client
  PkgWatchClient,
  ApiClientError,
  // Types
  type PackageHealth,
  type ScanResult,
  type AbandonmentRisk,
  type RiskLevel,
  type ErrorCode,
} from "@pkgwatch/api-client";
