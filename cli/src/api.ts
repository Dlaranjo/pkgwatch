/**
 * Re-export API client from shared package.
 *
 * This ensures backward compatibility for consumers importing from '@pkgwatch/cli/api'.
 */
export {
  // Client
  PkgWatchClient,
  ApiClientError,
  // Types
  type PackageHealth,
  type PackageHealthFull,
  type ScanResult,
  type UsageStats,
  type AbandonmentRisk,
  type HealthComponents,
  type Confidence,
  type Signals,
  type RiskLevel,
  type ErrorCode,
  type ClientOptions,
  // Utilities
  getRiskColor,
  formatBytes,
} from "@pkgwatch/api-client";
