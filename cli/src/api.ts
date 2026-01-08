/**
 * Re-export API client from shared package.
 *
 * This ensures backward compatibility for consumers importing from '@dephealth/cli/api'.
 */
export {
  // Client
  DepHealthClient,
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
} from "@dephealth/api-client";
