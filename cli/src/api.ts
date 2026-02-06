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
  type ReferralStatus,
  type ReferralStats,
  type ReferralEntry,
  type AddReferralCodeResponse,
  type AbandonmentRisk,
  type HealthComponents,
  type Confidence,
  type Signals,
  type RiskLevel,
  type ErrorCode,
  type ClientOptions,
  type CollectingResponse,
  isCollectingResponse,
  // Utilities
  getRiskColor,
  formatBytes,
  // Dependency parsing
  type Ecosystem,
  type DependencyFormat,
  type DependencyFile,
  type ParseResult,
  DependencyParseError,
  detectDependencyFile,
  parsePackageJson,
  parseRequirementsTxt,
  parsePyprojectToml,
  parsePipfile,
  readDependencies,
  readDependenciesFromFile,
  // Discovery and repo scanning
  type DiscoveryOptions,
  type DiscoveredManifest,
  type DiscoveryResult,
  type ManifestStatus,
  type ManifestScanResult,
  type RepoScanSummary,
  type RepoScanResult,
  type RepoScanOptions,
  DEFAULT_EXCLUDES,
  discoverManifests,
  scanRepository,
  previewRepoScan,
} from "@pkgwatch/api-client";
