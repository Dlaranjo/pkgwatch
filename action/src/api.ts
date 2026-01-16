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
  // Dependency parsing
  type Ecosystem,
  type ParseResult,
  DependencyParseError,
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
