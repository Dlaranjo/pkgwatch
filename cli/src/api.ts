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
} from "@pkgwatch/api-client";
