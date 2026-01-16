/**
 * Repository Scanner Module
 *
 * Scans an entire repository for dependency health by discovering all
 * manifest files and aggregating results.
 */

import {
  discoverManifests,
  type DiscoveredManifest,
  type DiscoveryOptions,
} from "./discovery.js";
import {
  readDependenciesFromFile,
  DependencyParseError,
  type Ecosystem,
} from "./dependencies.js";
import {
  PkgWatchClient,
  ApiClientError,
  type PackageHealth,
  type ScanResult,
} from "./index.js";

// ===========================================
// Types
// ===========================================

export type ManifestStatus = "success" | "parse_error" | "api_error" | "rate_limited" | "skipped";

export interface ManifestScanResult {
  /** The manifest that was scanned */
  manifest: DiscoveredManifest;
  /** Status of this manifest's scan */
  status: ManifestStatus;
  /** Error message if status != success */
  error?: string;
  /** Health results for packages in this manifest */
  packages?: PackageHealth[];
  /** Packages that were not found in the registry */
  notFound?: string[];
  /** Risk level counts for this manifest */
  counts?: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface RepoScanSummary {
  /** Total number of manifest files discovered */
  totalManifests: number;
  /** Number of manifests successfully scanned */
  successfulManifests: number;
  /** Number of manifests that failed to scan */
  failedManifests: number;
  /** Total packages scanned (may include duplicates across manifests) */
  totalPackages: number;
  /** Unique packages after deduplication */
  uniquePackages: number;
  /** Counts by risk level (deduplicated) */
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface RepoScanResult {
  /** Results for each manifest file */
  manifests: ManifestScanResult[];
  /** Aggregated summary */
  summary: RepoScanSummary;
  /** True if maxManifests limit was reached */
  truncated: boolean;
  /** True if scan stopped due to rate limiting */
  rateLimited: boolean;
  /** Number of API requests used (unique packages scanned) */
  quotaUsed: number;
  /** Remaining quota after scan (if available from API) */
  quotaRemaining?: number;
  /** Discovery warnings (e.g., permission issues) */
  warnings: string[];
}

export interface RepoScanOptions {
  /** Base path to scan (usually repository root) */
  basePath: string;
  /** API key for PkgWatch */
  apiKey: string;
  /** Include dev dependencies (default: true) */
  includeDev?: boolean;
  /** Glob patterns to exclude */
  excludePatterns?: string[];
  /** Maximum manifest files to scan (default: 100) */
  maxManifests?: number;
  /** Maximum directory depth (default: 10) */
  maxDepth?: number;
  /** Follow workspace definitions (default: true) */
  followWorkspaces?: boolean;
  /** API client options */
  clientOptions?: {
    baseUrl?: string;
    timeout?: number;
    maxRetries?: number;
  };
  /** Progress callback */
  onProgress?: (current: number, total: number, manifest: string) => void;
}

// ===========================================
// Internal Types
// ===========================================

interface ParsedManifest {
  manifest: DiscoveredManifest;
  dependencies: Record<string, string>;
}

interface PackageLocation {
  packageName: string;
  manifests: DiscoveredManifest[];
}

// ===========================================
// Helper Functions
// ===========================================

/**
 * Parse a manifest file and extract dependencies
 */
function parseManifest(
  manifest: DiscoveredManifest,
  includeDev: boolean
): { dependencies: Record<string, string>; error?: string } {
  try {
    const result = readDependenciesFromFile(manifest.path, includeDev);
    return { dependencies: result.dependencies };
  } catch (err) {
    if (err instanceof DependencyParseError) {
      return { dependencies: {}, error: err.message };
    }
    return {
      dependencies: {},
      error: err instanceof Error ? err.message : "Unknown parse error",
    };
  }
}

/**
 * Group packages by ecosystem and track which manifests contain each package
 */
function groupByEcosystem(
  parsedManifests: ParsedManifest[]
): {
  npm: Map<string, DiscoveredManifest[]>;
  pypi: Map<string, DiscoveredManifest[]>;
} {
  const npm = new Map<string, DiscoveredManifest[]>();
  const pypi = new Map<string, DiscoveredManifest[]>();

  for (const { manifest, dependencies } of parsedManifests) {
    const targetMap = manifest.ecosystem === "npm" ? npm : pypi;

    for (const packageName of Object.keys(dependencies)) {
      const existing = targetMap.get(packageName);
      if (existing) {
        existing.push(manifest);
      } else {
        targetMap.set(packageName, [manifest]);
      }
    }
  }

  return { npm, pypi };
}

/**
 * Create a map from package name to health result
 */
function createHealthMap(result: ScanResult): Map<string, PackageHealth> {
  const map = new Map<string, PackageHealth>();
  for (const pkg of result.packages) {
    map.set(pkg.package, pkg);
  }
  return map;
}

/**
 * Count risk levels in a list of packages
 */
function countRiskLevels(packages: PackageHealth[]): {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
} {
  return {
    total: packages.length,
    critical: packages.filter((p) => p.risk_level === "CRITICAL").length,
    high: packages.filter((p) => p.risk_level === "HIGH").length,
    medium: packages.filter((p) => p.risk_level === "MEDIUM").length,
    low: packages.filter((p) => p.risk_level === "LOW").length,
  };
}

// ===========================================
// Main Entry Point
// ===========================================

/**
 * Scan an entire repository for dependency health.
 *
 * Discovers all manifest files, parses dependencies, calls the PkgWatch API,
 * and aggregates results.
 *
 * @param options - Scan options
 * @returns Aggregated scan results
 */
export async function scanRepository(options: RepoScanOptions): Promise<RepoScanResult> {
  const {
    basePath,
    apiKey,
    includeDev = true,
    excludePatterns,
    maxManifests = 100,
    maxDepth = 10,
    followWorkspaces = true,
    clientOptions = {},
    onProgress,
  } = options;

  // Initialize result structure
  const manifestResults: ManifestScanResult[] = [];
  const warnings: string[] = [];
  let rateLimited = false;
  let quotaUsed = 0;
  let quotaRemaining: number | undefined;

  // Step 1: Discover manifest files
  const discoveryOptions: DiscoveryOptions = {
    basePath,
    excludePatterns,
    maxManifests,
    maxDepth,
    followWorkspaces,
  };

  const discovery = discoverManifests(discoveryOptions);
  warnings.push(...discovery.warnings);

  if (discovery.manifests.length === 0) {
    return {
      manifests: [],
      summary: {
        totalManifests: 0,
        successfulManifests: 0,
        failedManifests: 0,
        totalPackages: 0,
        uniquePackages: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      },
      truncated: discovery.truncated,
      rateLimited: false,
      quotaUsed: 0,
      warnings,
    };
  }

  // Step 2: Parse all manifests
  const parsedManifests: ParsedManifest[] = [];
  const parseFailures: ManifestScanResult[] = [];

  for (const manifest of discovery.manifests) {
    const { dependencies, error } = parseManifest(manifest, includeDev);

    if (error) {
      parseFailures.push({
        manifest,
        status: "parse_error",
        error,
      });
    } else if (Object.keys(dependencies).length === 0) {
      // Empty manifest - still success but no packages
      manifestResults.push({
        manifest,
        status: "success",
        packages: [],
        notFound: [],
        counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
      });
    } else {
      parsedManifests.push({ manifest, dependencies });
    }
  }

  // Add parse failures to results
  manifestResults.push(...parseFailures);

  // Step 3: Group packages by ecosystem (for deduplication)
  const { npm: npmPackages, pypi: pypiPackages } = groupByEcosystem(parsedManifests);

  // Track unique package count
  const uniquePackageCount = npmPackages.size + pypiPackages.size;
  quotaUsed = uniquePackageCount;

  // Step 4: Call API for each ecosystem
  const client = new PkgWatchClient(apiKey, clientOptions);

  // Results maps for each ecosystem
  const npmHealthMap = new Map<string, PackageHealth>();
  const pypiHealthMap = new Map<string, PackageHealth>();
  const npmNotFound = new Set<string>();
  const pypiNotFound = new Set<string>();

  // Track progress across scans
  let progressCount = 0;
  const npmManifestCount = parsedManifests.filter((m) => m.manifest.ecosystem === "npm").length;
  const pypiManifestCount = parsedManifests.filter((m) => m.manifest.ecosystem === "pypi").length;

  // Scan npm packages
  if (npmPackages.size > 0) {
    onProgress?.(progressCount, parsedManifests.length, "Scanning npm packages...");

    const npmDeps: Record<string, string> = {};
    for (const [name] of npmPackages) {
      npmDeps[name] = "*"; // Version doesn't matter for health lookup
    }

    try {
      const result = await client.scan(npmDeps, "npm");

      // Store results in map
      for (const pkg of result.packages) {
        npmHealthMap.set(pkg.package, pkg);
      }

      // Track not found
      if (result.not_found) {
        for (const name of result.not_found) {
          npmNotFound.add(name);
        }
      }

      // Update progress after npm scan completes
      progressCount += npmManifestCount;
      onProgress?.(progressCount, parsedManifests.length, "npm scan complete");
    } catch (err) {
      if (err instanceof ApiClientError) {
        if (err.code === "rate_limited") {
          rateLimited = true;
          // Mark all npm manifests as rate limited
          for (const { manifest } of parsedManifests) {
            if (manifest.ecosystem === "npm") {
              manifestResults.push({
                manifest,
                status: "rate_limited",
                error: "Rate limit exceeded",
              });
            }
          }
        } else {
          // Other API error - mark npm manifests as failed
          for (const { manifest } of parsedManifests) {
            if (manifest.ecosystem === "npm") {
              manifestResults.push({
                manifest,
                status: "api_error",
                error: err.message,
              });
            }
          }
        }
      } else {
        // Unexpected error - mark npm manifests as failed
        const errorMessage = err instanceof Error ? err.message : "Unknown error";
        for (const { manifest } of parsedManifests) {
          if (manifest.ecosystem === "npm") {
            manifestResults.push({
              manifest,
              status: "api_error",
              error: `Unexpected error: ${errorMessage}`,
            });
          }
        }
        warnings.push(`Unexpected error during npm scan: ${errorMessage}`);
      }
    }
  }

  // Scan pypi packages (if not rate limited)
  if (pypiPackages.size > 0 && !rateLimited) {
    onProgress?.(progressCount, parsedManifests.length, "Scanning PyPI packages...");

    const pypiDeps: Record<string, string> = {};
    for (const [name] of pypiPackages) {
      pypiDeps[name] = "*";
    }

    try {
      const result = await client.scan(pypiDeps, "pypi");

      // Store results in map
      for (const pkg of result.packages) {
        pypiHealthMap.set(pkg.package, pkg);
      }

      // Track not found
      if (result.not_found) {
        for (const name of result.not_found) {
          pypiNotFound.add(name);
        }
      }

      // Update progress after pypi scan completes
      progressCount += pypiManifestCount;
      onProgress?.(progressCount, parsedManifests.length, "pypi scan complete");
    } catch (err) {
      if (err instanceof ApiClientError) {
        if (err.code === "rate_limited") {
          rateLimited = true;
          // Mark all pypi manifests as rate limited
          for (const { manifest } of parsedManifests) {
            if (manifest.ecosystem === "pypi") {
              manifestResults.push({
                manifest,
                status: "rate_limited",
                error: "Rate limit exceeded",
              });
            }
          }
        } else {
          // Other API error
          for (const { manifest } of parsedManifests) {
            if (manifest.ecosystem === "pypi") {
              manifestResults.push({
                manifest,
                status: "api_error",
                error: err.message,
              });
            }
          }
        }
      } else {
        // Unexpected error - mark pypi manifests as failed
        const errorMessage = err instanceof Error ? err.message : "Unknown error";
        for (const { manifest } of parsedManifests) {
          if (manifest.ecosystem === "pypi") {
            manifestResults.push({
              manifest,
              status: "api_error",
              error: `Unexpected error: ${errorMessage}`,
            });
          }
        }
        warnings.push(`Unexpected error during pypi scan: ${errorMessage}`);
      }
    }
  } else if (pypiPackages.size > 0 && rateLimited) {
    // Mark pypi manifests as rate limited
    for (const { manifest } of parsedManifests) {
      if (manifest.ecosystem === "pypi") {
        manifestResults.push({
          manifest,
          status: "rate_limited",
          error: "Rate limit exceeded (from npm scan)",
        });
      }
    }
  }

  // Step 5: Map results back to manifests
  for (const { manifest, dependencies } of parsedManifests) {
    // Skip if already added (due to error)
    if (manifestResults.some((r) => r.manifest.path === manifest.path)) {
      continue;
    }

    const healthMap = manifest.ecosystem === "npm" ? npmHealthMap : pypiHealthMap;
    const notFoundSet = manifest.ecosystem === "npm" ? npmNotFound : pypiNotFound;

    const packages: PackageHealth[] = [];
    const notFound: string[] = [];

    for (const packageName of Object.keys(dependencies)) {
      const health = healthMap.get(packageName);
      if (health) {
        packages.push(health);
      } else if (notFoundSet.has(packageName)) {
        notFound.push(packageName);
      }
    }

    manifestResults.push({
      manifest,
      status: "success",
      packages,
      notFound,
      counts: countRiskLevels(packages),
    });
  }

  // Step 6: Calculate summary
  const successfulManifests = manifestResults.filter((r) => r.status === "success");
  const failedManifests = manifestResults.filter((r) => r.status !== "success");

  // Get all unique packages for summary counts
  const allUniquePackages: PackageHealth[] = [];
  const seenPackages = new Set<string>();

  for (const result of successfulManifests) {
    if (result.packages) {
      for (const pkg of result.packages) {
        const key = `${result.manifest.ecosystem}:${pkg.package}`;
        if (!seenPackages.has(key)) {
          seenPackages.add(key);
          allUniquePackages.push(pkg);
        }
      }
    }
  }

  const summaryCounts = countRiskLevels(allUniquePackages);

  // Calculate total packages (with duplicates)
  let totalPackages = 0;
  for (const result of successfulManifests) {
    if (result.counts) {
      totalPackages += result.counts.total;
    }
  }

  // Sort manifest results by path for consistent output
  manifestResults.sort((a, b) => a.manifest.relativePath.localeCompare(b.manifest.relativePath));

  return {
    manifests: manifestResults,
    summary: {
      totalManifests: discovery.manifests.length,
      successfulManifests: successfulManifests.length,
      failedManifests: failedManifests.length,
      totalPackages,
      uniquePackages: uniquePackageCount,
      ...summaryCounts,
    },
    truncated: discovery.truncated,
    rateLimited,
    quotaUsed,
    quotaRemaining,
    warnings,
  };
}

/**
 * Get a preview of what would be scanned without making API calls.
 * Useful for showing users what will be scanned and quota usage.
 */
export function previewRepoScan(options: Omit<RepoScanOptions, "apiKey">): {
  manifests: DiscoveredManifest[];
  packageCounts: { npm: number; pypi: number; total: number };
  truncated: boolean;
  warnings: string[];
} {
  const {
    basePath,
    includeDev = true,
    excludePatterns,
    maxManifests = 100,
    maxDepth = 10,
    followWorkspaces = true,
  } = options;

  const discovery = discoverManifests({
    basePath,
    excludePatterns,
    maxManifests,
    maxDepth,
    followWorkspaces,
  });

  // Parse manifests to count packages
  const npmPackages = new Set<string>();
  const pypiPackages = new Set<string>();

  for (const manifest of discovery.manifests) {
    const { dependencies } = parseManifest(manifest, includeDev);
    const targetSet = manifest.ecosystem === "npm" ? npmPackages : pypiPackages;

    for (const name of Object.keys(dependencies)) {
      targetSet.add(name);
    }
  }

  return {
    manifests: discovery.manifests,
    packageCounts: {
      npm: npmPackages.size,
      pypi: pypiPackages.size,
      total: npmPackages.size + pypiPackages.size,
    },
    truncated: discovery.truncated,
    warnings: discovery.warnings,
  };
}
