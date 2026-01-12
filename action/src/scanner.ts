import { resolve } from "node:path";
import { statSync, existsSync } from "node:fs";
import * as core from "@actions/core";
import {
  PkgWatchClient,
  ScanResult,
  PackageHealth,
  ApiClientError,
  readDependencies,
  readDependenciesFromFile,
  DependencyParseError,
  Ecosystem,
} from "./api";

const BATCH_SIZE = 25;

export interface ScanOptions {
  apiKey: string;
  basePath: string;
  includeDev: boolean;
  ecosystemOverride?: Ecosystem;
}

export interface ScanResultWithMeta extends ScanResult {
  /** The dependency file format that was scanned */
  format: string;
  /** The detected ecosystem */
  ecosystem: string;
}

export async function scanDependencies(
  apiKey: string,
  basePath: string,
  includeDev: boolean,
  ecosystemOverride?: Ecosystem
): Promise<ScanResultWithMeta> {
  // Determine if basePath is a file or directory and read dependencies
  let dependencies: Record<string, string>;
  let ecosystem: Ecosystem;
  let format: string;

  try {
    const resolvedPath = resolve(basePath);

    // Check if path exists
    if (!existsSync(resolvedPath)) {
      throw new DependencyParseError(`Path does not exist: ${resolvedPath}`);
    }

    // Use stat to properly determine if path is a file or directory
    const stats = statSync(resolvedPath);
    if (stats.isFile()) {
      const result = readDependenciesFromFile(resolvedPath, includeDev);
      dependencies = result.dependencies;
      ecosystem = result.ecosystem;
      format = result.format;
    } else if (stats.isDirectory()) {
      const result = readDependencies(resolvedPath, includeDev);
      dependencies = result.dependencies;
      ecosystem = result.ecosystem;
      format = result.format;
    } else {
      throw new DependencyParseError(`Path is not a file or directory: ${resolvedPath}`);
    }
  } catch (err) {
    if (err instanceof DependencyParseError) {
      throw new Error(
        `${err.message}\n\nEnsure the 'working-directory' input points to a directory containing a supported dependency file.`
      );
    }
    throw err;
  }

  // Allow ecosystem override
  if (ecosystemOverride) {
    ecosystem = ecosystemOverride;
    core.debug(`Ecosystem overridden to ${ecosystem}`);
  }

  const depCount = Object.keys(dependencies).length;

  if (depCount === 0) {
    core.info(`No dependencies found in ${format}`);
    return { total: 0, critical: 0, high: 0, medium: 0, low: 0, packages: [], format, ecosystem };
  }

  core.info(`Found ${depCount} ${ecosystem} dependencies in ${format}, analyzing health scores...`);

  const client = new PkgWatchClient(apiKey);

  // Batch processing for large dependency lists to avoid timeouts
  if (depCount <= BATCH_SIZE) {
    // Small enough to process in one request
    try {
      const result = await client.scan(dependencies, ecosystem);
      return { ...result, format, ecosystem };
    } catch (error) {
      // For single batch, we can't recover - rethrow with context
      if (error instanceof ApiClientError) {
        throw error;
      }
      throw new Error(`Failed to scan dependencies: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Process in batches
  const depEntries = Object.entries(dependencies);
  const allPackages: PackageHealth[] = [];
  let notFound: string[] = [];

  let failedBatches = 0;

  for (let i = 0; i < depEntries.length; i += BATCH_SIZE) {
    const batchNum = Math.floor(i / BATCH_SIZE) + 1;
    const totalBatches = Math.ceil(depEntries.length / BATCH_SIZE);
    core.info(`Processing batch ${batchNum}/${totalBatches}...`);

    const batchEntries = depEntries.slice(i, Math.min(i + BATCH_SIZE, depEntries.length));
    const batchDeps = Object.fromEntries(batchEntries);

    try {
      const batchResult = await client.scan(batchDeps, ecosystem);
      allPackages.push(...batchResult.packages);
      if (batchResult.not_found) {
        notFound.push(...batchResult.not_found);
      }
    } catch (error) {
      // Fail immediately on rate limit or auth errors - no point retrying more batches
      if (error instanceof ApiClientError) {
        if (error.code === "rate_limited" || error.code === "unauthorized" || error.code === "forbidden") {
          throw error;
        }
      }

      failedBatches++;
      const packageNames = batchEntries.map(([name]) => name);
      const errorMessage = error instanceof Error ? error.message : String(error);
      core.warning(`Batch ${batchNum} failed: ${errorMessage}. Packages: ${packageNames.slice(0, 5).join(", ")}${packageNames.length > 5 ? ` and ${packageNames.length - 5} more` : ""}`);
      // Continue with remaining batches instead of failing entirely
    }
  }

  if (failedBatches > 0) {
    core.warning(`${failedBatches} batch(es) failed. Results may be incomplete.`);
  }

  // Aggregate results
  return {
    total: allPackages.length,
    critical: allPackages.filter((p: PackageHealth) => p.risk_level === "CRITICAL").length,
    high: allPackages.filter((p: PackageHealth) => p.risk_level === "HIGH").length,
    medium: allPackages.filter((p: PackageHealth) => p.risk_level === "MEDIUM").length,
    low: allPackages.filter((p: PackageHealth) => p.risk_level === "LOW").length,
    packages: allPackages,
    not_found: notFound.length > 0 ? notFound : undefined,
    format,
    ecosystem,
  };
}
