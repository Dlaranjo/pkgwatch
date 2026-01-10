import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import * as core from "@actions/core";
import { DepHealthClient, ScanResult, PackageHealth, ApiClientError } from "./api";

const BATCH_SIZE = 25;

export async function scanDependencies(
  apiKey: string,
  basePath: string,
  includeDev: boolean
): Promise<ScanResult> {
  const packagePath = basePath.endsWith(".json")
    ? resolve(basePath)
    : resolve(basePath, "package.json");

  if (!existsSync(packagePath)) {
    throw new Error(
      `Cannot find package.json at ${packagePath}\n\nEnsure the 'working-directory' input is correct.`
    );
  }

  const content = readFileSync(packagePath, "utf-8");

  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(content);
  } catch {
    throw new Error(
      `Invalid JSON in package.json at ${packagePath}\n\nEnsure the file contains valid JSON.`
    );
  }

  const dependencies: Record<string, string> = {
    ...(pkg.dependencies || {}),
    ...(includeDev ? pkg.devDependencies || {} : {}),
  };

  const depCount = Object.keys(dependencies).length;

  if (depCount === 0) {
    core.info("No dependencies found in package.json");
    return { total: 0, critical: 0, high: 0, medium: 0, low: 0, packages: [] };
  }

  core.info(`Found ${depCount} dependencies, analyzing health scores...`);

  const client = new DepHealthClient(apiKey);

  // Batch processing for large dependency lists to avoid timeouts
  if (depCount <= BATCH_SIZE) {
    // Small enough to process in one request
    try {
      return await client.scan(dependencies);
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
      const batchResult = await client.scan(batchDeps);
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
  };
}
