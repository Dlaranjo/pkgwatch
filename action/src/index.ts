import * as core from "@actions/core";
import * as path from "node:path";
import { scanDependencies } from "./scanner";
import { generateSummary, generateRepoSummary } from "./summary";
import {
  ApiClientError,
  scanRepository,
  DEFAULT_EXCLUDES,
  type RepoScanResult,
} from "./api";

type ScanMode = "single" | "recursive";

async function run(): Promise<void> {
  try {
    // Get and mask API key immediately (security)
    const apiKey = core.getInput("api-key", { required: true });
    core.setSecret(apiKey);

    const workingDirectory = core.getInput("working-directory") || ".";
    const scanMode = (core.getInput("scan-mode")?.toLowerCase() || "single") as ScanMode;
    const excludePatternsInput = core.getInput("exclude-patterns") || "";
    const maxManifests = parseInt(core.getInput("max-manifests") || "100", 10);
    const failOn = core.getInput("fail-on")?.toUpperCase() || "";
    const includeDev = !["false", "no", "0"].includes(core.getInput("include-dev")?.toLowerCase() || "");
    const softFail = ["true", "yes", "1"].includes(core.getInput("soft-fail")?.toLowerCase() || "");

    // Validate scan-mode
    if (!["single", "recursive"].includes(scanMode)) {
      core.setFailed(
        `Invalid 'scan-mode' value: ${scanMode}\n\nValid options: single, recursive`
      );
      return;
    }

    // Validate fail-on
    if (failOn && !["HIGH", "CRITICAL"].includes(failOn)) {
      core.setFailed(
        `Invalid 'fail-on' value: ${failOn}\n\nValid options: HIGH, CRITICAL, or empty (never fail)`
      );
      return;
    }

    // Validate max-manifests
    if (isNaN(maxManifests) || maxManifests < 1 || maxManifests > 1000) {
      core.setFailed(
        `Invalid 'max-manifests' value: ${core.getInput("max-manifests")}\n\nMust be a number between 1 and 1000`
      );
      return;
    }

    // Validate working directory (security - prevent path traversal)
    const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
    const resolvedPath = path.resolve(workspace, workingDirectory);
    const relativePath = path.relative(workspace, resolvedPath);
    if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
      core.setFailed("working-directory must be within the repository");
      return;
    }

    // Run scan based on mode
    if (scanMode === "recursive") {
      await runRecursiveScan({
        apiKey,
        resolvedPath,
        excludePatternsInput,
        maxManifests,
        includeDev,
        failOn,
        softFail,
      });
    } else {
      await runSingleScan({
        apiKey,
        resolvedPath,
        includeDev,
        failOn,
        softFail,
      });
    }
  } catch (error) {
    handleError(error);
  }
}

interface SingleScanOptions {
  apiKey: string;
  resolvedPath: string;
  includeDev: boolean;
  failOn: string;
  softFail: boolean;
}

async function runSingleScan(options: SingleScanOptions): Promise<void> {
  const { apiKey, resolvedPath, includeDev, failOn, softFail } = options;

  core.info(`Scanning dependencies in ${resolvedPath}`);

  // Run scan
  const result = await scanDependencies(apiKey, resolvedPath, includeDev);

  // Determine highest risk
  const highestRisk =
    result.critical > 0
      ? "CRITICAL"
      : result.high > 0
        ? "HIGH"
        : result.medium > 0
          ? "MEDIUM"
          : result.low > 0
            ? "LOW"
            : "NONE";

  const hasIssues = result.critical > 0 || result.high > 0;

  // Check threshold
  let failed = false;
  if (failOn === "CRITICAL" && result.critical > 0) {
    failed = true;
  } else if (failOn === "HIGH" && hasIssues) {
    failed = true;
  }

  // Set outputs
  core.setOutput("total", result.total);
  core.setOutput("critical", result.critical);
  core.setOutput("high", result.high);
  core.setOutput("medium", result.medium);
  core.setOutput("low", result.low);
  core.setOutput("has-issues", hasIssues);
  core.setOutput("highest-risk", highestRisk);
  core.setOutput("failed", failed);
  core.setOutput("not-found-count", result.not_found?.length || 0);
  core.setOutput("results", JSON.stringify(result));

  // Set recursive-mode outputs to empty/default values
  core.setOutput("manifests-scanned", 1);
  core.setOutput("manifests-failed", 0);
  core.setOutput("per-manifest-results", "{}");
  core.setOutput("truncated", false);

  // Warn about packages that couldn't be found
  if (result.not_found && result.not_found.length > 0) {
    const maxToShow = 10;
    const shown = result.not_found.slice(0, maxToShow);
    const remaining = result.not_found.length - shown.length;
    const suffix = remaining > 0 ? ` (and ${remaining} more)` : "";
    core.warning(
      `${result.not_found.length} package(s) not found in registry: ${shown.join(", ")}${suffix}`
    );
  }

  // Generate job summary
  await generateSummary(result, failed, failOn);

  // Add annotations for high-risk packages
  for (const pkg of result.packages) {
    if (pkg.risk_level === "CRITICAL" || pkg.risk_level === "HIGH") {
      const safeName = sanitizeForAnnotation(pkg.package);
      const riskFactor = pkg.abandonment_risk?.risk_factors?.[0];
      const reason = riskFactor ? ` - ${sanitizeForAnnotation(riskFactor)}` : "";
      core.warning(
        `${safeName}: ${pkg.risk_level} risk (score: ${pkg.health_score}/100)${reason}`,
        {
          title: pkg.risk_level === "CRITICAL" ? "Critical Dependency Risk" : "High Dependency Risk",
          file: result.format,
        }
      );
    }
  }

  // Log summary
  core.info(
    `Scan complete: ${result.total} packages (${result.critical} critical, ${result.high} high, ${result.medium} medium, ${result.low} low)`
  );

  // Exit based on threshold
  if (failed && !softFail) {
    core.setFailed(
      `Found ${result.critical} CRITICAL and ${result.high} HIGH risk packages (threshold: ${failOn})`
    );
  } else if (failed && softFail) {
    core.warning(
      `Found ${result.critical} CRITICAL and ${result.high} HIGH risk packages (threshold: ${failOn}) - soft-fail mode`
    );
  }
}

interface RecursiveScanOptions {
  apiKey: string;
  resolvedPath: string;
  excludePatternsInput: string;
  maxManifests: number;
  includeDev: boolean;
  failOn: string;
  softFail: boolean;
}

async function runRecursiveScan(options: RecursiveScanOptions): Promise<void> {
  const { apiKey, resolvedPath, excludePatternsInput, maxManifests, includeDev, failOn, softFail } = options;

  core.info(`Scanning repository recursively in ${resolvedPath}`);

  // Parse exclude patterns - use defaults if empty or whitespace-only
  const parsedPatterns = excludePatternsInput
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  const excludePatterns = parsedPatterns.length > 0 ? parsedPatterns : DEFAULT_EXCLUDES;

  // Run recursive scan
  const result: RepoScanResult = await scanRepository({
    basePath: resolvedPath,
    apiKey,
    includeDev,
    excludePatterns,
    maxManifests,
    onProgress: (current, total, manifest) => {
      core.info(`Scanning manifest ${current}/${total}: ${manifest}`);
    },
  });

  const { summary } = result;

  // Determine highest risk
  const highestRisk =
    summary.critical > 0
      ? "CRITICAL"
      : summary.high > 0
        ? "HIGH"
        : summary.medium > 0
          ? "MEDIUM"
          : summary.low > 0
            ? "LOW"
            : "NONE";

  const hasIssues = summary.critical > 0 || summary.high > 0;

  // Check threshold
  let failed = false;
  if (failOn === "CRITICAL" && summary.critical > 0) {
    failed = true;
  } else if (failOn === "HIGH" && hasIssues) {
    failed = true;
  }

  // Set outputs
  core.setOutput("total", summary.totalPackages);
  core.setOutput("critical", summary.critical);
  core.setOutput("high", summary.high);
  core.setOutput("medium", summary.medium);
  core.setOutput("low", summary.low);
  core.setOutput("has-issues", hasIssues);
  core.setOutput("highest-risk", highestRisk);
  core.setOutput("failed", failed);

  // Count not found across all manifests
  const allNotFound = result.manifests
    .filter((m) => m.notFound)
    .flatMap((m) => m.notFound || []);
  core.setOutput("not-found-count", allNotFound.length);

  // Build per-manifest results for JSON output
  const perManifestResults = Object.fromEntries(
    result.manifests.map((m) => [
      m.manifest.relativePath,
      {
        status: m.status,
        ecosystem: m.manifest.ecosystem,
        error: m.error,
        counts: m.counts,
        notFound: m.notFound,
      },
    ])
  );

  core.setOutput("results", JSON.stringify(result));
  core.setOutput("manifests-scanned", summary.successfulManifests);
  core.setOutput("manifests-failed", summary.failedManifests);
  core.setOutput("per-manifest-results", JSON.stringify(perManifestResults));
  core.setOutput("truncated", result.truncated);

  // Warn about truncation
  if (result.truncated) {
    core.warning(
      `Manifest limit reached (${maxManifests}). Some manifests were not scanned. Increase max-manifests if needed.`
    );
  }

  // Warn about rate limiting
  if (result.rateLimited) {
    core.warning(
      `Rate limit reached during scan. Some manifests were not fully scanned. Check your usage at https://pkgwatch.dev/dashboard`
    );
  }

  // Warn about not found packages
  if (allNotFound.length > 0) {
    const maxToShow = 10;
    const unique = [...new Set(allNotFound)];
    const shown = unique.slice(0, maxToShow);
    const remaining = unique.length - shown.length;
    const suffix = remaining > 0 ? ` (and ${remaining} more)` : "";
    core.warning(
      `${unique.length} package(s) not found in registry: ${shown.join(", ")}${suffix}`
    );
  }

  // Generate job summary
  await generateRepoSummary(result, failed, failOn);

  // Add annotations for high-risk packages (grouped by manifest)
  for (const manifestResult of result.manifests) {
    if (manifestResult.status !== "success" || !manifestResult.packages) continue;

    for (const pkg of manifestResult.packages) {
      if (pkg.risk_level === "CRITICAL" || pkg.risk_level === "HIGH") {
        const safeName = sanitizeForAnnotation(pkg.package);
        const riskFactor = pkg.abandonment_risk?.risk_factors?.[0];
        const reason = riskFactor ? ` - ${sanitizeForAnnotation(riskFactor)}` : "";
        core.warning(
          `${safeName}: ${pkg.risk_level} risk (score: ${pkg.health_score}/100)${reason}`,
          {
            title: pkg.risk_level === "CRITICAL" ? "Critical Dependency Risk" : "High Dependency Risk",
            file: manifestResult.manifest.relativePath,
          }
        );
      }
    }
  }

  // Log summary
  core.info(
    `Scan complete: ${summary.totalManifests} manifests, ${summary.uniquePackages} unique packages (${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low)`
  );

  // Exit based on threshold
  if (failed && !softFail) {
    core.setFailed(
      `Found ${summary.critical} CRITICAL and ${summary.high} HIGH risk packages across ${summary.totalManifests} manifests (threshold: ${failOn})`
    );
  } else if (failed && softFail) {
    core.warning(
      `Found ${summary.critical} CRITICAL and ${summary.high} HIGH risk packages across ${summary.totalManifests} manifests (threshold: ${failOn}) - soft-fail mode`
    );
  }
}

/**
 * Sanitize text for safe use in annotations (removes control characters and newlines).
 */
function sanitizeForAnnotation(text: string): string {
  return text
    .replace(/[\x00-\x1F\x7F]/g, "") // Remove control characters
    .slice(0, 100); // Limit length
}

function handleError(error: unknown): void {
  if (error instanceof ApiClientError) {
    switch (error.code) {
      case "unauthorized":
        core.setFailed(
          `Authentication failed (401)\n\nYour API key appears to be invalid or expired.\nVerify at https://pkgwatch.dev/dashboard`
        );
        break;
      case "forbidden":
        core.setFailed(
          `Access forbidden (403)\n\nYour account may have exceeded plan limits or been disabled.\nCheck https://pkgwatch.dev/dashboard`
        );
        break;
      case "rate_limited":
        core.setFailed(
          `Rate limit exceeded (429)\n\nYour API quota has been exhausted.\nUpgrade at https://pkgwatch.dev/pricing`
        );
        break;
      case "timeout":
        core.setFailed(
          `Request timed out\n\nThe PkgWatch API did not respond in time.\nCheck https://status.pkgwatch.dev`
        );
        break;
      case "network_error":
        core.setFailed(
          `Network error\n\nUnable to reach PkgWatch API.\nCheck https://status.pkgwatch.dev`
        );
        break;
      default:
        core.setFailed(`API error: ${error.message}`);
    }
  } else if (error instanceof Error) {
    // Handle specific error messages with better guidance
    if (error.message.includes("Invalid API key format")) {
      core.setFailed(
        `Invalid API key format\n\nAPI keys should start with 'pw_'.\nGet your key at https://pkgwatch.dev/dashboard`
      );
    } else if (error.message.includes("API key is required")) {
      core.setFailed(
        `API key is required\n\nPlease provide your API key via the 'api-key' input.\nGet your key at https://pkgwatch.dev/dashboard`
      );
    } else {
      core.setFailed(`Action failed: ${error.message}`);
    }
  } else {
    core.setFailed("An unknown error occurred");
  }
}

run().catch((error) => {
  // Catch any unhandled errors (e.g., bugs in handleError itself)
  core.setFailed(`Unhandled error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
