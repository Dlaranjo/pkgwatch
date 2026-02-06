#!/usr/bin/env node
/**
 * PkgWatch CLI - Check package health scores from the command line.
 *
 * Usage:
 *   pkgwatch check <package>      Check a single package
 *   pkgwatch scan [path]          Scan package.json dependencies
 *   pkgwatch usage                Show API usage statistics
 *   pkgwatch config <action>      Manage configuration
 *   pkgwatch feedback             Send feedback or report issues
 */

import { program, Option } from "commander";
import picocolors from "picocolors";
import open from "open";

// Use mutable binding so we can swap to no-color version
// Type as ReturnType of createColors since that's what we'll assign
let pc: ReturnType<typeof picocolors.createColors> = picocolors;
import ora, { type Ora } from "ora";
import cliProgress from "cli-progress";
import { resolve as resolvePath, relative as relativePath, basename } from "node:path";
import { statSync, existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";

// Exit codes (defined early for global error handler)
const EXIT_SUCCESS = 0;
const EXIT_RISK_EXCEEDED = 1;
const EXIT_CLI_ERROR = 2;

// Sleep helper for retry delays
const sleep = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));

// GitHub repo URL for feedback links
const GITHUB_REPO = "https://github.com/Dlaranjo/pkgwatch";

// Global unhandled rejection handler to prevent silent crashes
// Check NO_COLOR directly since pc might not be updated yet (preAction hasn't run)
process.on("unhandledRejection", (error) => {
  const useColor = !process.env.NO_COLOR;
  const red = useColor ? pc.red : (s: string) => s;
  console.error(red("Unexpected error:"), error instanceof Error ? error.message : String(error));
  process.exit(EXIT_CLI_ERROR);
});

// Dynamic version from package.json
const require = createRequire(import.meta.url);
const { version: VERSION } = require("../package.json");

// Global options state
let quietMode = false;
let verboseMode = false;

/**
 * Create a spinner that respects quiet mode.
 */
function createSpinner(text: string): Ora | null {
  if (quietMode) return null;
  return ora(text).start();
}

/**
 * Log output that respects quiet mode.
 */
function log(message: string): void {
  if (!quietMode) console.log(message);
}

/**
 * Log verbose output (only in verbose mode).
 */
function logVerbose(message: string): void {
  if (verboseMode) console.log(pc.dim(`[verbose] ${message}`));
}

/**
 * Open a URL in the default browser with fallback for headless environments.
 */
async function openUrl(url: string, description: string): Promise<void> {
  try {
    await open(url);
    log(pc.green(`Opened ${description} in your browser`));
  } catch {
    // Fallback for headless/WSL/CI environments
    log(pc.yellow("Could not open browser automatically."));
    log(pc.dim(`Please visit: ${pc.underline(url)}`));
  }
}

/**
 * Check and display rate limit warning based on usage percentage.
 */
async function checkRateLimitWarning(client: PkgWatchClient): Promise<void> {
  if (quietMode) return;

  try {
    const data = await client.getUsage();
    const usedPercent = data.usage.usage_percentage;
    const remaining = data.usage.remaining;

    if (usedPercent >= 95) {
      console.log(pc.red(`\n⚠ Warning: ${remaining.toLocaleString()} requests remaining this month (${usedPercent.toFixed(0)}% used)`));
      console.log(pc.dim("  Upgrade at https://pkgwatch.dev/pricing"));
    } else if (usedPercent >= 80) {
      console.log(pc.yellow(`\n⚠ ${remaining.toLocaleString()} requests remaining this month (${usedPercent.toFixed(0)}% used)`));
    }
  } catch {
    // Silently ignore errors when checking rate limits
  }
}

import {
  PkgWatchClient,
  ApiClientError,
  getRiskColor,
  readDependencies,
  readDependenciesFromFile,
  DependencyParseError,
  scanRepository,
  previewRepoScan,
  DEFAULT_EXCLUDES,
  type PackageHealthFull,
  type PackageHealth,
  type ScanResult,
  type Ecosystem,
  type RepoScanResult,
  type ManifestScanResult,
  type CollectingResponse,
  isCollectingResponse,
} from "./api.js";
import {
  getApiKey,
  setApiKey,
  clearConfig,
  getConfigPath,
  maskApiKey,
  readConfig,
} from "./config.js";

/**
 * Get API client, supports demo mode (no API key) or authenticated mode.
 */
function getClient(): PkgWatchClient {
  const apiKey = getApiKey();
  if (!apiKey) {
    logVerbose("No API key configured, using demo mode (20 requests/hour)");
  }
  return new PkgWatchClient(apiKey);
}

/**
 * Format health score with color.
 */
function formatScore(score: number | null): string {
  if (score === null) return pc.dim("--/100");
  if (score >= 70) return pc.green(`${score}/100`);
  if (score >= 50) return pc.yellow(`${score}/100`);
  return pc.red(`${score}/100`);
}

/**
 * Format risk level with color.
 */
function formatRisk(level: string): string {
  const color = getRiskColor(level);
  switch (color) {
    case "red":
      return pc.red(level);
    case "yellow":
      return pc.yellow(level);
    case "green":
      return pc.green(level);
    default:
      return pc.blue(level);
  }
}

/**
 * Format large numbers with K/M suffix.
 */
function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}

/**
 * Convert scan results to SARIF format for security tooling integration.
 */
function toSarif(result: ScanResult): object {
  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "pkgwatch",
          version: VERSION,
          informationUri: "https://pkgwatch.dev",
        }
      },
      results: result.packages
        .filter((p: PackageHealth) => p.risk_level === "CRITICAL" || p.risk_level === "HIGH")
        .map((p: PackageHealth) => ({
          ruleId: `pkgwatch/${p.risk_level.toLowerCase()}`,
          level: p.risk_level === "CRITICAL" ? "error" : "warning",
          message: {
            text: `${p.package}: ${p.risk_level} risk (health score: ${p.health_score})`,
          },
        })),
    }],
  };
}

/**
 * Print package health details.
 */
function printPackageDetails(pkg: PackageHealthFull): void {
  console.log("");
  console.log(pc.bold(`${pkg.package}@${pkg.latest_version}`));
  console.log("");
  console.log(`  Health Score    ${formatScore(pkg.health_score)}  ${formatRisk(pkg.risk_level)}`);
  const abandonProb = pkg.abandonment_risk?.probability ?? 0;
  const abandonMonths = pkg.abandonment_risk?.time_horizon_months ?? 12;
  console.log(`  Abandon Risk    ${abandonProb.toFixed(1)}% (${abandonMonths} months)`);
  console.log("");

  // Positive signals
  const { signals } = pkg;
  if (signals.days_since_last_commit <= 30) {
    console.log(`  ${pc.green("+")} Active commits (${signals.days_since_last_commit} days ago)`);
  }
  if (signals.weekly_downloads >= 1_000_000) {
    console.log(`  ${pc.green("+")} ${formatNumber(signals.weekly_downloads)}+ weekly downloads`);
  }
  if (signals.maintainer_count >= 3) {
    console.log(`  ${pc.green("+")} ${signals.maintainer_count} maintainers`);
  }
  if (signals.active_contributors_90d >= 5) {
    console.log(`  ${pc.green("+")} ${signals.active_contributors_90d} active contributors (90d)`);
  }
  // Show bus factor if available and healthy
  if (signals.true_bus_factor && signals.true_bus_factor >= 3) {
    console.log(`  ${pc.green("+")} Bus factor: ${signals.true_bus_factor} (healthy)`);
  }

  // Negative signals / risk factors
  const riskFactors = pkg.abandonment_risk?.risk_factors ?? [];
  if (riskFactors.length > 0) {
    for (const factor of riskFactors) {
      console.log(`  ${pc.yellow("!")} ${factor}`);
    }
  }
  if (signals.is_deprecated) {
    console.log(`  ${pc.red("!")} Package is deprecated`);
  }
  if (signals.archived) {
    console.log(`  ${pc.red("!")} Repository is archived`);
  }
  if (signals.maintainer_count <= 2 && signals.maintainer_count > 0) {
    console.log(`  ${pc.yellow("!")} Low maintainer count (${signals.maintainer_count})`);
  }
  // Warning for low bus factor (contribution concentration)
  if (signals.true_bus_factor && signals.true_bus_factor <= 1) {
    console.log(`  ${pc.yellow("!")} Single person does 50%+ of commits (bus factor: ${signals.true_bus_factor})`);
  }

  console.log("");

  // Component scores
  console.log(pc.dim("  Components:"));
  console.log(`    Maintainer:  ${pkg.components.maintainer_health.toFixed(0)}/100`);
  console.log(`    Evolution:   ${pkg.components.evolution_health.toFixed(0)}/100`);
  console.log(`    Community:   ${pkg.components.community_health.toFixed(0)}/100`);
  console.log(`    User Impact: ${pkg.components.user_centric.toFixed(0)}/100`);
  // Security component (new in v2)
  if (pkg.components.security_health !== undefined) {
    console.log(`    Security:    ${pkg.components.security_health.toFixed(0)}/100`);
  }
  console.log("");

  // Feedback link for score disputes
  console.log(pc.dim(`  Wrong score? ${pc.underline(`https://github.com/Dlaranjo/pkgwatch/issues/new?title=Score+feedback:+${pkg.ecosystem}/${pkg.package}&labels=score-feedback`)}`));
  console.log("");
}


/**
 * Prompt for input (for API key).
 */
async function prompt(question: string): Promise<string> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolvePromise) => {
    rl.question(question, (answer) => {
      rl.close();
      resolvePromise(answer.trim());
    });
  });
}

// ============================================================
// Commands
// ============================================================

program
  .name("pkgwatch")
  .description("Monitor npm and PyPI package health and catch risks early")
  .version(VERSION)
  .option("-q, --quiet", "Suppress non-essential output")
  .option("-v, --verbose", "Show detailed output")
  .option("--no-color", "Disable colored output (also respects NO_COLOR env)")
  .hook("preAction", (thisCommand) => {
    const opts = thisCommand.opts();
    quietMode = opts.quiet ?? false;
    verboseMode = opts.verbose ?? false;

    // Handle --no-color flag (Commander sets opts.color = false for --no-color)
    // Also respect NO_COLOR environment variable per https://no-color.org/
    if (opts.color === false || process.env.NO_COLOR) {
      pc = picocolors.createColors(false);
    }
  });

// ------------------------------------------------------------
// check <package>
// ------------------------------------------------------------

program
  .command("check <package>")
  .alias("c")
  .description("Check health score for a single package")
  .option("--json", "Output as JSON")
  .option("--include-incomplete", "Return partial data for packages still being collected")
  .option("--max-retries <n>", "Max retries for packages being collected (default: 3)", "3")
  .option("--max-wait <seconds>", "Max total wait time in seconds (default: 600)", "600")
  .option("--no-retry", "Disable automatic retry for 202 responses")
  .addOption(new Option("-e, --ecosystem <name>", "Package ecosystem").choices(["npm", "pypi"]).default("npm"))
  .action(async (packageName: string, options: {
    json?: boolean;
    ecosystem: string;
    includeIncomplete?: boolean;
    maxRetries?: string;
    maxWait?: string;
    retry?: boolean;  // Commander sets to false with --no-retry
  }) => {
    const client = getClient();
    let spinner = createSpinner(`Checking ${packageName} (${options.ecosystem})...`);
    logVerbose(`Fetching package data from API`);

    try {
      // Fetch package data, with optional bypass for incomplete data
      let pkg = await client.getPackage(
        packageName,
        options.ecosystem,
        { includeIncomplete: options.includeIncomplete }
      );
      spinner?.stop();

      // Handle 202 "collecting" response - package data not yet ready
      if (isCollectingResponse(pkg)) {
        // Handle --no-retry flag
        if (options.retry === false) {
          if (options.json) {
            console.log(JSON.stringify(pkg, null, 2));
          } else {
            console.log(pc.yellow(`Package data is being collected for ${packageName}`));
            console.log(pc.dim(`Retry disabled. Use --include-incomplete to get partial data.`));
          }
          process.exit(EXIT_CLI_ERROR);
        }

        const maxRetries = parseInt(options.maxRetries || "3", 10);
        const maxWait = parseInt(options.maxWait || "600", 10);
        let retryCount = 0;
        let totalWaited = 0;
        let result: PackageHealthFull | CollectingResponse = pkg;

        while (isCollectingResponse(result) && retryCount < maxRetries && totalWaited < maxWait) {
          const waitTime = Math.min(result.retry_after_seconds, maxWait - totalWaited);
          retryCount++;

          spinner = createSpinner(
            `Package data being collected (attempt ${retryCount}/${maxRetries}), waiting ${waitTime}s...`
          );

          await sleep(waitTime * 1000);
          totalWaited += waitTime;
          spinner?.stop();

          try {
            result = await client.getPackage(
              packageName,
              options.ecosystem,
              { includeIncomplete: options.includeIncomplete }
            );
          } catch (retryError) {
            // Handle errors during retry (404, rate limit, etc.)
            if (retryError instanceof ApiClientError) {
              if (retryError.status === 404) {
                console.error(pc.red(`Package not found: ${packageName}`));
              } else {
                console.error(pc.red(`API Error during retry: ${retryError.message}`));
              }
            } else {
              console.error(pc.red(`Error during retry: ${String(retryError)}`));
            }
            process.exit(EXIT_CLI_ERROR);
          }
        }

        // After retries exhausted or data ready
        if (isCollectingResponse(result)) {
          if (options.json) {
            console.log(JSON.stringify(result, null, 2));
          } else {
            console.log(pc.yellow(`Package data still being collected after ${retryCount} retries.`));
            console.log(pc.dim(`Use --include-incomplete to get partial data.`));
          }
          process.exit(EXIT_CLI_ERROR);
        }

        // Data is ready - continue to normal output
        pkg = result;
      }

      if (options.json) {
        console.log(JSON.stringify(pkg, null, 2));
      } else {
        printPackageDetails(pkg);
      }

      // Check rate limit and show warning if needed
      await checkRateLimitWarning(client);

      process.exit(EXIT_SUCCESS);
    } catch (error) {
      spinner?.stop();
      if (error instanceof ApiClientError) {
        if (error.status === 404) {
          console.error(pc.red(`Package not found: ${packageName}`));
        } else if (error.code === "rate_limited") {
          console.error(pc.red("Rate limit exceeded."));
          console.error(pc.dim("Your API quota has been exhausted. Try again later or upgrade your plan."));
          console.error(pc.dim("  https://pkgwatch.dev/pricing"));
        } else if (error.code === "forbidden") {
          console.error(pc.red("Access denied - check your API key permissions."));
          console.error(pc.dim("Your API key may not have access to this resource."));
        } else {
          console.error(pc.red(`API Error: ${error.message}`));
        }
      } else if (error instanceof Error) {
        console.error(pc.red(`Unexpected error: ${error.message}`));
        console.error(pc.dim("\nIf this persists, please report at:"));
        console.error(pc.dim("  https://github.com/Dlaranjo/pkgwatch/issues"));
      } else {
        console.error(pc.red(`Unexpected error: ${String(error)}`));
        console.error(pc.dim("\nIf this persists, please report at:"));
        console.error(pc.dim("  https://github.com/Dlaranjo/pkgwatch/issues"));
      }
      process.exit(EXIT_CLI_ERROR);
    }
  });

// ------------------------------------------------------------
// Recursive scan helper
// ------------------------------------------------------------

interface RecursiveScanOptions {
  failOn?: string;
  ecosystem?: string;
  dev?: boolean;
  exclude?: string;
  maxManifests?: string;
  confirm?: boolean;
  ignoreNotFound?: boolean;
}

/**
 * Prompt for yes/no confirmation.
 */
async function promptConfirm(question: string): Promise<boolean> {
  const answer = await prompt(question);
  return ["y", "yes", ""].includes(answer.toLowerCase());
}

/**
 * Format status emoji for manifest scan result.
 */
function getStatusEmoji(status: string): string {
  switch (status) {
    case "success":
      return pc.green("✓");
    case "parse_error":
      return pc.red("✗");
    case "api_error":
      return pc.yellow("⚠");
    case "rate_limited":
      return pc.red("⊘");
    default:
      return pc.dim("?");
  }
}

/**
 * Run recursive scan across all manifests in directory.
 */
async function runRecursiveScan(
  path: string | undefined,
  options: RecursiveScanOptions & { ecosystem?: string },
  outputFormat: string
): Promise<void> {
  const cwd = process.cwd();
  const basePath = path ? resolvePath(cwd, path) : cwd;
  const includeDev = options.dev !== false;
  const maxManifests = parseInt(options.maxManifests || "100", 10);

  // Validate max-manifests
  if (isNaN(maxManifests) || maxManifests < 1) {
    console.error(pc.red("--max-manifests must be a positive integer"));
    process.exit(EXIT_CLI_ERROR);
  }

  // Warn if --ecosystem is used with --recursive (it's ignored)
  if (options.ecosystem) {
    console.warn(pc.yellow("Note: --ecosystem is ignored in recursive mode (ecosystems are auto-detected per manifest)"));
  }

  // Parse exclude patterns - use defaults if empty or whitespace-only
  const parsedPatterns = options.exclude
    ? options.exclude.split(",").map((p) => p.trim()).filter(Boolean)
    : [];
  const excludePatterns = parsedPatterns.length > 0 ? parsedPatterns : DEFAULT_EXCLUDES;

  // Check if path exists
  if (!existsSync(basePath)) {
    console.error(pc.red(`Path does not exist: ${basePath}`));
    process.exit(EXIT_CLI_ERROR);
  }

  // Preview scan first (no API calls)
  const spinner = createSpinner("Discovering manifest files...");
  let preview;
  try {
    preview = previewRepoScan({
      basePath,
      includeDev,
      excludePatterns,
      maxManifests,
    });
    spinner?.stop();
  } catch (err) {
    spinner?.stop();
    console.error(pc.red(`Error discovering manifests: ${err instanceof Error ? err.message : String(err)}`));
    process.exit(EXIT_CLI_ERROR);
  }

  if (preview.manifests.length === 0) {
    log(pc.yellow("No manifest files found"));
    process.exit(EXIT_SUCCESS);
  }

  // Show discovery summary
  const npmCount = preview.manifests.filter((m) => m.ecosystem === "npm").length;
  const pypiCount = preview.manifests.filter((m) => m.ecosystem === "pypi").length;
  const ecosystemParts = [];
  if (npmCount > 0) ecosystemParts.push(`${npmCount} npm`);
  if (pypiCount > 0) ecosystemParts.push(`${pypiCount} pypi`);

  log(`Found ${pc.bold(String(preview.manifests.length))} manifest files (${ecosystemParts.join(", ")})`);
  log(`Total unique packages: ${pc.bold(String(preview.packageCounts.total))}`);

  if (preview.truncated) {
    log(pc.yellow(`\n⚠ Truncated: Max manifest limit (${maxManifests}) reached`));
  }

  // Confirmation prompt (unless in CI or --no-confirm)
  // Robust CI detection - check multiple environment variables
  const isCI = Boolean(
    process.env.CI ||
    process.env.GITHUB_ACTIONS ||
    process.env.GITLAB_CI ||
    process.env.JENKINS_URL ||
    process.env.CIRCLECI ||
    process.env.TRAVIS ||
    process.env.BUILDKITE
  );
  const skipConfirm = options.confirm === false || isCI;

  if (!skipConfirm && outputFormat === "table") {
    log("");
    // Try to get usage info for quota display
    const apiKey = getApiKey();
    if (apiKey) {
      try {
        const client = new PkgWatchClient(apiKey);
        const usage = await client.getUsage();
        const remaining = usage.usage.remaining;
        log(`This will use ${pc.bold(String(preview.packageCounts.total))} of your ${remaining.toLocaleString()} remaining requests.`);

        // Warn if quota is insufficient
        if (preview.packageCounts.total > remaining) {
          log(pc.yellow(`\n⚠ Warning: This scan requires ${preview.packageCounts.total} requests but you only have ${remaining} remaining.`));
          log(pc.yellow("The scan may be incomplete due to rate limiting."));
        }
      } catch {
        // Ignore errors, just skip quota display
      }
    }

    const confirmed = await promptConfirm("Continue? [Y/n] ");
    if (!confirmed) {
      log(pc.dim("Scan cancelled"));
      process.exit(EXIT_SUCCESS);
    }
  }

  log("");

  // Run actual scan - requires API key
  const apiKey = getApiKey();
  if (!apiKey) {
    console.error(pc.red("Recursive scan requires an API key."));
    console.error(pc.dim("Run: pkgwatch config set"));
    console.error(pc.dim("Get your key at https://pkgwatch.dev"));
    process.exit(EXIT_CLI_ERROR);
  }

  let result: RepoScanResult;

  try {
    result = await scanRepository({
      basePath,
      apiKey,
      includeDev,
      excludePatterns,
      maxManifests,
      onProgress: (current, total, manifest) => {
        if (!quietMode && outputFormat === "table") {
          process.stdout.write(`\rScanning manifest ${current}/${total}: ${manifest}`);
          process.stdout.write("\x1b[K"); // Clear to end of line
        }
      },
    });

    if (!quietMode && outputFormat === "table") {
      process.stdout.write("\r\x1b[K"); // Clear progress line
    }
  } catch (err) {
    if (err instanceof ApiClientError) {
      handleApiError(err);
    } else {
      console.error(pc.red(`Error scanning repository: ${err instanceof Error ? err.message : String(err)}`));
    }
    process.exit(EXIT_CLI_ERROR);
  }

  // Output results
  if (outputFormat === "json") {
    console.log(JSON.stringify(result, null, 2));
  } else if (outputFormat === "sarif") {
    // SARIF output with all packages from all manifests
    const allPackages: PackageHealth[] = [];
    for (const m of result.manifests) {
      if (m.packages) allPackages.push(...m.packages);
    }
    const sarifResult: ScanResult = {
      total: allPackages.length,
      critical: result.summary.critical,
      high: result.summary.high,
      medium: result.summary.medium,
      low: result.summary.low,
      packages: allPackages,
    };
    console.log(JSON.stringify(toSarif(sarifResult), null, 2));
  } else {
    // Table output - show results per manifest
    log("");

    for (const m of result.manifests) {
      const status = getStatusEmoji(m.status);
      const ecosystem = m.manifest.ecosystem.toUpperCase();
      log(`${status} ${pc.bold(m.manifest.relativePath)} ${pc.dim(`(${ecosystem})`)}`);

      if (m.status === "success" && m.packages) {
        const critical = m.packages.filter((p) => p.risk_level === "CRITICAL");
        const high = m.packages.filter((p) => p.risk_level === "HIGH");

        // Helper to format package name with data quality indicator
        const formatPkg = (p: PackageHealth) => {
          const isUnverified = !p.data_quality || p.data_quality.assessment !== "VERIFIED";
          return isUnverified ? `${p.package}${pc.dim("*")}` : p.package;
        };

        if (critical.length > 0) {
          log(`  ${pc.red(`CRITICAL (${critical.length}):`)} ${critical.map(formatPkg).join(", ")}`);
        }
        if (high.length > 0) {
          log(`  ${pc.red(`HIGH (${high.length}):`)} ${high.map(formatPkg).join(", ")}`);
        }
        if (critical.length === 0 && high.length === 0 && m.packages.length > 0) {
          log(`  ${pc.green("No high-risk issues")} (${m.packages.length} packages)`);
        }
        if (m.packages.length === 0) {
          log(`  ${pc.dim("No dependencies")}`);
        }
      } else if (m.status === "parse_error") {
        log(`  ${pc.red(`Error: ${m.error || "Parse error"}`)}`);
      } else if (m.status === "api_error") {
        log(`  ${pc.yellow(`API Error: ${m.error || "Unknown error"}`)}`);
      } else if (m.status === "rate_limited") {
        log(`  ${pc.red("Rate limited - skipped")}`);
      }

      // Show not found packages (unless --ignore-not-found)
      if (!options.ignoreNotFound && m.notFound && m.notFound.length > 0) {
        const shown = m.notFound.slice(0, 5);
        const more = m.notFound.length - shown.length;
        log(`  ${pc.dim(`Not found: ${shown.join(", ")}${more > 0 ? ` (+${more} more)` : ""}`)}`);
      }

      log("");
    }

    // Summary line
    const { summary } = result;
    log(pc.dim("─".repeat(50)));
    log(`Summary: ${summary.totalManifests} manifests, ${summary.uniquePackages} unique packages`);
    log(
      `  ${pc.red(`${summary.critical} critical`)}, ${pc.red(`${summary.high} high`)}, ${pc.yellow(`${summary.medium} medium`)}, ${pc.green(`${summary.low} low`)}`
    );

    // Calculate aggregate data quality from all manifests (deduplicated)
    const unverifiedRiskPackages = new Set<string>();
    for (const m of result.manifests) {
      if (m.status === "success" && m.packages) {
        for (const pkg of m.packages) {
          if ((pkg.risk_level === "CRITICAL" || pkg.risk_level === "HIGH") &&
              (!pkg.data_quality || pkg.data_quality.assessment !== "VERIFIED")) {
            unverifiedRiskPackages.add(pkg.package);
          }
        }
      }
    }

    if (unverifiedRiskPackages.size > 0) {
      log("");
      log(pc.yellow(`Note: ${unverifiedRiskPackages.size} unique HIGH/CRITICAL packages have incomplete data.`));
      log(pc.dim(`Packages marked with * may appear risky due to missing repository information.`));
    }

    if (result.truncated) {
      log(pc.yellow(`\n⚠ Truncated: Max manifest limit reached`));
    }
    if (result.rateLimited) {
      log(pc.red(`\n⚠ Rate limited: Some manifests were not scanned`));
    }
  }

  // Check rate limit warning
  await checkRateLimitWarning(getClient());

  // Check fail-on threshold
  const { summary } = result;
  if (options.failOn) {
    const threshold = options.failOn.toUpperCase();
    if (threshold === "CRITICAL" && summary.critical > 0) {
      log(pc.red(`\nExiting with code 1: Found ${summary.critical} CRITICAL risk package(s) (--fail-on ${threshold})`));
      process.exit(EXIT_RISK_EXCEEDED);
    }
    if (threshold === "HIGH" && (summary.critical > 0 || summary.high > 0)) {
      const count = summary.critical + summary.high;
      log(pc.red(`\nExiting with code 1: Found ${count} HIGH+ risk package(s) (--fail-on ${threshold})`));
      process.exit(EXIT_RISK_EXCEEDED);
    }
  }

  // Exit with error if ALL manifests failed
  if (summary.successfulManifests === 0 && summary.failedManifests > 0) {
    log(pc.red("\nAll manifests failed to scan"));
    process.exit(EXIT_CLI_ERROR);
  }

  process.exit(EXIT_SUCCESS);
}

/**
 * Handle API errors with user-friendly messages.
 */
function handleApiError(error: ApiClientError): void {
  if (error.code === "rate_limited") {
    console.error(pc.red("Rate limit exceeded."));
    console.error(pc.dim("Your API quota has been exhausted. Try again later or upgrade your plan."));
    console.error(pc.dim("  https://pkgwatch.dev/pricing"));
  } else if (error.code === "forbidden") {
    console.error(pc.red("Access denied - check your API key permissions."));
    console.error(pc.dim("Your API key may not have access to this resource."));
  } else if (error.code === "unauthorized") {
    console.error(pc.red("Authentication failed."));
    console.error(pc.dim("Your API key may be invalid or expired."));
    console.error(pc.dim("  https://pkgwatch.dev/dashboard"));
  } else {
    console.error(pc.red(`API Error: ${error.message}`));
  }
}

// ------------------------------------------------------------
// scan [path]
// ------------------------------------------------------------
program
  .command("scan [path]")
  .alias("s")
  .description("Scan dependencies in a package.json or requirements.txt file")
  .option("--json", "Output as JSON (deprecated, use --output json)")
  .option("-o, --output <format>", "Output format: table, json, sarif", "table")
  .option("--fail-on <level>", "Exit 1 if risk level reached (HIGH or CRITICAL)")
  .option("--no-dev", "Exclude dev dependencies from scan")
  .option("-r, --recursive", "Scan all manifest files in directory (monorepo mode)")
  .option("--exclude <patterns>", "Glob patterns to exclude (comma-separated)")
  .option("--max-manifests <n>", "Maximum number of manifests to scan", "100")
  .option("--no-confirm", "Skip confirmation prompt for recursive scans")
  .option("--ignore-not-found", "Don't show packages not found in registry")
  .addOption(new Option("-e, --ecosystem <name>", "Override detected ecosystem").choices(["npm", "pypi"]))
  .action(async (path: string | undefined, options: { json?: boolean; output?: string; failOn?: string; ecosystem?: string; dev?: boolean; recursive?: boolean; exclude?: string; maxManifests?: string; confirm?: boolean; ignoreNotFound?: boolean }) => {
    // Handle backward compatibility: --json flag
    let outputFormat = options.output || "table";
    if (options.json) {
      console.warn(pc.yellow("Warning: --json flag is deprecated. Use --output json instead."));
      outputFormat = "json";
    }

    // Validate output format
    const VALID_FORMATS = ["table", "json", "sarif"];
    if (!VALID_FORMATS.includes(outputFormat)) {
      console.error(pc.red(`Invalid output format: ${outputFormat}`));
      console.error(`Valid options: ${VALID_FORMATS.join(", ")}`);
      process.exit(EXIT_CLI_ERROR);
    }

    // Validate --fail-on value
    const VALID_FAIL_ON = ["HIGH", "CRITICAL"];
    if (options.failOn && !VALID_FAIL_ON.includes(options.failOn.toUpperCase())) {
      console.error(pc.red(`Invalid --fail-on value: ${options.failOn}`));
      console.error(`Valid options: ${VALID_FAIL_ON.join(", ")}`);
      process.exit(EXIT_CLI_ERROR);
    }

    // Handle recursive mode
    if (options.recursive) {
      await runRecursiveScan(path, options, outputFormat);
      return;
    }

    const client = getClient();
    const cwd = process.cwd();
    const includeDev = options.dev !== false; // --no-dev sets this to false

    // Read and parse dependencies
    let dependencies: Record<string, string>;
    let ecosystem: Ecosystem;
    let format: string;

    try {
      if (!path) {
        // Auto-detect dependency file in current directory
        const result = readDependencies(cwd, includeDev);
        dependencies = result.dependencies;
        ecosystem = result.ecosystem;
        format = result.format;
        logVerbose(`Detected ${format} (${ecosystem})`);
      } else {
        // Determine if path is a file or directory
        const resolvedPath = resolvePath(cwd, path);

        // Security: Log when scanning outside cwd
        const relPath = relativePath(cwd, resolvedPath);
        if (relPath.startsWith("..") || relPath.startsWith("..\\")) {
          logVerbose(`Scanning path outside current directory: ${resolvedPath}`);
        }

        // Check if path exists and determine if it's a file or directory
        if (!existsSync(resolvedPath)) {
          throw new DependencyParseError(`Path does not exist: ${resolvedPath}`);
        }

        const stats = statSync(resolvedPath);
        if (stats.isFile()) {
          const result = readDependenciesFromFile(resolvedPath, includeDev);
          dependencies = result.dependencies;
          ecosystem = result.ecosystem;
          format = result.format;
        } else if (stats.isDirectory()) {
          // Path is a directory - auto-detect
          const result = readDependencies(resolvedPath, includeDev);
          dependencies = result.dependencies;
          ecosystem = result.ecosystem;
          format = result.format;
        } else {
          throw new DependencyParseError(`Path is not a file or directory: ${resolvedPath}`);
        }
        logVerbose(`Detected ${format} (${ecosystem})`);
      }
    } catch (err) {
      if (err instanceof DependencyParseError) {
        console.error(pc.red(`Error: ${err.message}`));
      } else if (err instanceof Error) {
        console.error(pc.red(`Error reading dependencies: ${err.message}`));
      } else {
        console.error(pc.red(`Error reading dependencies: ${String(err)}`));
      }
      process.exit(EXIT_CLI_ERROR);
    }

    // Allow --ecosystem to override detected ecosystem
    if (options.ecosystem) {
      ecosystem = options.ecosystem as Ecosystem;
      logVerbose(`Ecosystem overridden to ${ecosystem}`);
    }

    const depCount = Object.keys(dependencies).length;

    if (depCount === 0) {
      log(pc.yellow(`No dependencies found in ${format}`));
      process.exit(EXIT_SUCCESS);
    }

    logVerbose(`Found ${depCount} dependencies in ${format}`);

    // Constants for progress bar and batching
    const PROGRESS_BAR_THRESHOLD = 20;
    const BATCH_SIZE = 25;

    let result: ScanResult;
    let activeProgressBar: cliProgress.SingleBar | null = null;

    try {
      // Use progress bar for large scans (20+ dependencies)
      if (depCount >= PROGRESS_BAR_THRESHOLD && outputFormat === "table" && !quietMode) {
        activeProgressBar = new cliProgress.SingleBar({
          format: `Scanning ${ecosystem} |{bar}| {percentage}% | {value}/{total} packages`,
          barCompleteChar: '█',
          barIncompleteChar: '░',
        });

        activeProgressBar.start(depCount, 0);

        // Batch processing with progress updates
        const depEntries = Object.entries(dependencies);
        const allPackages: PackageHealth[] = [];
        let notFound: string[] = [];
        const failedPackages: string[] = [];

        for (let i = 0; i < depEntries.length; i += BATCH_SIZE) {
          const batchEntries = depEntries.slice(i, Math.min(i + BATCH_SIZE, depEntries.length));
          const batchDeps = Object.fromEntries(batchEntries);

          try {
            const batchResult = await client.scan(batchDeps, ecosystem);
            allPackages.push(...batchResult.packages);
            if (batchResult.not_found) {
              notFound.push(...batchResult.not_found);
            }
          } catch (error) {
            // Track failed packages but continue with remaining batches
            const packageNames = batchEntries.map(([name]) => name);
            failedPackages.push(...packageNames);
            logVerbose(`Batch failed: ${error instanceof Error ? error.message : String(error)}`);
          }

          activeProgressBar.update(Math.min(i + BATCH_SIZE, depEntries.length));
        }

        activeProgressBar.stop();
        activeProgressBar = null;

        // Report failed packages if any
        if (failedPackages.length > 0) {
          console.log(pc.yellow(`\n⚠ Could not scan ${failedPackages.length} package(s) due to errors:`));
          if (failedPackages.length <= 5) {
            for (const pkg of failedPackages) {
              console.log(pc.dim(`  - ${pkg}`));
            }
          } else {
            for (const pkg of failedPackages.slice(0, 5)) {
              console.log(pc.dim(`  - ${pkg}`));
            }
            console.log(pc.dim(`  ... and ${failedPackages.length - 5} more`));
          }
          console.log("");
        }

        // Aggregate results with data quality
        let verifiedCount = 0;
        let partialCount = 0;
        let unverifiedCount = 0;
        let verifiedRiskCount = 0;
        let unverifiedRiskCount = 0;

        for (const pkg of allPackages) {
          const assessment = pkg.data_quality?.assessment || "UNVERIFIED";
          const isHighRisk = pkg.risk_level === "HIGH" || pkg.risk_level === "CRITICAL";

          if (assessment === "VERIFIED") {
            verifiedCount++;
            if (isHighRisk) verifiedRiskCount++;
          } else if (assessment === "PARTIAL") {
            partialCount++;
            if (isHighRisk) unverifiedRiskCount++;
          } else {
            unverifiedCount++;
            if (isHighRisk) unverifiedRiskCount++;
          }
        }

        result = {
          total: allPackages.length,
          critical: allPackages.filter((p: PackageHealth) => p.risk_level === "CRITICAL").length,
          high: allPackages.filter((p: PackageHealth) => p.risk_level === "HIGH").length,
          medium: allPackages.filter((p: PackageHealth) => p.risk_level === "MEDIUM").length,
          low: allPackages.filter((p: PackageHealth) => p.risk_level === "LOW").length,
          packages: allPackages,
          not_found: notFound.length > 0 ? notFound : undefined,
          data_quality: {
            verified_count: verifiedCount,
            partial_count: partialCount,
            unverified_count: unverifiedCount,
          },
          verified_risk_count: verifiedRiskCount,
          unverified_risk_count: unverifiedRiskCount,
        };
      } else {
        // Use spinner for smaller scans
        const spinner = outputFormat !== "table" ? null : createSpinner(`Scanning ${depCount} ${ecosystem} dependencies...`);
        result = await client.scan(dependencies, ecosystem);
        spinner?.stop();
      }

      // Output results in requested format
      switch (outputFormat) {
        case "json":
          console.log(JSON.stringify(result, null, 2));
          break;
        case "sarif":
          console.log(JSON.stringify(toSarif(result), null, 2));
          break;
        case "table":
        default:
        // Group by risk level
        const critical = result.packages.filter((p: PackageHealth) => p.risk_level === "CRITICAL");
        const high = result.packages.filter((p: PackageHealth) => p.risk_level === "HIGH");
        const medium = result.packages.filter((p: PackageHealth) => p.risk_level === "MEDIUM");
        const low = result.packages.filter((p: PackageHealth) => p.risk_level === "LOW");

        if (critical.length > 0) {
          log(pc.red(pc.bold(`CRITICAL (${critical.length})`)));
          for (const pkg of critical) {
            const reason = pkg.abandonment_risk?.risk_factors?.[0] || "";
            const isUnverified = !pkg.data_quality || pkg.data_quality.assessment !== "VERIFIED";
            const qualifier = isUnverified ? pc.dim(" (limited data)") : "";
            log(`  ${pc.red(pkg.package.padEnd(20))} ${formatScore(pkg.health_score)}   ${reason}${qualifier}`);
          }
          log("");
        }

        if (high.length > 0) {
          log(pc.red(`HIGH (${high.length})`));
          for (const pkg of high) {
            const reason = pkg.abandonment_risk?.risk_factors?.[0] || "";
            const isUnverified = !pkg.data_quality || pkg.data_quality.assessment !== "VERIFIED";
            const qualifier = isUnverified ? pc.dim(" (limited data)") : "";
            log(`  ${pkg.package.padEnd(20)} ${formatScore(pkg.health_score)}   ${reason}${qualifier}`);
          }
          log("");
        }

        if (medium.length > 0) {
          log(pc.yellow(`MEDIUM (${medium.length})`));
          for (const pkg of medium) {
            log(`  ${pkg.package.padEnd(20)} ${formatScore(pkg.health_score)}`);
          }
          log("");
        }

        // Summary
        log(pc.dim("---"));
        log(
          `Summary: ${pc.red(`${result.critical} critical`)}, ${pc.red(`${result.high} high`)}, ${pc.yellow(`${result.medium} medium`)}, ${pc.green(`${result.low} low`)}`
        );

        // Data quality summary (if available)
        if (result.data_quality) {
          const dq = result.data_quality;
          log("");
          log(pc.cyan("Data Quality:"));
          log(`  Verified:   ${dq.verified_count} packages (complete data)`);
          log(`  Partial:    ${dq.partial_count} packages (some data missing)`);
          log(`  Unverified: ${dq.unverified_count} packages (limited data)`);
        }

        // Warn about unverified risks
        const unverifiedRisk = result.unverified_risk_count || 0;
        if (unverifiedRisk > 0) {
          log("");
          log(pc.yellow(`Note: ${unverifiedRisk} HIGH/CRITICAL packages have incomplete data.`));
          log(pc.dim(`These may appear risky due to missing repository information.`));
        }
        break;
      }

      // Check rate limit and show warning if needed
      await checkRateLimitWarning(client);

      // Check fail-on threshold
      if (options.failOn) {
        const threshold = options.failOn.toUpperCase();
        if (threshold === "CRITICAL" && result.critical > 0) {
          log(pc.red(`\nExiting with code 1: Found ${result.critical} CRITICAL risk package(s) (--fail-on ${threshold})`));
          process.exit(EXIT_RISK_EXCEEDED);
        }
        if (threshold === "HIGH" && (result.critical > 0 || result.high > 0)) {
          const count = result.critical + result.high;
          log(pc.red(`\nExiting with code 1: Found ${count} HIGH+ risk package(s) (--fail-on ${threshold})`));
          process.exit(EXIT_RISK_EXCEEDED);
        }
      }

      process.exit(EXIT_SUCCESS);
    } catch (error) {
      // Stop progress bar if still active
      if (activeProgressBar) {
        activeProgressBar.stop();
      }

      if (error instanceof ApiClientError) {
        if (error.code === "rate_limited") {
          console.error(pc.red("Rate limit exceeded."));
          console.error(pc.dim("Your API quota has been exhausted. Try again later or upgrade your plan."));
          console.error(pc.dim("  https://pkgwatch.dev/pricing"));
        } else if (error.code === "forbidden") {
          console.error(pc.red("Access denied - check your API key permissions."));
          console.error(pc.dim("Your API key may not have access to this resource."));
        } else {
          console.error(pc.red(`API Error: ${error.message}`));
        }
      } else if (error instanceof Error) {
        console.error(pc.red(`Unexpected error: ${error.message}`));
        console.error(pc.dim("\nIf this persists, please report at:"));
        console.error(pc.dim("  https://github.com/Dlaranjo/pkgwatch/issues"));
      } else {
        console.error(pc.red(`Unexpected error: ${String(error)}`));
        console.error(pc.dim("\nIf this persists, please report at:"));
        console.error(pc.dim("  https://github.com/Dlaranjo/pkgwatch/issues"));
      }
      process.exit(EXIT_CLI_ERROR);
    }
  });

// ------------------------------------------------------------
// usage
// ------------------------------------------------------------
program
  .command("usage")
  .alias("u")
  .description("Show API usage statistics")
  .action(async () => {
    const client = getClient();
    const spinner = createSpinner("Fetching usage statistics...");

    try {
      const data = await client.getUsage();
      spinner?.stop();

      console.log("");
      console.log(pc.bold("API Usage"));
      console.log("");
      console.log(`  Tier:      ${data.tier}`);
      console.log(`  Used:      ${data.usage.requests_this_month.toLocaleString()} / ${data.usage.monthly_limit.toLocaleString()}`);
      console.log(`  Remaining: ${data.usage.remaining.toLocaleString()}`);
      console.log(`  Resets:    ${new Date(data.reset.date).toLocaleDateString()}`);
      console.log("");

      // Progress bar
      const pct = data.usage.usage_percentage;
      const filled = Math.round(pct / 5);
      const bar = pc.green("=".repeat(filled)) + pc.dim("-".repeat(20 - filled));
      console.log(`  [${bar}] ${pct.toFixed(1)}%`);
      console.log("");

      process.exit(EXIT_SUCCESS);
    } catch (error) {
      spinner?.stop();

      if (error instanceof ApiClientError) {
        if (error.code === "rate_limited") {
          console.error(pc.red("Rate limit exceeded."));
          console.error(pc.dim("Your API quota has been exhausted. Try again later or upgrade your plan."));
          console.error(pc.dim("  https://pkgwatch.dev/pricing"));
        } else if (error.code === "forbidden") {
          console.error(pc.red("Access denied - check your API key permissions."));
          console.error(pc.dim("Your API key may not have access to this resource."));
        } else {
          console.error(pc.red(`API Error: ${error.message}`));
        }
      } else if (error instanceof Error) {
        console.error(pc.red(`Unexpected error: ${error.message}`));
        console.error(pc.dim("\nIf this persists, please report at:"));
        console.error(pc.dim("  https://github.com/Dlaranjo/pkgwatch/issues"));
      } else {
        console.error(pc.red(`Unexpected error: ${String(error)}`));
        console.error(pc.dim("\nIf this persists, please report at:"));
        console.error(pc.dim("  https://github.com/Dlaranjo/pkgwatch/issues"));
      }
      process.exit(EXIT_CLI_ERROR);
    }
  });

// ------------------------------------------------------------
// doctor
// ------------------------------------------------------------
program
  .command("doctor")
  .description("Diagnose configuration and test API connectivity")
  .action(async () => {
    console.log(pc.bold("PkgWatch Doctor\n"));

    // Check 1: API key configured
    const apiKey = getApiKey();
    if (apiKey) {
      console.log(pc.green("✓") + " API key configured");
      console.log(pc.dim(`  Key: ${maskApiKey(apiKey)}`));
    } else {
      console.log(pc.red("✗") + " No API key configured");
      console.log(pc.dim("  Run: pkgwatch config set"));
      process.exit(EXIT_CLI_ERROR);
    }

    // Check 2: API connectivity
    const spinner = createSpinner("Testing API connectivity...");
    try {
      const client = new PkgWatchClient(apiKey);
      const data = await client.getUsage();
      spinner?.succeed("API connection successful");
      console.log(pc.dim(`  Tier: ${data.tier}`));
      console.log(pc.dim(`  Usage: ${data.usage.requests_this_month}/${data.usage.monthly_limit}`));
    } catch (error) {
      spinner?.fail("API connection failed");
      if (error instanceof ApiClientError) {
        console.log(pc.dim(`  Error: ${error.message}`));
        if (error.code === "unauthorized") {
          console.log(pc.dim("  Your API key may be invalid or expired"));
        }
      }
      process.exit(EXIT_CLI_ERROR);
    }

    // Check 3: Node.js version
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.slice(1).split(".")[0]);
    if (majorVersion >= 20) {
      console.log(pc.green("✓") + ` Node.js ${nodeVersion}`);
    } else {
      console.log(pc.yellow("!") + ` Node.js ${nodeVersion} (20+ recommended)`);
    }

    console.log(pc.green("\n✓ All checks passed"));
    process.exit(EXIT_SUCCESS);
  });

// ------------------------------------------------------------
// config <action>
// ------------------------------------------------------------
const configCmd = program
  .command("config")
  .description("Manage CLI configuration");

configCmd
  .command("set")
  .description("Set API key")
  .action(async () => {
    console.log("");
    console.log("Enter your PkgWatch API key.");
    console.log(pc.dim(`Get one at ${pc.underline("https://pkgwatch.dev")}`));
    console.log("");

    const key = await prompt("API Key: ");

    if (!key) {
      console.error(pc.red("Error: API key cannot be empty"));
      process.exit(EXIT_CLI_ERROR);
    }

    // Validate key format
    if (!key.startsWith("pw_")) {
      console.error(pc.red("Invalid API key format. Keys should start with 'pw_'"));
      process.exit(EXIT_CLI_ERROR);
    }

    // Test the key
    const spinner = createSpinner("Validating API key...");
    try {
      const client = new PkgWatchClient(key);
      const data = await client.getUsage();
      spinner?.succeed("API key validated");

      setApiKey(key);
      console.log(pc.green("\nAPI key saved successfully!"));
      console.log(pc.dim(`Tier: ${data.tier}`));
      console.log(pc.dim(`Monthly limit: ${data.usage.monthly_limit.toLocaleString()} requests`));
      console.log(pc.dim(`Config file: ${getConfigPath()}`));
    } catch (error) {
      spinner?.fail("API key validation failed");
      if (error instanceof ApiClientError && error.code === "unauthorized") {
        console.error(pc.red("\nInvalid API key. Please check your key and try again."));
        console.error(pc.dim("Get your API key at https://pkgwatch.dev"));
      } else if (error instanceof Error) {
        console.error(pc.red(`\nError: ${error.message}`));
      } else {
        console.error(pc.red(`\nError: ${String(error)}`));
      }
      process.exit(EXIT_CLI_ERROR);
    }
    process.exit(EXIT_SUCCESS);
  });

configCmd
  .command("show")
  .description("Show current configuration")
  .action(() => {
    const config = readConfig();
    const envKey = process.env.PKGWATCH_API_KEY;

    console.log("");
    console.log(pc.bold("Configuration"));
    console.log("");
    console.log(`  Config file: ${getConfigPath()}`);
    console.log("");

    if (envKey) {
      console.log(`  API Key (env): ${maskApiKey(envKey)}`);
    }
    if (config.apiKey) {
      console.log(`  API Key (file): ${maskApiKey(config.apiKey)}`);
    }
    if (!envKey && !config.apiKey) {
      console.log(pc.yellow("  No API key configured"));
    }

    console.log("");
    process.exit(EXIT_SUCCESS);
  });

configCmd
  .command("clear")
  .description("Clear configuration")
  .action(() => {
    clearConfig();
    console.log(pc.green("Configuration cleared."));
    process.exit(EXIT_SUCCESS);
  });

// ------------------------------------------------------------
// referral - Manage referral program
// ------------------------------------------------------------
const referralCmd = program
  .command("referral")
  .description("Manage your referral program");

referralCmd
  .command("status")
  .description("Show referral stats and bonus balance")
  .action(async () => {
    const spinner = createSpinner("Fetching referral status...");

    try {
      const client = getClient();
      const data = await client.getReferralStatus();

      spinner?.succeed("Referral status loaded");

      log("");
      log(pc.bold("Referral Program"));
      log(pc.dim("─".repeat(40)));
      log("");
      log(`${pc.cyan("Referral Link:")} ${data.referral_url}`);
      log(`${pc.green("Bonus Balance:")} ${data.bonus_requests.toLocaleString()} requests`);
      log(`${pc.dim("Lifetime Cap:")} ${data.bonus_lifetime.toLocaleString()} / ${data.bonus_cap.toLocaleString()}${data.at_cap ? pc.yellow(" (at cap)") : ""}`);
      log("");
      log(pc.bold("Stats"));
      log(`  Total Referrals: ${data.stats.total_referrals}`);
      log(`  Pending: ${data.stats.pending_referrals}`);
      log(`  Paid Conversions: ${data.stats.paid_conversions}`);
      log(`  Retained: ${data.stats.retained_conversions}`);
      log(`  Rewards Earned: ${data.stats.total_rewards_earned.toLocaleString()}`);

      if (data.referrals.length > 0) {
        log("");
        log(pc.bold("Recent Referrals"));
        for (const ref of data.referrals.slice(0, 5)) {
          const statusColor = ref.status === "credited" ? pc.green : pc.yellow;
          log(`  ${ref.email} - ${statusColor(ref.status)} ${ref.reward > 0 ? `(+${ref.reward.toLocaleString()})` : ""}`);
        }
      }

      process.exit(EXIT_SUCCESS);
    } catch (error) {
      spinner?.fail("Failed to fetch referral status");
      if (error instanceof ApiClientError) {
        if (error.code === "unauthorized") {
          console.error(pc.red("Requires session authentication. Please log in via the dashboard."));
        } else {
          console.error(pc.red(error.message));
        }
      } else {
        console.error(pc.red("Unknown error occurred"));
      }
      process.exit(EXIT_CLI_ERROR);
    }
  });

referralCmd
  .command("link")
  .description("Show your referral link")
  .action(async () => {
    try {
      const client = getClient();
      const data = await client.getReferralStatus();
      console.log(data.referral_url);
      process.exit(EXIT_SUCCESS);
    } catch (error) {
      if (error instanceof ApiClientError && error.code === "unauthorized") {
        console.error(pc.red("Requires session authentication. Please log in via the dashboard."));
      } else {
        console.error(pc.red("Failed to fetch referral link"));
      }
      process.exit(EXIT_CLI_ERROR);
    }
  });

// ------------------------------------------------------------
// feedback - Send feedback or report issues
// ------------------------------------------------------------
const feedbackCmd = program
  .command("feedback")
  .description("Send feedback or report issues");

feedbackCmd
  .command("bug")
  .description("Report a bug")
  .action(async () => {
    const url = `${GITHUB_REPO}/issues/new?template=bug_report.yml&labels=bug,cli`;
    await openUrl(url, "bug report form");
    process.exit(EXIT_SUCCESS);
  });

feedbackCmd
  .command("feature")
  .alias("idea")
  .description("Request a feature")
  .action(async () => {
    const url = `${GITHUB_REPO}/issues/new?template=feature_request.yml&labels=enhancement,cli`;
    await openUrl(url, "feature request form");
    process.exit(EXIT_SUCCESS);
  });

feedbackCmd
  .action(async () => {
    // Default action: open issue chooser
    const url = `${GITHUB_REPO}/issues/new/choose`;
    await openUrl(url, "feedback options");
    process.exit(EXIT_SUCCESS);
  });

// Add help text with exit codes and examples
program.addHelpText('after', `
Exit Codes:
  0   Success
  1   Risk threshold exceeded (with --fail-on)
  2   CLI error (invalid arguments, missing config)

Examples:
  pkgwatch check lodash                Check npm package (default)
  pkgwatch check requests -e pypi      Check Python package
  pkgwatch scan                        Auto-detect and scan dependencies
  pkgwatch scan ./python-project       Scan Python project (auto-detects requirements.txt)
  pkgwatch scan --fail-on HIGH         Scan and fail on HIGH+ risk
  pkgwatch scan -e pypi                Override ecosystem to PyPI
  pkgwatch scan --no-dev               Exclude dev dependencies
  pkgwatch scan -o json                Output as JSON
  pkgwatch scan -o sarif               Output as SARIF
  pkgwatch scan --recursive            Scan all manifests in repo (monorepo mode)
  pkgwatch scan -r --no-confirm        Recursive scan without confirmation
  pkgwatch scan -r --max-manifests 50  Limit to 50 manifests
  pkgwatch scan -r --ignore-not-found  Hide packages not found in registry
  pkgwatch doctor                      Diagnose configuration issues
  pkgwatch referral status             Show referral program stats
  pkgwatch referral link               Print your referral link
  pkgwatch feedback                    Open feedback options
  pkgwatch feedback bug                Report a bug
  pkgwatch feedback feature            Request a new feature

Supported dependency files:
  npm:  package.json
  pypi: pyproject.toml, requirements.txt, Pipfile
`);

// Parse and run
program.parse();
