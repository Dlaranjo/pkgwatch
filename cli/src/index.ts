#!/usr/bin/env node
/**
 * PkgWatch CLI - Check package health scores from the command line.
 *
 * Usage:
 *   pkgwatch check <package>      Check a single package
 *   pkgwatch scan [path]          Scan package.json dependencies
 *   pkgwatch usage                Show API usage statistics
 *   pkgwatch config <action>      Manage configuration
 */

import { program } from "commander";
import pc from "picocolors";
import ora, { type Ora } from "ora";
import cliProgress from "cli-progress";
import { readFileSync, existsSync } from "node:fs";
import { resolve as resolvePath, relative as relativePath } from "node:path";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";

// Exit codes (defined early for global error handler)
const EXIT_SUCCESS = 0;
const EXIT_RISK_EXCEEDED = 1;
const EXIT_CLI_ERROR = 2;

// Global unhandled rejection handler to prevent silent crashes
process.on("unhandledRejection", (error) => {
  console.error(pc.red("Unexpected error:"), error instanceof Error ? error.message : String(error));
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
      console.log(pc.dim("  Upgrade at https://pkgwatch.laranjo.dev/pricing"));
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
  type PackageHealthFull,
  type PackageHealth,
  type ScanResult,
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
 * Get API client, exiting if no API key is configured.
 */
function getClient(): PkgWatchClient {
  const apiKey = getApiKey();
  if (!apiKey) {
    console.error(pc.red("Error: No API key configured."));
    console.error("");
    console.error("Set your API key using one of:");
    console.error(`  ${pc.cyan("pkgwatch config set")}           # Interactive setup`);
    console.error(`  ${pc.cyan("export PKGWATCH_API_KEY=pw_...")}  # Environment variable`);
    console.error("");
    console.error(`Get your API key at ${pc.underline("https://pkgwatch.laranjo.dev")}`);
    process.exit(EXIT_CLI_ERROR);
  }
  return new PkgWatchClient(apiKey);
}

/**
 * Format health score with color.
 */
function formatScore(score: number): string {
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
          informationUri: "https://pkgwatch.laranjo.dev",
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
}

/**
 * Read and parse package.json from path.
 */
function readPackageJson(filePath: string): Record<string, string> {
  if (!existsSync(filePath)) {
    console.error(pc.red(`Error: File not found: ${filePath}`));
    process.exit(EXIT_CLI_ERROR);
  }

  try {
    const content = readFileSync(filePath, "utf-8");
    const pkg = JSON.parse(content);
    return {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
    };
  } catch (error) {
    console.error(pc.red(`Error: Failed to parse ${filePath}`));
    console.error((error as Error).message);
    process.exit(EXIT_CLI_ERROR);
  }
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
  .hook("preAction", (thisCommand) => {
    const opts = thisCommand.opts();
    quietMode = opts.quiet ?? false;
    verboseMode = opts.verbose ?? false;
  });

// ------------------------------------------------------------
// check <package>
// ------------------------------------------------------------
program
  .command("check <package>")
  .alias("c")
  .description("Check health score for a single package")
  .option("--json", "Output as JSON")
  .action(async (packageName: string, options: { json?: boolean }) => {
    const client = getClient();
    const spinner = createSpinner(`Checking ${packageName}...`);
    logVerbose(`Fetching package data from API`);

    try {
      const pkg = await client.getPackage(packageName);
      spinner?.stop();

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
          console.error(pc.dim("  https://pkgwatch.laranjo.dev/pricing"));
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
// scan [path]
// ------------------------------------------------------------
program
  .command("scan [path]")
  .alias("s")
  .description("Scan dependencies in a package.json file")
  .option("--json", "Output as JSON (deprecated, use --output json)")
  .option("-o, --output <format>", "Output format: table, json, sarif", "table")
  .option("--fail-on <level>", "Exit 1 if risk level reached (HIGH or CRITICAL)")
  .action(async (path: string | undefined, options: { json?: boolean; output?: string; failOn?: string }) => {
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

    const client = getClient();

    // Resolve the file path
    const cwd = process.cwd();
    let filePath: string;
    if (!path) {
      filePath = resolvePath(cwd, "package.json");
    } else if (path.endsWith(".json")) {
      filePath = resolvePath(cwd, path);
    } else {
      filePath = resolvePath(cwd, path, "package.json");
    }

    // Security: Validate path is within current working directory
    const relPath = relativePath(cwd, filePath);
    if (relPath.startsWith("..") && !relPath.startsWith("..\\") && relPath !== "..") {
      // Allow paths like "../sibling-project/package.json" for monorepo use
      // but warn the user
      logVerbose(`Scanning path outside current directory: ${filePath}`);
    }

    const dependencies = readPackageJson(filePath);
    const depCount = Object.keys(dependencies).length;

    if (depCount === 0) {
      log(pc.yellow("No dependencies found in package.json"));
      process.exit(EXIT_SUCCESS);
    }

    logVerbose(`Reading ${filePath}`);

    // Constants for progress bar and batching
    const PROGRESS_BAR_THRESHOLD = 20;
    const BATCH_SIZE = 25;

    let result: ScanResult;
    let activeProgressBar: cliProgress.SingleBar | null = null;

    try {
      // Use progress bar for large scans (20+ dependencies)
      if (depCount >= PROGRESS_BAR_THRESHOLD && outputFormat === "table" && !quietMode) {
        activeProgressBar = new cliProgress.SingleBar({
          format: 'Scanning |{bar}| {percentage}% | {value}/{total} packages',
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
            const batchResult = await client.scan(batchDeps);
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

        // Aggregate results
        result = {
          total: allPackages.length,
          critical: allPackages.filter((p: PackageHealth) => p.risk_level === "CRITICAL").length,
          high: allPackages.filter((p: PackageHealth) => p.risk_level === "HIGH").length,
          medium: allPackages.filter((p: PackageHealth) => p.risk_level === "MEDIUM").length,
          low: allPackages.filter((p: PackageHealth) => p.risk_level === "LOW").length,
          packages: allPackages,
          not_found: notFound.length > 0 ? notFound : undefined,
        };
      } else {
        // Use spinner for smaller scans
        const spinner = outputFormat !== "table" ? null : createSpinner(`Scanning ${depCount} dependencies...`);
        result = await client.scan(dependencies);
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
            log(`  ${pc.red(pkg.package.padEnd(20))} ${formatScore(pkg.health_score)}   ${reason}`);
          }
          log("");
        }

        if (high.length > 0) {
          log(pc.red(`HIGH (${high.length})`));
          for (const pkg of high) {
            const reason = pkg.abandonment_risk?.risk_factors?.[0] || "";
            log(`  ${pkg.package.padEnd(20)} ${formatScore(pkg.health_score)}   ${reason}`);
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
          console.error(pc.dim("  https://pkgwatch.laranjo.dev/pricing"));
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
          console.error(pc.dim("  https://pkgwatch.laranjo.dev/pricing"));
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
    console.log(pc.dim(`Get one at ${pc.underline("https://pkgwatch.laranjo.dev")}`));
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
        console.error(pc.dim("Get your API key at https://pkgwatch.laranjo.dev"));
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

// Add help text with exit codes and examples
program.addHelpText('after', `
Exit Codes:
  0   Success
  1   Risk threshold exceeded (with --fail-on)
  2   CLI error (invalid arguments, missing config)

Examples:
  pkgwatch check lodash              Check single package
  pkgwatch c lodash                  Check with alias
  pkgwatch scan --fail-on HIGH       Scan and fail on HIGH+ risk
  pkgwatch scan ./packages/frontend  Scan specific directory
  pkgwatch scan -o json              Output as JSON
  pkgwatch scan -o sarif             Output as SARIF
  pkgwatch doctor                    Diagnose configuration issues
`);

// Parse and run
program.parse();
