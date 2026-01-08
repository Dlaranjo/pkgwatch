#!/usr/bin/env node
/**
 * DepHealth CLI - Check npm package health scores from the command line.
 *
 * Usage:
 *   dephealth check <package>      Check a single package
 *   dephealth scan [path]          Scan package.json dependencies
 *   dephealth usage                Show API usage statistics
 *   dephealth config <action>      Manage configuration
 */

import { program } from "commander";
import pc from "picocolors";
import ora, { type Ora } from "ora";
import { readFileSync, existsSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";

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

import {
  DepHealthClient,
  ApiClientError,
  getRiskColor,
  type PackageHealthFull,
  type PackageHealth,
} from "./api.js";
import {
  getApiKey,
  setApiKey,
  clearConfig,
  getConfigPath,
  maskApiKey,
  readConfig,
} from "./config.js";

// Exit codes
const EXIT_SUCCESS = 0;
const EXIT_RISK_EXCEEDED = 1;
const EXIT_CLI_ERROR = 2;

/**
 * Get API client, exiting if no API key is configured.
 */
function getClient(): DepHealthClient {
  const apiKey = getApiKey();
  if (!apiKey) {
    console.error(pc.red("Error: No API key configured."));
    console.error("");
    console.error("Set your API key using one of:");
    console.error(`  ${pc.cyan("dephealth config set")}           # Interactive setup`);
    console.error(`  ${pc.cyan("export DEPHEALTH_API_KEY=dh_...")}  # Environment variable`);
    console.error("");
    console.error(`Get your API key at ${pc.underline("https://dephealth.laranjo.dev")}`);
    process.exit(EXIT_CLI_ERROR);
  }
  return new DepHealthClient(apiKey);
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

  console.log("");

  // Component scores
  console.log(pc.dim("  Components:"));
  console.log(`    Maintainer:  ${pkg.components.maintainer_health.toFixed(0)}/100`);
  console.log(`    Evolution:   ${pkg.components.evolution_health.toFixed(0)}/100`);
  console.log(`    Community:   ${pkg.components.community_health.toFixed(0)}/100`);
  console.log(`    User Impact: ${pkg.components.user_centric.toFixed(0)}/100`);
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
  .name("dephealth")
  .description("Check npm package health scores from the command line")
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

      process.exit(EXIT_SUCCESS);
    } catch (error) {
      spinner?.stop();
      if (error instanceof ApiClientError) {
        if (error.status === 404) {
          console.error(pc.red(`Package not found: ${packageName}`));
        } else {
          console.error(pc.red(`API Error: ${error.message}`));
        }
      } else {
        console.error(pc.red(`Error: ${(error as Error).message}`));
      }
      process.exit(EXIT_CLI_ERROR);
    }
  });

// ------------------------------------------------------------
// scan [path]
// ------------------------------------------------------------
program
  .command("scan [path]")
  .description("Scan dependencies in a package.json file")
  .option("--json", "Output as JSON")
  .option("--fail-on <level>", "Exit 1 if risk level reached (HIGH or CRITICAL)")
  .action(async (path: string | undefined, options: { json?: boolean; failOn?: string }) => {
    // Validate --fail-on value
    const VALID_FAIL_ON = ["HIGH", "CRITICAL"];
    if (options.failOn && !VALID_FAIL_ON.includes(options.failOn.toUpperCase())) {
      console.error(pc.red(`Invalid --fail-on value: ${options.failOn}`));
      console.error(`Valid options: ${VALID_FAIL_ON.join(", ")}`);
      process.exit(EXIT_CLI_ERROR);
    }

    const client = getClient();
    const filePath = resolvePath(path || ".", path?.endsWith(".json") ? "" : "package.json");

    const dependencies = readPackageJson(filePath);
    const depCount = Object.keys(dependencies).length;

    if (depCount === 0) {
      log(pc.yellow("No dependencies found in package.json"));
      process.exit(EXIT_SUCCESS);
    }

    const spinner = options.json ? null : createSpinner(`Scanning ${depCount} dependencies...`);
    logVerbose(`Reading ${filePath}`);

    try {
      const result = await client.scan(dependencies);
      spinner?.stop();

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        // Group by risk level
        const critical = result.packages.filter((p) => p.risk_level === "CRITICAL");
        const high = result.packages.filter((p) => p.risk_level === "HIGH");
        const medium = result.packages.filter((p) => p.risk_level === "MEDIUM");
        const low = result.packages.filter((p) => p.risk_level === "LOW");

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
      }

      // Check fail-on threshold
      if (options.failOn) {
        const threshold = options.failOn.toUpperCase();
        if (threshold === "CRITICAL" && result.critical > 0) {
          process.exit(EXIT_RISK_EXCEEDED);
        }
        if (threshold === "HIGH" && (result.critical > 0 || result.high > 0)) {
          process.exit(EXIT_RISK_EXCEEDED);
        }
      }

      process.exit(EXIT_SUCCESS);
    } catch (error) {
      spinner?.stop();
      if (error instanceof ApiClientError) {
        console.error(pc.red(`API Error: ${error.message}`));
      } else {
        console.error(pc.red(`Error: ${(error as Error).message}`));
      }
      process.exit(EXIT_CLI_ERROR);
    }
  });

// ------------------------------------------------------------
// usage
// ------------------------------------------------------------
program
  .command("usage")
  .description("Show API usage statistics")
  .action(async () => {
    const client = getClient();

    try {
      const data = await client.getUsage();

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
      if (error instanceof ApiClientError) {
        console.error(pc.red(`API Error: ${error.message}`));
      } else {
        console.error(pc.red(`Error: ${(error as Error).message}`));
      }
      process.exit(EXIT_CLI_ERROR);
    }
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
    console.log("Enter your DepHealth API key.");
    console.log(pc.dim(`Get one at ${pc.underline("https://dephealth.laranjo.dev")}`));
    console.log("");

    const key = await prompt("API Key: ");

    if (!key) {
      console.error(pc.red("Error: API key cannot be empty"));
      process.exit(EXIT_CLI_ERROR);
    }

    if (!key.startsWith("dh_")) {
      console.error(pc.yellow("Warning: API key should start with 'dh_'"));
    }

    setApiKey(key);
    console.log(pc.green("API key saved!"));
    console.log(pc.dim(`Config file: ${getConfigPath()}`));
    process.exit(EXIT_SUCCESS);
  });

configCmd
  .command("show")
  .description("Show current configuration")
  .action(() => {
    const config = readConfig();
    const envKey = process.env.DEPHEALTH_API_KEY;

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

// Parse and run
program.parse();
