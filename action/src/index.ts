import * as core from "@actions/core";
import * as path from "node:path";
import { scanDependencies } from "./scanner";
import { generateSummary } from "./summary";
import { ApiClientError } from "./api";

async function run(): Promise<void> {
  try {
    // Get and mask API key immediately (security)
    const apiKey = core.getInput("api-key", { required: true });
    core.setSecret(apiKey);

    const workingDirectory = core.getInput("working-directory") || ".";
    const failOn = core.getInput("fail-on")?.toUpperCase() || "";
    const includeDev = !["false", "no", "0"].includes(core.getInput("include-dev")?.toLowerCase() || "");
    const softFail = ["true", "yes", "1"].includes(core.getInput("soft-fail")?.toLowerCase() || "");

    // Validate fail-on
    if (failOn && !["HIGH", "CRITICAL"].includes(failOn)) {
      core.setFailed(
        `Invalid 'fail-on' value: ${failOn}\n\nValid options: HIGH, CRITICAL, or empty (never fail)`
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
            file: "package.json",
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
  } catch (error) {
    handleError(error);
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
          `Authentication failed (401)\n\nYour API key appears to be invalid or expired.\nVerify at https://pkgwatch.laranjo.dev/dashboard`
        );
        break;
      case "forbidden":
        core.setFailed(
          `Access forbidden (403)\n\nYour account may have exceeded plan limits or been disabled.\nCheck https://pkgwatch.laranjo.dev/dashboard`
        );
        break;
      case "rate_limited":
        core.setFailed(
          `Rate limit exceeded (429)\n\nYour API quota has been exhausted.\nUpgrade at https://pkgwatch.laranjo.dev/pricing`
        );
        break;
      case "timeout":
        core.setFailed(
          `Request timed out\n\nThe PkgWatch API did not respond in time.\nCheck https://status.pkgwatch.laranjo.dev`
        );
        break;
      case "network_error":
        core.setFailed(
          `Network error\n\nUnable to reach PkgWatch API.\nCheck https://status.pkgwatch.laranjo.dev`
        );
        break;
      default:
        core.setFailed(`API error: ${error.message}`);
    }
  } else if (error instanceof Error) {
    // Handle specific error messages with better guidance
    if (error.message.includes("Invalid API key format")) {
      core.setFailed(
        `Invalid API key format\n\nAPI keys should start with 'pw_'.\nGet your key at https://pkgwatch.laranjo.dev/dashboard`
      );
    } else if (error.message.includes("API key is required")) {
      core.setFailed(
        `API key is required\n\nPlease provide your API key via the 'api-key' input.\nGet your key at https://pkgwatch.laranjo.dev/dashboard`
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
