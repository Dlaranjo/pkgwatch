import * as core from "@actions/core";
import * as path from "node:path";
import { scanDependencies } from "./scanner.js";
import { generateSummary } from "./summary.js";
import { ApiClientError } from "./api.js";

async function run(): Promise<void> {
  try {
    // Get and mask API key immediately (security)
    const apiKey = core.getInput("api-key", { required: true });
    core.setSecret(apiKey);

    const workingDirectory = core.getInput("working-directory") || ".";
    const failOn = core.getInput("fail-on")?.toUpperCase() || "";
    const includeDev = core.getInput("include-dev") !== "false";

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
    core.setOutput("results", JSON.stringify(result));

    // Generate job summary
    await generateSummary(result, failed, failOn);

    // Log summary
    core.info(
      `Scan complete: ${result.total} packages (${result.critical} critical, ${result.high} high, ${result.medium} medium, ${result.low} low)`
    );

    // Exit based on threshold
    if (failed) {
      core.setFailed(
        `Found ${result.critical} CRITICAL and ${result.high} HIGH risk packages (threshold: ${failOn})`
      );
    }
  } catch (error) {
    handleError(error);
  }
}

function handleError(error: unknown): void {
  if (error instanceof ApiClientError) {
    switch (error.code) {
      case "unauthorized":
        core.setFailed(
          `Authentication failed (401)\n\nYour API key appears to be invalid or expired.\nVerify at https://dephealth.laranjo.dev/dashboard`
        );
        break;
      case "rate_limited":
        core.setFailed(
          `Rate limit exceeded (429)\n\nYour API quota has been exhausted.\nUpgrade at https://dephealth.laranjo.dev/pricing`
        );
        break;
      case "timeout":
        core.setFailed(
          `Request timed out\n\nThe DepHealth API did not respond in time.\nCheck https://status.dephealth.laranjo.dev`
        );
        break;
      case "network_error":
        core.setFailed(
          `Network error\n\nUnable to reach DepHealth API.\nCheck https://status.dephealth.laranjo.dev`
        );
        break;
      default:
        core.setFailed(`API error: ${error.message}`);
    }
  } else if (error instanceof Error) {
    core.setFailed(`Action failed: ${error.message}`);
  } else {
    core.setFailed("An unknown error occurred");
  }
}

run();
