# Agent Prompt: CLI and GitHub Action UX Improvements

## Context

You are working on DepHealth, a dependency health intelligence platform. The CLI and GitHub Action are the primary interfaces for developers. They need UX improvements for better discoverability, feedback, and error handling.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 6: CLI/Action UX Review)

## Your Mission

Improve the developer experience of the CLI and GitHub Action with better commands, progress indicators, and error handling.

## Current CLI Structure

```
dephealth
  check <package>     Check single package
  scan [path]         Scan package.json
  usage               Show API usage
  config
    set               Set API key
    show              Show config
    clear             Clear config
```

### Key Files
- `cli/src/index.ts` - CLI main entry (496 lines)
- `cli/src/config.ts` - Configuration management
- `cli/src/api.ts` - API client re-export
- `action/src/index.ts` - GitHub Action entry
- `action/src/scanner.ts` - Package.json scanner
- `action/src/summary.ts` - Job summary generator
- `packages/api-client/src/index.ts` - Shared API client

## Improvements to Implement

### 1. Add Command Aliases (HIGH PRIORITY - Quick Win)

**Location:** `cli/src/index.ts`

**Current:**
```typescript
program
  .command("check <package>")
  .description("Check health score for a single package")
```

**Add aliases:**
```typescript
program
  .command("check <package>")
  .alias("c")
  .description("Check health score for a single package")

program
  .command("scan [path]")
  .alias("s")
  .description("Scan package.json dependencies")

program
  .command("usage")
  .alias("u")
  .description("Show API usage statistics")
```

### 2. Add `dephealth doctor` Command (HIGH PRIORITY)

**Location:** `cli/src/index.ts`

**Purpose:** Diagnose configuration issues and test API connectivity.

**Implementation:**
```typescript
program
  .command("doctor")
  .description("Diagnose configuration and test API connectivity")
  .action(async () => {
    console.log(pc.bold("DepHealth Doctor\n"));

    // Check 1: API key configured
    const apiKey = getApiKey();
    if (apiKey) {
      console.log(pc.green("✓") + " API key configured");
      console.log(pc.dim(`  Key: ${maskKey(apiKey)}`));
    } else {
      console.log(pc.red("✗") + " No API key configured");
      console.log(pc.dim("  Run: dephealth config set"));
      process.exit(EXIT_CLI_ERROR);
    }

    // Check 2: API connectivity
    const spinner = createSpinner("Testing API connectivity...");
    try {
      const client = new DepHealthClient(apiKey);
      const usage = await client.getUsage();
      spinner?.succeed("API connection successful");
      console.log(pc.dim(`  Tier: ${usage.tier}`));
      console.log(pc.dim(`  Usage: ${usage.requests_this_month}/${usage.monthly_limit}`));
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
    if (majorVersion >= 18) {
      console.log(pc.green("✓") + ` Node.js ${nodeVersion}`);
    } else {
      console.log(pc.yellow("!") + ` Node.js ${nodeVersion} (18+ recommended)`);
    }

    console.log(pc.green("\n✓ All checks passed"));
  });
```

### 3. Validate API Key on `config set` (HIGH PRIORITY)

**Location:** `cli/src/index.ts` - config set command

**Current:**
```typescript
.action(async (key) => {
  setApiKey(key);
  console.log(pc.green("API key saved successfully!"));
});
```

**Improved:**
```typescript
.action(async (key) => {
  // Validate key format
  if (!key.startsWith("dh_")) {
    console.error(pc.red("Invalid API key format. Keys should start with 'dh_'"));
    process.exit(EXIT_CLI_ERROR);
  }

  // Test the key
  const spinner = createSpinner("Validating API key...");
  try {
    const client = new DepHealthClient(key);
    const usage = await client.getUsage();
    spinner?.succeed("API key validated");

    setApiKey(key);
    console.log(pc.green("\nAPI key saved successfully!"));
    console.log(pc.dim(`Tier: ${usage.tier}`));
    console.log(pc.dim(`Monthly limit: ${usage.monthly_limit.toLocaleString()} requests`));
  } catch (error) {
    spinner?.fail("API key validation failed");
    if (error instanceof ApiClientError && error.code === "unauthorized") {
      console.error(pc.red("\nInvalid API key. Please check your key and try again."));
      console.error(pc.dim("Get your API key at https://dephealth.laranjo.dev"));
    } else {
      console.error(pc.red(`\nError: ${(error as Error).message}`));
    }
    process.exit(EXIT_CLI_ERROR);
  }
});
```

### 4. Add Progress Bar for Large Scans (MEDIUM PRIORITY)

**Location:** `cli/src/index.ts` - scan command

**Dependencies to add:**
```bash
cd cli
npm install cli-progress @types/cli-progress
```

**Implementation:**
```typescript
import cliProgress from "cli-progress";

// In scan action
const dependencies = Object.keys(packageJson.dependencies || {});
const devDependencies = Object.keys(packageJson.devDependencies || {});
const allDeps = [...new Set([...dependencies, ...devDependencies])];

if (allDeps.length > 20 && !quietMode) {
  // Use progress bar for larger scans
  const progressBar = new cliProgress.SingleBar({
    format: 'Scanning |{bar}| {percentage}% | {value}/{total} packages',
    barCompleteChar: '█',
    barIncompleteChar: '░',
  });

  progressBar.start(allDeps.length, 0);

  // Batch processing with progress updates
  const batchSize = 25;
  const results = [];

  for (let i = 0; i < allDeps.length; i += batchSize) {
    const batch = allDeps.slice(i, i + batchSize);
    const batchResults = await client.scan({ dependencies: batch });
    results.push(...batchResults.packages);
    progressBar.update(Math.min(i + batchSize, allDeps.length));
  }

  progressBar.stop();
} else {
  // Use spinner for smaller scans
  const spinner = createSpinner("Scanning dependencies...");
  // ... existing logic
}
```

### 5. Add `--output` Format Option (MEDIUM PRIORITY)

**Location:** `cli/src/index.ts`

**Current:** Only `--json` flag exists.

**Improved:**
```typescript
program
  .command("scan [path]")
  .option("-o, --output <format>", "Output format: json, table, sarif", "table")
  .action(async (path, options) => {
    // ... scanning logic ...

    switch (options.output) {
      case "json":
        console.log(JSON.stringify(result, null, 2));
        break;
      case "table":
        printResultsTable(result);
        break;
      case "sarif":
        console.log(JSON.stringify(toSarif(result), null, 2));
        break;
      default:
        console.error(pc.red(`Unknown output format: ${options.output}`));
        process.exit(EXIT_CLI_ERROR);
    }
  });

// SARIF format for security tooling integration
function toSarif(result: ScanResult): object {
  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "dephealth",
          version: VERSION,
          informationUri: "https://dephealth.laranjo.dev",
        }
      },
      results: result.packages
        .filter(p => p.risk_level === "CRITICAL" || p.risk_level === "HIGH")
        .map(p => ({
          ruleId: `dephealth/${p.risk_level.toLowerCase()}`,
          level: p.risk_level === "CRITICAL" ? "error" : "warning",
          message: {
            text: `${p.package}: ${p.risk_level} risk (health score: ${p.health_score})`,
          },
        })),
    }],
  };
}
```

### 6. Add Rate Limit Warning (MEDIUM PRIORITY)

**Location:** `cli/src/index.ts` - after API calls

**Implementation:**
```typescript
// After successful API response, check remaining quota
function checkRateLimitWarning(headers: Record<string, string>) {
  const limit = parseInt(headers["x-ratelimit-limit"] || "0");
  const remaining = parseInt(headers["x-ratelimit-remaining"] || "0");

  if (limit > 0) {
    const usedPercent = ((limit - remaining) / limit) * 100;

    if (usedPercent >= 95) {
      console.log(pc.red(`\n⚠ Warning: ${remaining} requests remaining this month (${usedPercent.toFixed(0)}% used)`));
      console.log(pc.dim("  Upgrade at https://dephealth.laranjo.dev/pricing"));
    } else if (usedPercent >= 80) {
      console.log(pc.yellow(`\n⚠ ${remaining} requests remaining this month (${usedPercent.toFixed(0)}% used)`));
    }
  }
}
```

### 7. Improve Error Messages with Report Link (LOW PRIORITY)

**Location:** `cli/src/index.ts` - error handling

**Current:**
```typescript
console.error(pc.red(`Error: ${(error as Error).message}`));
```

**Improved:**
```typescript
console.error(pc.red(`Unexpected error: ${(error as Error).message}`));
console.error(pc.dim("\nIf this persists, please report at:"));
console.error(pc.dim("  https://github.com/dephealth/cli/issues"));
```

### 8. Add Exit Codes to Help (LOW PRIORITY)

**Location:** `cli/src/index.ts`

```typescript
program.addHelpText('after', `
Exit Codes:
  0   Success
  1   Risk threshold exceeded (with --fail-on)
  2   CLI error (invalid arguments, missing config)

Examples:
  dephealth check lodash
  dephealth scan --fail-on HIGH
  dephealth scan ./packages/frontend
`);
```

## GitHub Action Improvements

### 9. Add Soft Fail Option (MEDIUM PRIORITY)

**Location:** `action/action.yml` and `action/src/index.ts`

**In action.yml:**
```yaml
inputs:
  soft-fail:
    description: 'Set outputs but do not fail the workflow even if risk threshold exceeded'
    required: false
    default: 'false'
```

**In index.ts:**
```typescript
const softFail = core.getInput("soft-fail") === "true";

// At the end, instead of always failing:
if (shouldFail && !softFail) {
  core.setFailed(`Found packages exceeding ${failOn} risk threshold`);
} else if (shouldFail && softFail) {
  core.warning(`Found packages exceeding ${failOn} risk threshold (soft-fail mode)`);
}
```

### 10. Add GitHub Annotations (LOW PRIORITY)

**Location:** `action/src/index.ts`

```typescript
// Add annotations for high-risk packages
for (const pkg of result.packages) {
  if (pkg.risk_level === "CRITICAL" || pkg.risk_level === "HIGH") {
    core.warning(
      `${pkg.package}: ${pkg.risk_level} risk (health score: ${pkg.health_score}/100)`,
      {
        title: "Dependency Health Warning",
        file: "package.json",
      }
    );
  }
}
```

## Files to Modify

| File | Changes |
|------|---------|
| `cli/src/index.ts` | Add aliases, doctor command, progress bar, output formats |
| `cli/package.json` | Add cli-progress dependency |
| `action/action.yml` | Add soft-fail input |
| `action/src/index.ts` | Add soft-fail handling, annotations |
| `cli/README.md` | Update documentation |
| `action/README.md` | Update documentation |

## Testing Requirements

```bash
# CLI tests
cd cli
npm test

# Action tests
cd action
npm test
```

Manual testing:
```bash
# Test doctor command
dephealth doctor

# Test aliases
dephealth c lodash
dephealth s --fail-on HIGH

# Test progress bar (need many deps)
dephealth scan /path/to/large/project

# Test output formats
dephealth scan --output json
dephealth scan --output sarif
```

## Success Criteria

1. Command aliases working (c, s, u)
2. `dephealth doctor` command implemented
3. API key validated on `config set`
4. Progress bar shown for 20+ dependencies
5. `--output` option supports json, table, sarif
6. Rate limit warnings at 80% and 95%
7. Exit codes documented in help
8. Soft-fail option in GitHub Action
9. All tests pass
10. Documentation updated

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 6 for full CLI/Action UX analysis.
