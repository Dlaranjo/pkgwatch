/**
 * Tests for CLI command parsing, validation, and output formatting.
 *
 * These tests verify the CLI handles various input scenarios correctly
 * without actually making API calls.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { spawn, ChildProcess } from "node:child_process";
import { join } from "node:path";
import { mkdirSync, rmSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

// Path to the CLI entry point (compiled)
const CLI_PATH = join(__dirname, "../../dist/index.js");

// Helper to run CLI and capture output
interface CLIResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

async function runCLI(args: string[], options: { timeout?: number; env?: Record<string, string> } = {}): Promise<CLIResult> {
  return new Promise((resolve) => {
    const timeout = options.timeout || 5000;
    const env = { ...process.env, ...options.env, NO_COLOR: "1" }; // Disable colors for testing
    let resolved = false;

    const proc = spawn("node", [CLI_PATH, ...args], { env });

    let stdout = "";
    let stderr = "";

    // spawn() ignores the timeout option — kill manually
    const killTimer = setTimeout(() => {
      if (!resolved) {
        proc.kill();
      }
    }, timeout);

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(killTimer);
        resolve({ stdout, stderr, exitCode: code });
      }
    });

    proc.on("error", () => {
      if (!resolved) {
        resolved = true;
        clearTimeout(killTimer);
        resolve({ stdout, stderr, exitCode: -1 });
      }
    });
  });
}

describe("CLI commands", () => {
  describe("version and help", () => {
    it("shows version with --version flag", async () => {
      const result = await runCLI(["--version"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toMatch(/\d+\.\d+\.\d+/); // semver pattern
    });

    it("shows version with -V flag", async () => {
      const result = await runCLI(["-V"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toMatch(/\d+\.\d+\.\d+/);
    });

    it("shows help with --help flag", async () => {
      const result = await runCLI(["--help"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Usage:");
      expect(result.stdout).toContain("pkgwatch");
      expect(result.stdout).toContain("check");
      expect(result.stdout).toContain("scan");
    });

    it("shows help with -h flag", async () => {
      const result = await runCLI(["-h"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Usage:");
    });

    it("shows command-specific help", async () => {
      const result = await runCLI(["check", "--help"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("check");
      expect(result.stdout).toContain("package");
    });

    it("shows scan command help", async () => {
      const result = await runCLI(["scan", "--help"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("scan");
      expect(result.stdout).toContain("--fail-on");
      expect(result.stdout).toContain("--output");
    });

    it("shows config command help", async () => {
      const result = await runCLI(["config", "--help"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("config");
      expect(result.stdout).toContain("set");
      expect(result.stdout).toContain("show");
      expect(result.stdout).toContain("clear");
    });

    it("shows exit codes in help", async () => {
      const result = await runCLI(["--help"]);
      expect(result.stdout).toContain("Exit Codes:");
      expect(result.stdout).toContain("0");
      expect(result.stdout).toContain("1");
      expect(result.stdout).toContain("2");
    });

    it("shows examples in help", async () => {
      const result = await runCLI(["--help"]);
      expect(result.stdout).toContain("Examples:");
      expect(result.stdout).toContain("pkgwatch check lodash");
    });
  });

  describe("check command argument validation", () => {
    it("requires package argument", async () => {
      const result = await runCLI(["check"]);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("missing required argument");
    });

    it("accepts ecosystem option", async () => {
      // This will fail at API call, but validates option parsing
      const result = await runCLI(["check", "lodash", "-e", "npm"]);
      // Should not error on option parsing (may error on API)
      expect(result.stderr).not.toContain("unknown option");
    });

    it("validates ecosystem choices", async () => {
      const result = await runCLI(["check", "lodash", "-e", "invalid"]);
      expect(result.exitCode).not.toBe(0);
      // Commander shows: Allowed choices are npm, pypi.
      expect(result.stderr).toContain("npm");
      expect(result.stderr).toContain("pypi");
    });

    it("accepts json output flag", async () => {
      const result = await runCLI(["check", "lodash", "--json"]);
      // Should not error on flag parsing
      expect(result.stderr).not.toContain("unknown option");
    });

    it("accepts command alias c", async () => {
      const result = await runCLI(["c", "--help"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("check");
    });
  });

  describe("scan command argument validation", () => {
    it("accepts optional path argument", async () => {
      const result = await runCLI(["scan", "--help"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("[path]");
    });

    it("validates output format choices", async () => {
      const result = await runCLI(["scan", "-o", "invalid"]);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr.toLowerCase()).toContain("invalid");
    });

    it("validates fail-on choices", async () => {
      const result = await runCLI(["scan", "--fail-on", "INVALID"]);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("HIGH");
      expect(result.stderr).toContain("CRITICAL");
    });

    it("accepts --no-dev flag", async () => {
      const result = await runCLI(["scan", "--no-dev", "--help"]);
      // Help should still show (flag is valid)
      expect(result.stdout).toContain("scan");
    });

    it("accepts recursive flag", async () => {
      const result = await runCLI(["scan", "-r", "--help"]);
      expect(result.stdout).toContain("recursive");
    });

    it("accepts max-manifests option", async () => {
      const result = await runCLI(["scan", "--max-manifests", "50", "--help"]);
      expect(result.exitCode).toBe(0);
    });

    it("accepts command alias s", async () => {
      const result = await runCLI(["s", "--help"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("scan");
    });

    it("shows SARIF in output options", async () => {
      const result = await runCLI(["scan", "--help"]);
      expect(result.stdout.toLowerCase()).toContain("sarif");
    });
  });

  describe("config command validation", () => {
    it("lists config subcommands", async () => {
      const result = await runCLI(["config", "--help"]);
      expect(result.stdout).toContain("set");
      expect(result.stdout).toContain("show");
      expect(result.stdout).toContain("clear");
    });

    it("config show works without API key", async () => {
      const result = await runCLI(["config", "show"], {
        env: { HOME: tmpdir() }, // Use temp home to avoid real config
      });
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Config");
    });

    it("config clear exits successfully", async () => {
      const testHome = join(tmpdir(), `pkgwatch-cli-test-${Date.now()}`);
      mkdirSync(testHome, { recursive: true });

      const result = await runCLI(["config", "clear"], {
        env: { HOME: testHome },
      });
      expect(result.exitCode).toBe(0);

      rmSync(testHome, { recursive: true, force: true });
    });
  });

  describe("usage command", () => {
    it("accepts usage command", async () => {
      const result = await runCLI(["usage", "--help"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("usage");
    });

    it("accepts command alias u", async () => {
      const result = await runCLI(["u", "--help"]);
      expect(result.exitCode).toBe(0);
    });
  });

  describe("doctor command", () => {
    it("accepts doctor command", async () => {
      const result = await runCLI(["doctor", "--help"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("doctor");
      expect(result.stdout).toContain("Diagnose");
    });
  });

  describe("feedback command", () => {
    it("accepts feedback command", async () => {
      const result = await runCLI(["feedback", "--help"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("feedback");
      expect(result.stdout).toContain("bug");
      expect(result.stdout).toContain("feature");
    });

    it("accepts feedback bug subcommand", async () => {
      const result = await runCLI(["feedback", "bug", "--help"]);
      expect(result.exitCode).toBe(0);
    });

    it("accepts feedback feature subcommand", async () => {
      const result = await runCLI(["feedback", "feature", "--help"]);
      expect(result.exitCode).toBe(0);
    });

    it("accepts feedback idea alias", async () => {
      const result = await runCLI(["feedback", "idea", "--help"]);
      expect(result.exitCode).toBe(0);
    });
  });

  describe("referral command", () => {
    it("accepts referral command", async () => {
      const result = await runCLI(["referral", "--help"]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("referral");
      expect(result.stdout).toContain("status");
      expect(result.stdout).toContain("link");
    });
  });

  describe("global options", () => {
    it("accepts quiet flag", async () => {
      const result = await runCLI(["-q", "--help"]);
      expect(result.exitCode).toBe(0);
    });

    it("accepts verbose flag", async () => {
      const result = await runCLI(["-v", "--help"]);
      expect(result.exitCode).toBe(0);
    });

    it("accepts no-color flag", async () => {
      const result = await runCLI(["--no-color", "--help"]);
      expect(result.exitCode).toBe(0);
    });

    it("respects NO_COLOR environment variable", async () => {
      const result = await runCLI(["--help"], {
        env: { NO_COLOR: "1" },
      });
      expect(result.exitCode).toBe(0);
      // Output should not contain ANSI codes
      expect(result.stdout).not.toMatch(/\x1b\[\d+m/);
    });
  });

  describe("unknown commands and options", () => {
    it("shows error for unknown command", async () => {
      const result = await runCLI(["unknowncommand"]);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("unknown command");
    });

    it("shows error for unknown option", async () => {
      const result = await runCLI(["--unknown-option"]);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("unknown option");
    });

    it("suggests similar commands for typos", async () => {
      // Commander may suggest similar commands
      const result = await runCLI(["chek"]); // typo of "check"
      expect(result.exitCode).not.toBe(0);
    });
  });
});

describe("CLI with mock dependencies", () => {
  const testDir = join(tmpdir(), `pkgwatch-scan-test-${Date.now()}`);

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true });
    }
  });

  describe("scan command with files", () => {
    it("detects package.json in directory", async () => {
      writeFileSync(
        join(testDir, "package.json"),
        JSON.stringify({
          name: "test-project",
          dependencies: { lodash: "^4.0.0" },
        })
      );

      // Will fail at API call without key, but validates file detection
      const result = await runCLI(["scan", testDir], {
        env: { NO_COLOR: "1" },
      });

      // Should attempt to scan (may fail at API)
      // The important thing is it found the file
      expect(result.stderr + result.stdout).not.toContain("No dependencies found");
    });

    it("reports no dependencies for empty package.json", async () => {
      writeFileSync(
        join(testDir, "package.json"),
        JSON.stringify({
          name: "empty-project",
          dependencies: {},
        })
      );

      const result = await runCLI(["scan", testDir], {
        env: { NO_COLOR: "1" },
      });

      expect(result.stdout).toContain("No dependencies");
      expect(result.exitCode).toBe(0);
    });

    it("reports error for non-existent path", async () => {
      const result = await runCLI(["scan", "/nonexistent/path"], {
        env: { NO_COLOR: "1" },
      });

      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain("does not exist");
    });

    it("handles malformed package.json gracefully", async () => {
      writeFileSync(join(testDir, "package.json"), "not valid json {");

      const result = await runCLI(["scan", testDir], {
        env: { NO_COLOR: "1" },
      });

      expect(result.exitCode).not.toBe(0);
      expect(result.stderr.toLowerCase()).toContain("error");
    });

    it("detects requirements.txt for Python projects", async () => {
      writeFileSync(join(testDir, "requirements.txt"), "requests==2.28.0\nflask>=2.0\n");

      const result = await runCLI(["scan", testDir], {
        env: { NO_COLOR: "1" },
      });

      // Should detect Python ecosystem
      expect(result.stderr + result.stdout).not.toContain("No dependency file found");
    }, 10_000);

    it("detects pyproject.toml for Python projects", async () => {
      writeFileSync(
        join(testDir, "pyproject.toml"),
        `[project]
name = "test-project"
dependencies = ["requests>=2.0"]
`
      );

      const result = await runCLI(["scan", testDir], {
        env: { NO_COLOR: "1" },
      });

      // Should detect Python ecosystem via pyproject.toml
      expect(result.stderr + result.stdout).not.toContain("No dependency file found");
    }, 10_000);
  });

  describe("recursive scan validation", () => {
    it("validates max-manifests is positive", async () => {
      const result = await runCLI(["scan", "-r", "--max-manifests", "0", testDir], {
        env: { NO_COLOR: "1" },
      });

      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain("positive");
    });

    it("validates max-manifests is a number", async () => {
      const result = await runCLI(["scan", "-r", "--max-manifests", "abc", testDir], {
        env: { NO_COLOR: "1" },
      });

      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain("positive");
    });

    it("warns about --ecosystem being ignored in recursive mode", async () => {
      writeFileSync(
        join(testDir, "package.json"),
        JSON.stringify({ name: "test", dependencies: {} })
      );

      const result = await runCLI(["scan", "-r", "-e", "npm", "--no-confirm", testDir], {
        env: { NO_COLOR: "1", CI: "1" },
      });

      expect(result.stdout + result.stderr).toContain("ignored");
    });

    it("requires API key for recursive scan", async () => {
      writeFileSync(
        join(testDir, "package.json"),
        JSON.stringify({ name: "test", dependencies: { lodash: "^4.0.0" } })
      );

      const result = await runCLI(["scan", "-r", "--no-confirm", testDir], {
        env: { NO_COLOR: "1", CI: "1", HOME: testDir }, // No API key configured
      });

      expect(result.exitCode).toBe(2);
      expect(result.stderr).toContain("API key");
    });
  });
});
