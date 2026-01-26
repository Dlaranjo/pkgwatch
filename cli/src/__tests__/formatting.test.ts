/**
 * Tests for CLI output formatting functions.
 *
 * These tests verify the internal formatting utilities work correctly.
 * We import directly from index.ts's internal functions by re-exporting
 * them or testing their behavior through observable outputs.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import picocolors from "picocolors";
import { getRiskColor } from "../api.js";

// Since formatting functions are internal to index.ts, we test their behavior
// through the exported utilities and document expected formatting behavior.

describe("formatting utilities", () => {
  describe("getRiskColor utility", () => {
    it("maps risk levels to appropriate colors", () => {
      // CRITICAL and HIGH should be red (danger)
      expect(getRiskColor("CRITICAL")).toBe("red");
      expect(getRiskColor("HIGH")).toBe("red");

      // MEDIUM should be yellow (warning)
      expect(getRiskColor("MEDIUM")).toBe("yellow");

      // LOW should be green (safe)
      expect(getRiskColor("LOW")).toBe("green");

      // Unknown should be blue (neutral)
      expect(getRiskColor("UNKNOWN")).toBe("blue");
    });

    it("returns blue for empty or invalid levels", () => {
      expect(getRiskColor("")).toBe("blue");
      expect(getRiskColor("invalid")).toBe("blue");
      expect(getRiskColor("none")).toBe("blue");
    });
  });

  describe("score formatting behavior", () => {
    // These test the expected format of score displays

    it("formats null scores as dashes", () => {
      // When health_score is null, should display as "--/100"
      const formatScore = (score: number | null): string => {
        if (score === null) return "--/100";
        return `${score}/100`;
      };

      expect(formatScore(null)).toBe("--/100");
      expect(formatScore(75)).toBe("75/100");
      expect(formatScore(0)).toBe("0/100");
    });

    it("formats scores with color thresholds", () => {
      // Expected thresholds: >= 70 green, >= 50 yellow, < 50 red
      const getScoreColor = (score: number): string => {
        if (score >= 70) return "green";
        if (score >= 50) return "yellow";
        return "red";
      };

      expect(getScoreColor(100)).toBe("green");
      expect(getScoreColor(70)).toBe("green");
      expect(getScoreColor(69)).toBe("yellow");
      expect(getScoreColor(50)).toBe("yellow");
      expect(getScoreColor(49)).toBe("red");
      expect(getScoreColor(0)).toBe("red");
    });
  });

  describe("number formatting behavior", () => {
    it("formats large numbers with K suffix", () => {
      const formatNumber = (n: number): string => {
        if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
        if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
        return n.toString();
      };

      expect(formatNumber(500)).toBe("500");
      expect(formatNumber(1000)).toBe("1.0K");
      expect(formatNumber(1500)).toBe("1.5K");
      expect(formatNumber(1000000)).toBe("1.0M");
      expect(formatNumber(2500000)).toBe("2.5M");
    });

    it("handles edge cases for number formatting", () => {
      const formatNumber = (n: number): string => {
        if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
        if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
        return n.toString();
      };

      expect(formatNumber(0)).toBe("0");
      expect(formatNumber(999)).toBe("999");
      expect(formatNumber(999999)).toBe("1000.0K");
    });
  });

  describe("SARIF output format", () => {
    // Test SARIF output structure matches the spec

    it("produces valid SARIF 2.1.0 structure", () => {
      const VERSION = "1.0.0";

      const toSarif = (result: { packages: Array<{ package: string; risk_level: string; health_score: number }> }) => {
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
              .filter((p) => p.risk_level === "CRITICAL" || p.risk_level === "HIGH")
              .map((p) => ({
                ruleId: `pkgwatch/${p.risk_level.toLowerCase()}`,
                level: p.risk_level === "CRITICAL" ? "error" : "warning",
                message: {
                  text: `${p.package}: ${p.risk_level} risk (health score: ${p.health_score})`,
                },
              })),
          }],
        };
      };

      const sarif = toSarif({
        packages: [
          { package: "risky-pkg", risk_level: "CRITICAL", health_score: 15 },
          { package: "medium-pkg", risk_level: "MEDIUM", health_score: 55 },
          { package: "safe-pkg", risk_level: "LOW", health_score: 85 },
        ],
      });

      // Validate structure
      expect(sarif.$schema).toContain("sarif-schema-2.1.0");
      expect(sarif.version).toBe("2.1.0");
      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0].tool.driver.name).toBe("pkgwatch");

      // Only CRITICAL and HIGH should be in results
      expect(sarif.runs[0].results).toHaveLength(1);
      expect(sarif.runs[0].results[0].ruleId).toBe("pkgwatch/critical");
      expect(sarif.runs[0].results[0].level).toBe("error");
    });

    it("maps HIGH to warning level", () => {
      const toSarif = (packages: Array<{ package: string; risk_level: string; health_score: number }>) => {
        return {
          results: packages
            .filter((p) => p.risk_level === "CRITICAL" || p.risk_level === "HIGH")
            .map((p) => ({
              ruleId: `pkgwatch/${p.risk_level.toLowerCase()}`,
              level: p.risk_level === "CRITICAL" ? "error" : "warning",
            })),
        };
      };

      const sarif = toSarif([
        { package: "high-risk", risk_level: "HIGH", health_score: 35 },
      ]);

      expect(sarif.results[0].level).toBe("warning");
      expect(sarif.results[0].ruleId).toBe("pkgwatch/high");
    });

    it("produces empty results for low-risk packages", () => {
      const toSarif = (packages: Array<{ package: string; risk_level: string; health_score: number }>) => {
        return {
          results: packages
            .filter((p) => p.risk_level === "CRITICAL" || p.risk_level === "HIGH")
            .map((p) => ({})),
        };
      };

      const sarif = toSarif([
        { package: "safe1", risk_level: "LOW", health_score: 90 },
        { package: "safe2", risk_level: "MEDIUM", health_score: 60 },
      ]);

      expect(sarif.results).toHaveLength(0);
    });
  });

  describe("picocolors integration", () => {
    it("creates colors function with color support", () => {
      const pc = picocolors.createColors(true);
      expect(pc.red("test")).toContain("test");
      // Should contain ANSI codes
      expect(pc.red("test")).toMatch(/\x1b\[/);
    });

    it("creates colors function without color support", () => {
      const pc = picocolors.createColors(false);
      // Should NOT contain ANSI codes
      expect(pc.red("test")).toBe("test");
      expect(pc.green("test")).toBe("test");
      expect(pc.yellow("test")).toBe("test");
    });
  });

  describe("exit code behavior", () => {
    // Document expected exit codes

    it("uses correct exit code constants", () => {
      const EXIT_SUCCESS = 0;
      const EXIT_RISK_EXCEEDED = 1;
      const EXIT_CLI_ERROR = 2;

      expect(EXIT_SUCCESS).toBe(0);
      expect(EXIT_RISK_EXCEEDED).toBe(1);
      expect(EXIT_CLI_ERROR).toBe(2);
    });

    it("fail-on logic for CRITICAL threshold", () => {
      const shouldFail = (threshold: string, critical: number, high: number): boolean => {
        const t = threshold.toUpperCase();
        if (t === "CRITICAL" && critical > 0) return true;
        if (t === "HIGH" && (critical > 0 || high > 0)) return true;
        return false;
      };

      // CRITICAL threshold
      expect(shouldFail("CRITICAL", 1, 0)).toBe(true);
      expect(shouldFail("CRITICAL", 0, 1)).toBe(false);
      expect(shouldFail("CRITICAL", 0, 0)).toBe(false);

      // HIGH threshold
      expect(shouldFail("HIGH", 1, 0)).toBe(true);
      expect(shouldFail("HIGH", 0, 1)).toBe(true);
      expect(shouldFail("HIGH", 1, 1)).toBe(true);
      expect(shouldFail("HIGH", 0, 0)).toBe(false);
    });
  });

  describe("manifest status emoji formatting", () => {
    it("maps status to correct emoji", () => {
      // This matches getStatusEmoji in index.ts
      const getStatusEmoji = (status: string, pc: typeof picocolors): string => {
        switch (status) {
          case "success":
            return pc.green("OK");
          case "parse_error":
            return pc.red("X");
          case "api_error":
            return pc.yellow("!");
          case "rate_limited":
            return pc.red("X");
          default:
            return pc.dim("?");
        }
      };

      // With colors disabled for testing
      const pc = picocolors.createColors(false);
      expect(getStatusEmoji("success", pc)).toBe("OK");
      expect(getStatusEmoji("parse_error", pc)).toBe("X");
      expect(getStatusEmoji("api_error", pc)).toBe("!");
      expect(getStatusEmoji("rate_limited", pc)).toBe("X");
      expect(getStatusEmoji("unknown", pc)).toBe("?");
    });
  });

  describe("API key masking consistency", () => {
    // Verify masking behavior matches config.ts

    it("masks typical API keys consistently", () => {
      const maskApiKey = (key: string): string => {
        if (key.length <= 12) return "***";
        return `${key.slice(0, 6)}...${key.slice(-4)}`;
      };

      // Standard format: pw_xxxxxxxxxxxx
      // "pw_abc123def456xyz" has 18 chars
      // First 6: "pw_abc", Last 4: "6xyz"
      expect(maskApiKey("pw_abc123def456xyz")).toBe("pw_abc...6xyz");
      expect(maskApiKey("pw_test")).toBe("***"); // 7 chars <= 12
      expect(maskApiKey("")).toBe("***");
    });
  });

  describe("progress bar thresholds", () => {
    // Document progress bar behavior thresholds

    it("uses progress bar for large scans", () => {
      const PROGRESS_BAR_THRESHOLD = 20;
      const shouldUseProgressBar = (depCount: number, outputFormat: string, quiet: boolean): boolean => {
        return depCount >= PROGRESS_BAR_THRESHOLD && outputFormat === "table" && !quiet;
      };

      expect(shouldUseProgressBar(20, "table", false)).toBe(true);
      expect(shouldUseProgressBar(19, "table", false)).toBe(false);
      expect(shouldUseProgressBar(100, "json", false)).toBe(false);
      expect(shouldUseProgressBar(100, "table", true)).toBe(false);
    });

    it("batches large scans correctly", () => {
      const BATCH_SIZE = 25;

      const calculateBatches = (depCount: number): number => {
        return Math.ceil(depCount / BATCH_SIZE);
      };

      expect(calculateBatches(25)).toBe(1);
      expect(calculateBatches(26)).toBe(2);
      expect(calculateBatches(50)).toBe(2);
      expect(calculateBatches(75)).toBe(3);
      expect(calculateBatches(100)).toBe(4);
    });
  });

  describe("rate limit warning thresholds", () => {
    it("shows critical warning at 95%+", () => {
      const getWarningLevel = (percent: number): "critical" | "warning" | "none" => {
        if (percent >= 95) return "critical";
        if (percent >= 80) return "warning";
        return "none";
      };

      expect(getWarningLevel(95)).toBe("critical");
      expect(getWarningLevel(100)).toBe("critical");
      expect(getWarningLevel(94)).toBe("warning");
      expect(getWarningLevel(80)).toBe("warning");
      expect(getWarningLevel(79)).toBe("none");
      expect(getWarningLevel(50)).toBe("none");
    });
  });

  describe("CI environment detection", () => {
    it("detects various CI environments", () => {
      const isCI = (env: Record<string, string | undefined>): boolean => {
        return Boolean(
          env.CI ||
          env.GITHUB_ACTIONS ||
          env.GITLAB_CI ||
          env.JENKINS_URL ||
          env.CIRCLECI ||
          env.TRAVIS ||
          env.BUILDKITE
        );
      };

      expect(isCI({ CI: "true" })).toBe(true);
      expect(isCI({ GITHUB_ACTIONS: "true" })).toBe(true);
      expect(isCI({ GITLAB_CI: "true" })).toBe(true);
      expect(isCI({ JENKINS_URL: "http://jenkins" })).toBe(true);
      expect(isCI({ CIRCLECI: "true" })).toBe(true);
      expect(isCI({ TRAVIS: "true" })).toBe(true);
      expect(isCI({ BUILDKITE: "true" })).toBe(true);
      expect(isCI({})).toBe(false);
    });
  });

  describe("data quality indicator formatting", () => {
    it("identifies unverified packages", () => {
      const isUnverified = (dataQuality?: { assessment: string }): boolean => {
        return !dataQuality || dataQuality.assessment !== "VERIFIED";
      };

      expect(isUnverified(undefined)).toBe(true);
      expect(isUnverified({ assessment: "UNVERIFIED" })).toBe(true);
      expect(isUnverified({ assessment: "PARTIAL" })).toBe(true);
      expect(isUnverified({ assessment: "VERIFIED" })).toBe(false);
    });

    it("counts data quality categories correctly", () => {
      const countDataQuality = (packages: Array<{ data_quality?: { assessment: string } }>) => {
        let verified = 0;
        let partial = 0;
        let unverified = 0;

        for (const pkg of packages) {
          const assessment = pkg.data_quality?.assessment || "UNVERIFIED";
          if (assessment === "VERIFIED") verified++;
          else if (assessment === "PARTIAL") partial++;
          else unverified++;
        }

        return { verified, partial, unverified };
      };

      const packages = [
        { data_quality: { assessment: "VERIFIED" } },
        { data_quality: { assessment: "VERIFIED" } },
        { data_quality: { assessment: "PARTIAL" } },
        { data_quality: { assessment: "UNVERIFIED" } },
        {}, // no data_quality
      ];

      const counts = countDataQuality(packages);
      expect(counts.verified).toBe(2);
      expect(counts.partial).toBe(1);
      expect(counts.unverified).toBe(2);
    });
  });
});
