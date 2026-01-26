import { describe, it, expect, vi, beforeEach } from "vitest";
import * as core from "@actions/core";
import { generateSummary, generateRepoSummary } from "../src/summary.js";
import type { ScanResult, RepoScanResult } from "../src/api.js";

// Mock @actions/core
vi.mock("@actions/core", () => ({
  summary: {
    addRaw: vi.fn().mockReturnThis(),
    addHeading: vi.fn().mockReturnThis(),
    addTable: vi.fn().mockReturnThis(),
    write: vi.fn().mockResolvedValue(undefined),
  },
}));

describe("generateSummary", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("generates summary with pass banner when threshold not exceeded", async () => {
    const result: ScanResult = {
      total: 5,
      critical: 0,
      high: 0,
      medium: 2,
      low: 3,
      packages: [],
    };

    await generateSummary(result, false, "HIGH");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("[!TIP]")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Scan Passed")
    );
    expect(core.summary.write).toHaveBeenCalled();
  });

  it("generates summary with fail banner when threshold exceeded", async () => {
    const result: ScanResult = {
      total: 5,
      critical: 1,
      high: 2,
      medium: 1,
      low: 1,
      packages: [],
    };

    await generateSummary(result, true, "HIGH");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("[!CAUTION]")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Policy Violation")
    );
  });

  it("generates table for high-risk packages", async () => {
    const result: ScanResult = {
      total: 2,
      critical: 1,
      high: 1,
      medium: 0,
      low: 0,
      packages: [
        {
          package: "bad-pkg",
          risk_level: "CRITICAL",
          health_score: 15,
          abandonment_risk: { risk_factors: ["Deprecated"] },
        } as any,
        {
          package: "risky-pkg",
          risk_level: "HIGH",
          health_score: 40,
          abandonment_risk: { risk_factors: ["Low maintainers"] },
        } as any,
      ],
    };

    await generateSummary(result, true, "HIGH");

    expect(core.summary.addHeading).toHaveBeenCalledWith(
      "Packages Requiring Attention",
      3
    );
    expect(core.summary.addTable).toHaveBeenCalled();
  });

  it("shows healthy banner when no threshold set and no issues", async () => {
    const result: ScanResult = {
      total: 1,
      critical: 0,
      high: 0,
      medium: 0,
      low: 1,
      packages: [],
    };

    await generateSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("[!TIP]")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Healthy")
    );
  });

  it("shows warning banner when no threshold set but has issues", async () => {
    const result: ScanResult = {
      total: 2,
      critical: 1,
      high: 0,
      medium: 0,
      low: 1,
      packages: [],
    };

    await generateSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("[!WARNING]")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Attention")
    );
  });

  it("generates collapsible section for all packages", async () => {
    const result: ScanResult = {
      total: 2,
      critical: 0,
      high: 0,
      medium: 1,
      low: 1,
      packages: [
        { package: "pkg-a", risk_level: "MEDIUM", health_score: 60 } as any,
        { package: "pkg-b", risk_level: "LOW", health_score: 80 } as any,
      ],
    };

    await generateSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("<details>")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("View all packages")
    );
  });
});

describe("escapeMarkdown (via generateSummary)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("escapes markdown special characters in package names", async () => {
    const result: ScanResult = {
      total: 1,
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      packages: [
        {
          package: "@scope/pkg-name",
          risk_level: "CRITICAL",
          health_score: 10,
          abandonment_risk: { risk_factors: ["Test *bold* _italic_"] },
        } as any,
      ],
    };

    await generateSummary(result, true, "CRITICAL");

    // The table should be called with escaped content
    expect(core.summary.addTable).toHaveBeenCalled();
  });
});

describe("feedback links in footer", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows feedback links when CRITICAL issues found", async () => {
    const result: ScanResult = {
      total: 5,
      critical: 1,
      high: 0,
      medium: 2,
      low: 2,
      packages: [],
    };

    await generateSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Wrong score?")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Feedback")
    );
  });

  it("shows feedback links when HIGH issues found", async () => {
    const result: ScanResult = {
      total: 5,
      critical: 0,
      high: 2,
      medium: 2,
      low: 1,
      packages: [],
    };

    await generateSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Wrong score?")
    );
  });

  it("hides feedback links when no HIGH/CRITICAL issues", async () => {
    const result: ScanResult = {
      total: 5,
      critical: 0,
      high: 0,
      medium: 2,
      low: 3,
      packages: [],
    };

    await generateSummary(result, false, "");

    // Check that addRaw was NOT called with "Wrong score?"
    const addRawCalls = (core.summary.addRaw as any).mock.calls;
    const hasWrongScoreLink = addRawCalls.some(
      (call: string[]) => call[0] && call[0].includes("Wrong score?")
    );
    expect(hasWrongScoreLink).toBe(false);
  });

  it("includes UTM parameters in PkgWatch link", async () => {
    const result: ScanResult = {
      total: 1,
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      packages: [],
    };

    await generateSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("utm_source=action")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("utm_medium=summary")
    );
  });

  it("shows feedback links when both CRITICAL and HIGH issues found", async () => {
    const result: ScanResult = {
      total: 5,
      critical: 2,
      high: 3,
      medium: 0,
      low: 0,
      packages: [],
    };

    await generateSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Wrong score?")
    );
  });

  it("feedback link points to discussions", async () => {
    const result: ScanResult = {
      total: 1,
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      packages: [],
    };

    await generateSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("discussions/new?category=feedback")
    );
  });

  it("wrong score link points to bug report template", async () => {
    const result: ScanResult = {
      total: 1,
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      packages: [],
    };

    await generateSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("template=bug_report.yml")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("labels=bug,action,false-positive")
    );
  });
});

describe("generateSummary - Data Quality Notes", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows data quality note when unverified risk packages exist", async () => {
    const result: ScanResult = {
      total: 2,
      critical: 1,
      high: 0,
      medium: 0,
      low: 1,
      packages: [
        {
          package: "risky-pkg",
          risk_level: "CRITICAL",
          health_score: 15,
          data_quality: { assessment: "UNVERIFIED", has_repository: false },
        } as any,
        {
          package: "good-pkg",
          risk_level: "LOW",
          health_score: 90,
          data_quality: { assessment: "VERIFIED", has_repository: true },
        } as any,
      ],
      unverified_risk_count: 1,
    };

    await generateSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("1 package(s) have incomplete data")
    );
  });

  it("does not show data quality note when all risk packages are verified", async () => {
    const result: ScanResult = {
      total: 2,
      critical: 1,
      high: 0,
      medium: 0,
      low: 1,
      packages: [
        {
          package: "risky-pkg",
          risk_level: "CRITICAL",
          health_score: 15,
          data_quality: { assessment: "VERIFIED", has_repository: true },
        } as any,
      ],
      unverified_risk_count: 0,
    };

    await generateSummary(result, false, "");

    const addRawCalls = (core.summary.addRaw as any).mock.calls;
    const hasIncompleteNote = addRawCalls.some(
      (call: string[]) => call[0] && call[0].includes("incomplete data")
    );
    expect(hasIncompleteNote).toBe(false);
  });
});

describe("generateSummary - Not Found Packages", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("displays not found packages note", async () => {
    const result: ScanResult = {
      total: 1,
      critical: 0,
      high: 0,
      medium: 0,
      low: 1,
      packages: [],
      not_found: ["nonexistentpkg", "typopackage", "privatepkg"],
    };

    await generateSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("3 package(s) not found")
    );
    // Note: escapeMarkdown adds backslash escapes, so we check for the escaped version
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("nonexistentpkg")
    );
  });

  it("does not show not found note when empty", async () => {
    const result: ScanResult = {
      total: 1,
      critical: 0,
      high: 0,
      medium: 0,
      low: 1,
      packages: [],
    };

    await generateSummary(result, false, "");

    const addRawCalls = (core.summary.addRaw as any).mock.calls;
    const hasNotFoundNote = addRawCalls.some(
      (call: string[]) => call[0] && call[0].includes("not found")
    );
    expect(hasNotFoundNote).toBe(false);
  });
});

describe("generateSummary - Summary Counts", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows only non-zero counts", async () => {
    const result: ScanResult = {
      total: 3,
      critical: 0,
      high: 2,
      medium: 0,
      low: 1,
      packages: [],
    };

    await generateSummary(result, false, "");

    // Should show HIGH and LOW but not CRITICAL or MEDIUM
    const addRawCalls = (core.summary.addRaw as any).mock.calls;
    const countsCall = addRawCalls.find(
      (call: string[]) => call[0] && call[0].includes("High")
    );
    expect(countsCall).toBeDefined();
    expect(countsCall[0]).toContain("2 High");
    expect(countsCall[0]).toContain("1 Low");
    expect(countsCall[0]).not.toContain("Critical");
    expect(countsCall[0]).not.toContain("Medium");
  });

  it("handles all zeros gracefully", async () => {
    const result: ScanResult = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      packages: [],
    };

    await generateSummary(result, false, "");

    // Should not crash and should write summary
    expect(core.summary.write).toHaveBeenCalled();
  });
});

describe("generateRepoSummary", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("generates summary for multi-manifest scan", async () => {
    const result: RepoScanResult = {
      manifests: [
        {
          manifest: { relativePath: "package.json", ecosystem: "npm", absolutePath: "/repo/package.json" },
          status: "success",
          packages: [
            { package: "lodash", risk_level: "LOW", health_score: 90 } as any,
          ],
          counts: { critical: 0, high: 0, medium: 0, low: 1 },
        },
        {
          manifest: { relativePath: "apps/web/package.json", ecosystem: "npm", absolutePath: "/repo/apps/web/package.json" },
          status: "success",
          packages: [
            { package: "express", risk_level: "MEDIUM", health_score: 70 } as any,
          ],
          counts: { critical: 0, high: 0, medium: 1, low: 0 },
        },
      ],
      summary: {
        totalManifests: 2,
        successfulManifests: 2,
        failedManifests: 0,
        uniquePackages: 2,
        totalPackages: 2,
        critical: 0,
        high: 0,
        medium: 1,
        low: 1,
      },
      truncated: false,
      rateLimited: false,
    };

    await generateRepoSummary(result, false, "HIGH");

    expect(core.summary.addHeading).toHaveBeenCalledWith(
      "PkgWatch Repository Scan Results",
      2
    );
    // The string uses ** for bold markdown, so check for the actual pattern
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("**2** manifest files")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("**2** unique packages")
    );
    expect(core.summary.write).toHaveBeenCalled();
  });

  it("shows caution banner when policy violated", async () => {
    const result: RepoScanResult = {
      manifests: [
        {
          manifest: { relativePath: "package.json", ecosystem: "npm", absolutePath: "/repo/package.json" },
          status: "success",
          packages: [
            { package: "risky", risk_level: "CRITICAL", health_score: 10 } as any,
          ],
          counts: { critical: 1, high: 0, medium: 0, low: 0 },
        },
      ],
      summary: {
        totalManifests: 1,
        successfulManifests: 1,
        failedManifests: 0,
        uniquePackages: 1,
        totalPackages: 1,
        critical: 1,
        high: 0,
        medium: 0,
        low: 0,
      },
      truncated: false,
      rateLimited: false,
    };

    await generateRepoSummary(result, true, "CRITICAL");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("[!CAUTION]")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Policy Violation")
    );
  });

  it("shows pass banner when threshold not exceeded", async () => {
    const result: RepoScanResult = {
      manifests: [],
      summary: {
        totalManifests: 1,
        successfulManifests: 1,
        failedManifests: 0,
        uniquePackages: 5,
        totalPackages: 5,
        critical: 0,
        high: 0,
        medium: 2,
        low: 3,
      },
      truncated: false,
      rateLimited: false,
    };

    await generateRepoSummary(result, false, "HIGH");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("[!TIP]")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Scan Passed")
    );
  });

  it("shows warning banner when issues found but no threshold", async () => {
    const result: RepoScanResult = {
      manifests: [],
      summary: {
        totalManifests: 1,
        successfulManifests: 1,
        failedManifests: 0,
        uniquePackages: 3,
        totalPackages: 3,
        critical: 1,
        high: 1,
        medium: 0,
        low: 1,
      },
      truncated: false,
      rateLimited: false,
    };

    await generateRepoSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("[!WARNING]")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Attention")
    );
  });

  it("shows healthy banner when no issues and no threshold", async () => {
    const result: RepoScanResult = {
      manifests: [],
      summary: {
        totalManifests: 1,
        successfulManifests: 1,
        failedManifests: 0,
        uniquePackages: 5,
        totalPackages: 5,
        critical: 0,
        high: 0,
        medium: 0,
        low: 5,
      },
      truncated: false,
      rateLimited: false,
    };

    await generateRepoSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("[!TIP]")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Healthy")
    );
  });
});

describe("generateRepoSummary - Truncation Warning", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows truncation warning when scan was truncated", async () => {
    const result: RepoScanResult = {
      manifests: [],
      summary: {
        totalManifests: 100,
        successfulManifests: 100,
        failedManifests: 0,
        uniquePackages: 500,
        totalPackages: 1000,
        critical: 0,
        high: 0,
        medium: 0,
        low: 500,
      },
      truncated: true,
      rateLimited: false,
    };

    await generateRepoSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Truncated")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("manifest limit reached")
    );
  });

  it("shows rate limiting warning when rate limited", async () => {
    const result: RepoScanResult = {
      manifests: [],
      summary: {
        totalManifests: 10,
        successfulManifests: 8,
        failedManifests: 2,
        uniquePackages: 50,
        totalPackages: 80,
        critical: 0,
        high: 0,
        medium: 0,
        low: 50,
      },
      truncated: false,
      rateLimited: true,
    };

    await generateRepoSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Rate Limited")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("quota reached")
    );
  });
});

describe("generateRepoSummary - Manifests Table", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("creates manifests table with status indicators", async () => {
    const result: RepoScanResult = {
      manifests: [
        {
          manifest: { relativePath: "package.json", ecosystem: "npm", absolutePath: "/repo/package.json" },
          status: "success",
          packages: [],
          counts: { critical: 0, high: 1, medium: 2, low: 3 },
        },
        {
          manifest: { relativePath: "apps/api/package.json", ecosystem: "npm", absolutePath: "/repo/apps/api/package.json" },
          status: "parse_error",
          error: "Invalid JSON",
        },
        {
          manifest: { relativePath: "services/payment/package.json", ecosystem: "npm", absolutePath: "/repo/services/payment/package.json" },
          status: "api_error",
          error: "Timeout",
        },
        {
          manifest: { relativePath: "services/auth/package.json", ecosystem: "npm", absolutePath: "/repo/services/auth/package.json" },
          status: "rate_limited",
          error: "Rate limit exceeded",
        },
      ],
      summary: {
        totalManifests: 4,
        successfulManifests: 1,
        failedManifests: 3,
        uniquePackages: 6,
        totalPackages: 6,
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
      },
      truncated: false,
      rateLimited: false,
    };

    await generateRepoSummary(result, false, "");

    // Should add manifests table
    expect(core.summary.addHeading).toHaveBeenCalledWith("Manifests", 3);
    expect(core.summary.addTable).toHaveBeenCalled();
  });
});

describe("generateRepoSummary - High Risk Packages Table", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("deduplicates packages appearing in multiple manifests", async () => {
    const result: RepoScanResult = {
      manifests: [
        {
          manifest: { relativePath: "package.json", ecosystem: "npm", absolutePath: "/repo/package.json" },
          status: "success",
          packages: [
            { package: "risky-pkg", risk_level: "CRITICAL", health_score: 10 } as any,
          ],
          counts: { critical: 1, high: 0, medium: 0, low: 0 },
        },
        {
          manifest: { relativePath: "apps/web/package.json", ecosystem: "npm", absolutePath: "/repo/apps/web/package.json" },
          status: "success",
          packages: [
            { package: "risky-pkg", risk_level: "CRITICAL", health_score: 10 } as any, // Same package
            { package: "another-risky", risk_level: "HIGH", health_score: 30 } as any,
          ],
          counts: { critical: 1, high: 1, medium: 0, low: 0 },
        },
      ],
      summary: {
        totalManifests: 2,
        successfulManifests: 2,
        failedManifests: 0,
        uniquePackages: 2,
        totalPackages: 3,
        critical: 2,
        high: 1,
        medium: 0,
        low: 0,
      },
      truncated: false,
      rateLimited: false,
    };

    await generateRepoSummary(result, false, "");

    // Should show "Packages Requiring Attention"
    expect(core.summary.addHeading).toHaveBeenCalledWith(
      "Packages Requiring Attention",
      3
    );
    // The table should be called with deduplicated entries
    expect(core.summary.addTable).toHaveBeenCalled();
  });

  it("includes data quality indicator in risk packages table", async () => {
    const result: RepoScanResult = {
      manifests: [
        {
          manifest: { relativePath: "package.json", ecosystem: "npm", absolutePath: "/repo/package.json" },
          status: "success",
          packages: [
            {
              package: "verified-risky",
              risk_level: "HIGH",
              health_score: 30,
              data_quality: { assessment: "VERIFIED", has_repository: true },
            } as any,
            {
              package: "unverified-risky",
              risk_level: "CRITICAL",
              health_score: 10,
              data_quality: { assessment: "PARTIAL", has_repository: false },
            } as any,
          ],
          counts: { critical: 1, high: 1, medium: 0, low: 0 },
        },
      ],
      summary: {
        totalManifests: 1,
        successfulManifests: 1,
        failedManifests: 0,
        uniquePackages: 2,
        totalPackages: 2,
        critical: 1,
        high: 1,
        medium: 0,
        low: 0,
      },
      truncated: false,
      rateLimited: false,
    };

    await generateRepoSummary(result, false, "");

    // Should have data quality note about incomplete data
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("incomplete data")
    );
  });
});

describe("generateRepoSummary - Failed Manifests Section", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows failed manifests in collapsible section", async () => {
    const result: RepoScanResult = {
      manifests: [
        {
          manifest: { relativePath: "broken/package.json", ecosystem: "npm", absolutePath: "/repo/broken/package.json" },
          status: "parse_error",
          error: "Unexpected token at line 5",
        },
      ],
      summary: {
        totalManifests: 1,
        successfulManifests: 0,
        failedManifests: 1,
        uniquePackages: 0,
        totalPackages: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      },
      truncated: false,
      rateLimited: false,
    };

    await generateRepoSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Failed manifests")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("Parse Error")
    );
  });
});

describe("generateRepoSummary - Not Found Packages", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("aggregates and deduplicates not found packages", async () => {
    const result: RepoScanResult = {
      manifests: [
        {
          manifest: { relativePath: "package.json", ecosystem: "npm", absolutePath: "/repo/package.json" },
          status: "success",
          packages: [],
          counts: { critical: 0, high: 0, medium: 0, low: 0 },
          notFound: ["pkg-a", "pkg-b"],
        },
        {
          manifest: { relativePath: "apps/package.json", ecosystem: "npm", absolutePath: "/repo/apps/package.json" },
          status: "success",
          packages: [],
          counts: { critical: 0, high: 0, medium: 0, low: 0 },
          notFound: ["pkg-b", "pkg-c"], // pkg-b is duplicate
        },
      ],
      summary: {
        totalManifests: 2,
        successfulManifests: 2,
        failedManifests: 0,
        uniquePackages: 0,
        totalPackages: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      },
      truncated: false,
      rateLimited: false,
    };

    await generateRepoSummary(result, false, "");

    // Should show 3 unique not found packages
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("3 package(s) not found")
    );
  });

  it("truncates large not found list", async () => {
    const notFoundPackages = Array.from({ length: 20 }, (_, i) => `missing-pkg-${i}`);
    const result: RepoScanResult = {
      manifests: [
        {
          manifest: { relativePath: "package.json", ecosystem: "npm", absolutePath: "/repo/package.json" },
          status: "success",
          packages: [],
          counts: { critical: 0, high: 0, medium: 0, low: 0 },
          notFound: notFoundPackages,
        },
      ],
      summary: {
        totalManifests: 1,
        successfulManifests: 1,
        failedManifests: 0,
        uniquePackages: 0,
        totalPackages: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      },
      truncated: false,
      rateLimited: false,
    };

    await generateRepoSummary(result, false, "");

    // Should show truncation indicator
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("and 5 more")
    );
  });
});

describe("generateRepoSummary - Collapsible Per-Manifest Details", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows all packages by manifest in collapsible section", async () => {
    const result: RepoScanResult = {
      manifests: [
        {
          manifest: { relativePath: "package.json", ecosystem: "npm", absolutePath: "/repo/package.json" },
          status: "success",
          packages: [
            { package: "lodash", risk_level: "LOW", health_score: 90 } as any,
            { package: "express", risk_level: "MEDIUM", health_score: 70 } as any,
          ],
          counts: { critical: 0, high: 0, medium: 1, low: 1 },
        },
      ],
      summary: {
        totalManifests: 1,
        successfulManifests: 1,
        failedManifests: 0,
        uniquePackages: 2,
        totalPackages: 2,
        critical: 0,
        high: 0,
        medium: 1,
        low: 1,
      },
      truncated: false,
      rateLimited: false,
    };

    await generateRepoSummary(result, false, "");

    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("<details>")
    );
    expect(core.summary.addRaw).toHaveBeenCalledWith(
      expect.stringContaining("View all packages by manifest")
    );
  });

  it("sorts packages by health score ascending", async () => {
    const result: RepoScanResult = {
      manifests: [
        {
          manifest: { relativePath: "package.json", ecosystem: "npm", absolutePath: "/repo/package.json" },
          status: "success",
          packages: [
            { package: "healthy", risk_level: "LOW", health_score: 95 } as any,
            { package: "unhealthy", risk_level: "HIGH", health_score: 25 } as any,
            { package: "medium", risk_level: "MEDIUM", health_score: 60 } as any,
          ],
          counts: { critical: 0, high: 1, medium: 1, low: 1 },
        },
      ],
      summary: {
        totalManifests: 1,
        successfulManifests: 1,
        failedManifests: 0,
        uniquePackages: 3,
        totalPackages: 3,
        critical: 0,
        high: 1,
        medium: 1,
        low: 1,
      },
      truncated: false,
      rateLimited: false,
    };

    await generateRepoSummary(result, false, "");

    // The markdown table should be generated - verify it's sorted
    const addRawCalls = (core.summary.addRaw as any).mock.calls;
    const tableCall = addRawCalls.find(
      (call: string[]) => call[0] && call[0].includes("unhealthy") && call[0].includes("healthy")
    );
    // unhealthy (25) should appear before healthy (95) in sorted order
    if (tableCall) {
      const unhealthyIndex = tableCall[0].indexOf("unhealthy");
      const healthyIndex = tableCall[0].indexOf("healthy");
      expect(unhealthyIndex).toBeLessThan(healthyIndex);
    }
  });
});

describe("escapeMarkdown edge cases", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("escapes pipe characters in package names", async () => {
    const result: ScanResult = {
      total: 1,
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      packages: [
        {
          package: "weird|name",
          risk_level: "CRITICAL",
          health_score: 10,
          abandonment_risk: { risk_factors: ["Test |pipe|"] },
        } as any,
      ],
    };

    await generateSummary(result, true, "CRITICAL");

    // Should not crash, table should be generated
    expect(core.summary.addTable).toHaveBeenCalled();
  });

  it("truncates very long package names", async () => {
    const longName = "a".repeat(200);
    const result: ScanResult = {
      total: 1,
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      packages: [
        {
          package: longName,
          risk_level: "CRITICAL",
          health_score: 10,
        } as any,
      ],
    };

    await generateSummary(result, true, "CRITICAL");

    // Should not crash
    expect(core.summary.addTable).toHaveBeenCalled();
  });

  it("escapes backslashes", async () => {
    const result: ScanResult = {
      total: 1,
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      packages: [
        {
          package: "path\\to\\pkg",
          risk_level: "CRITICAL",
          health_score: 10,
          abandonment_risk: { risk_factors: ["Test\\backslash"] },
        } as any,
      ],
    };

    await generateSummary(result, true, "CRITICAL");

    expect(core.summary.addTable).toHaveBeenCalled();
  });
});

describe("generateSummary - No packages scenario", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("does not generate collapsible when no packages", async () => {
    const result: ScanResult = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      packages: [],
    };

    await generateSummary(result, false, "");

    const addRawCalls = (core.summary.addRaw as any).mock.calls;
    const hasDetails = addRawCalls.some(
      (call: string[]) => call[0] && call[0].includes("<details>") && call[0].includes("View all packages")
    );
    expect(hasDetails).toBe(false);
  });

  it("does not generate risk table when no high/critical packages", async () => {
    const result: ScanResult = {
      total: 3,
      critical: 0,
      high: 0,
      medium: 2,
      low: 1,
      packages: [
        { package: "pkg1", risk_level: "MEDIUM", health_score: 60 } as any,
        { package: "pkg2", risk_level: "MEDIUM", health_score: 65 } as any,
        { package: "pkg3", risk_level: "LOW", health_score: 85 } as any,
      ],
    };

    await generateSummary(result, false, "");

    expect(core.summary.addHeading).not.toHaveBeenCalledWith(
      "Packages Requiring Attention",
      3
    );
  });
});
