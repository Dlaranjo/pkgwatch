import { describe, it, expect, vi, beforeEach } from "vitest";
import * as core from "@actions/core";
import { generateSummary } from "../src/summary.js";
import type { ScanResult } from "../src/api.js";

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

  it("skips banner when no threshold set", async () => {
    const result: ScanResult = {
      total: 1,
      critical: 0,
      high: 0,
      medium: 0,
      low: 1,
      packages: [],
    };

    await generateSummary(result, false, "");

    // Should not have CAUTION or TIP banners
    const rawCalls = vi.mocked(core.summary.addRaw).mock.calls;
    const bannerCalls = rawCalls.filter(
      (call) =>
        call[0].includes("[!CAUTION]") || call[0].includes("[!TIP]")
    );
    expect(bannerCalls.length).toBe(0);
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
