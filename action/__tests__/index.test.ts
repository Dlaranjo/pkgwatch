import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as core from "@actions/core";
import * as path from "node:path";

// Mock @actions/core
vi.mock("@actions/core", () => ({
  getInput: vi.fn(),
  setSecret: vi.fn(),
  setOutput: vi.fn(),
  setFailed: vi.fn(),
  warning: vi.fn(),
  info: vi.fn(),
  debug: vi.fn(),
  summary: {
    addRaw: vi.fn().mockReturnThis(),
    addHeading: vi.fn().mockReturnThis(),
    addTable: vi.fn().mockReturnThis(),
    write: vi.fn().mockResolvedValue(undefined),
  },
}));

// Mock scanner
vi.mock("../src/scanner.js", () => ({
  scanDependencies: vi.fn(),
}));

// Mock summary
vi.mock("../src/summary.js", () => ({
  generateSummary: vi.fn().mockResolvedValue(undefined),
  generateRepoSummary: vi.fn().mockResolvedValue(undefined),
}));

// Use vi.hoisted for mocks that need to be available at mock definition time
const { mockScanRepository } = vi.hoisted(() => ({
  mockScanRepository: vi.fn(),
}));

import { scanDependencies } from "../src/scanner.js";
import { generateSummary, generateRepoSummary } from "../src/summary.js";
import { ApiClientError } from "../src/api.js";

// Mock the api module for error handling tests
vi.mock("../src/api.js", async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    ApiClientError: actual.ApiClientError,
    scanRepository: mockScanRepository,
    DEFAULT_EXCLUDES: ["node_modules", ".git", "vendor"],
  };
});

describe("run() - Input Validation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("validates fail-on accepts CRITICAL", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "fail-on":
          return "CRITICAL";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 1,
      critical: 0,
      high: 0,
      medium: 0,
      low: 1,
      packages: [],
    });

    // Import and run
    await import("../src/index.js");

    // Wait for async execution
    await new Promise((r) => setTimeout(r, 50));

    // Should not fail on valid input
    expect(core.setFailed).not.toHaveBeenCalledWith(
      expect.stringContaining("Invalid 'fail-on'")
    );
  });

  it("rejects invalid fail-on values", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "fail-on":
          return "INVALID";
        default:
          return "";
      }
    });

    // Re-import to trigger run()
    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Invalid 'fail-on'")
    );
  });
});

describe("run() - Path Traversal Prevention", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("allows valid working directory within workspace", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "working-directory":
          return "packages/my-app";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 1,
      critical: 0,
      high: 0,
      medium: 0,
      low: 1,
      packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).not.toHaveBeenCalledWith(
      expect.stringContaining("working-directory must be within")
    );
  });

  it("rejects path traversal attempts", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "working-directory":
          return "../../../etc";
        default:
          return "";
      }
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      "working-directory must be within the repository"
    );
  });

  it("rejects absolute paths outside workspace", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "working-directory":
          return "/etc/passwd";
        default:
          return "";
      }
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      "working-directory must be within the repository"
    );
  });
});

describe("run() - Threshold Logic", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("fails when fail-on=CRITICAL and critical packages exist", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "fail-on":
          return "CRITICAL";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 2,
      critical: 1,
      high: 0,
      medium: 0,
      low: 1,
      packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("CRITICAL")
    );
  });

  it("does not fail when fail-on=CRITICAL and only high packages exist", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "fail-on":
          return "CRITICAL";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 2,
      critical: 0,
      high: 1,
      medium: 0,
      low: 1,
      packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    // Should not fail - only HIGH, not CRITICAL
    const failedCalls = vi.mocked(core.setFailed).mock.calls;
    const thresholdFails = failedCalls.filter(
      (call) => call[0].includes("CRITICAL") || call[0].includes("threshold")
    );
    expect(thresholdFails.length).toBe(0);
  });

  it("fails when fail-on=HIGH and high packages exist", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "fail-on":
          return "HIGH";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 2,
      critical: 0,
      high: 1,
      medium: 0,
      low: 1,
      packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("HIGH")
    );
  });
});

describe("run() - Soft Fail Mode", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("warns instead of failing when soft-fail is enabled", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "fail-on":
          return "CRITICAL";
        case "soft-fail":
          return "true";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 2,
      critical: 1,
      high: 0,
      medium: 0,
      low: 1,
      packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    // Should warn, not fail
    expect(core.warning).toHaveBeenCalledWith(
      expect.stringContaining("soft-fail mode")
    );
    // setFailed should only be called for threshold violations, not in soft-fail
    const failedCalls = vi.mocked(core.setFailed).mock.calls;
    const thresholdFails = failedCalls.filter(
      (call) =>
        call[0].includes("CRITICAL") &&
        !call[0].includes("Authentication") &&
        !call[0].includes("API error")
    );
    expect(thresholdFails.length).toBe(0);
  });
});

describe("run() - Outputs", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("sets all expected outputs", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 10,
      critical: 1,
      high: 2,
      medium: 3,
      low: 4,
      packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setOutput).toHaveBeenCalledWith("total", 10);
    expect(core.setOutput).toHaveBeenCalledWith("critical", 1);
    expect(core.setOutput).toHaveBeenCalledWith("high", 2);
    expect(core.setOutput).toHaveBeenCalledWith("medium", 3);
    expect(core.setOutput).toHaveBeenCalledWith("low", 4);
    expect(core.setOutput).toHaveBeenCalledWith("has-issues", true);
    expect(core.setOutput).toHaveBeenCalledWith("highest-risk", "CRITICAL");
  });
});

describe("sanitizeForAnnotation", () => {
  // Since sanitizeForAnnotation is not exported, we test it indirectly
  // through the annotation behavior

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("generates annotations for high-risk packages", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 1,
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      packages: [
        {
          package: "bad-package",
          risk_level: "CRITICAL",
          health_score: 10,
          abandonment_risk: { risk_factors: ["Deprecated"] },
          is_deprecated: true,
          archived: false,
          last_updated: "2024-01-01",
        },
      ],
      format: "package.json",
      ecosystem: "npm",
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.warning).toHaveBeenCalledWith(
      expect.stringContaining("bad-package"),
      expect.objectContaining({
        title: "Critical Dependency Risk",
        file: "package.json",
      })
    );
  });

  it("uses different title for HIGH vs CRITICAL", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 1,
      critical: 0,
      high: 1,
      medium: 0,
      low: 0,
      packages: [
        {
          package: "risky-package",
          risk_level: "HIGH",
          health_score: 40,
          abandonment_risk: { risk_factors: ["Low maintainers"] },
          is_deprecated: false,
          archived: false,
          last_updated: "2024-01-01",
        },
      ],
      format: "package.json",
      ecosystem: "npm",
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.warning).toHaveBeenCalledWith(
      expect.stringContaining("risky-package"),
      expect.objectContaining({
        title: "High Dependency Risk",
      })
    );
  });
});

describe("run() - Error Handling", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("handles unauthorized (401) error with actionable message", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    const error = new ApiClientError("Invalid API key", 401, "unauthorized");
    vi.mocked(scanDependencies).mockRejectedValue(error);

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Authentication failed (401)")
    );
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("pkgwatch.dev/dashboard")
    );
  });

  it("handles forbidden (403) error with actionable message", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    const error = new ApiClientError("Forbidden", 403, "forbidden");
    vi.mocked(scanDependencies).mockRejectedValue(error);

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Access forbidden (403)")
    );
  });

  it("handles rate_limited (429) error with actionable message", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    const error = new ApiClientError("Rate limited", 429, "rate_limited");
    vi.mocked(scanDependencies).mockRejectedValue(error);

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Rate limit exceeded (429)")
    );
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("pkgwatch.dev/pricing")
    );
  });

  it("handles timeout error with actionable message", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    const error = new ApiClientError("Timeout", 0, "timeout");
    vi.mocked(scanDependencies).mockRejectedValue(error);

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Request timed out")
    );
  });

  it("handles network_error with actionable message", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    const error = new ApiClientError("Network error", 0, "network_error");
    vi.mocked(scanDependencies).mockRejectedValue(error);

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Network error")
    );
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("status.pkgwatch.dev")
    );
  });

  it("handles invalid API key format with actionable message", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    const error = new Error("Invalid API key format. Keys should start with 'pw_'");
    vi.mocked(scanDependencies).mockRejectedValue(error);

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Invalid API key format")
    );
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("pkgwatch.dev/dashboard")
    );
  });

  it("handles unknown errors gracefully", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockRejectedValue("string error");

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith("An unknown error occurred");
  });
});

describe("run() - Not Found Packages", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("warns about not found packages and sets output", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 1,
      critical: 0,
      high: 0,
      medium: 0,
      low: 1,
      packages: [
        {
          package: "good-pkg",
          risk_level: "LOW",
          health_score: 90,
          abandonment_risk: {},
          is_deprecated: false,
          archived: false,
          last_updated: "2024-01-01",
        },
      ],
      not_found: ["nonexistent-pkg", "typo-pkg"],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setOutput).toHaveBeenCalledWith("not-found-count", 2);
    expect(core.warning).toHaveBeenCalledWith(
      expect.stringContaining("2 package(s) not found")
    );
    expect(core.warning).toHaveBeenCalledWith(
      expect.stringContaining("nonexistent-pkg")
    );
  });

  it("does not warn when no packages are not found", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 1,
      critical: 0,
      high: 0,
      medium: 0,
      low: 1,
      packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setOutput).toHaveBeenCalledWith("not-found-count", 0);
    // Only threshold/risk warnings should be present, not "not found" warning
    const warningCalls = vi.mocked(core.warning).mock.calls;
    const notFoundWarnings = warningCalls.filter(
      (call) => call[0].includes("not found")
    );
    expect(notFoundWarnings.length).toBe(0);
  });
});

describe("run() - Include Dev Parsing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("accepts lowercase 'false' for include-dev", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "include-dev":
          return "false";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 1, critical: 0, high: 0, medium: 0, low: 1, packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(scanDependencies).toHaveBeenCalledWith("test-key", "/workspace", false);
  });

  it("accepts uppercase 'FALSE' for include-dev", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "include-dev":
          return "FALSE";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 1, critical: 0, high: 0, medium: 0, low: 1, packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(scanDependencies).toHaveBeenCalledWith("test-key", "/workspace", false);
  });

  it("accepts 'no' for include-dev", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "include-dev":
          return "no";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 1, critical: 0, high: 0, medium: 0, low: 1, packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(scanDependencies).toHaveBeenCalledWith("test-key", "/workspace", false);
  });

  it("accepts '0' for include-dev", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "include-dev":
          return "0";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 1, critical: 0, high: 0, medium: 0, low: 1, packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(scanDependencies).toHaveBeenCalledWith("test-key", "/workspace", false);
  });
});

describe("run() - Scan Mode Validation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("accepts scan-mode=single", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "single";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 1, critical: 0, high: 0, medium: 0, low: 1, packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(scanDependencies).toHaveBeenCalled();
    expect(core.setFailed).not.toHaveBeenCalledWith(
      expect.stringContaining("Invalid 'scan-mode'")
    );
  });

  it("accepts scan-mode=recursive (case insensitive)", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "RECURSIVE";
        default:
          return "";
      }
    });

    mockScanRepository.mockResolvedValue({
      manifests: [],
      summary: {
        totalManifests: 0,
        successfulManifests: 0,
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
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(mockScanRepository).toHaveBeenCalled();
    expect(core.setFailed).not.toHaveBeenCalledWith(
      expect.stringContaining("Invalid 'scan-mode'")
    );
  });

  it("rejects invalid scan-mode values", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "invalid-mode";
        default:
          return "";
      }
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Invalid 'scan-mode' value: invalid-mode")
    );
  });
});

describe("run() - Max Manifests Validation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("accepts valid max-manifests value", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        case "max-manifests":
          return "50";
        default:
          return "";
      }
    });

    mockScanRepository.mockResolvedValue({
      manifests: [],
      summary: {
        totalManifests: 0,
        successfulManifests: 0,
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
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).not.toHaveBeenCalledWith(
      expect.stringContaining("Invalid 'max-manifests'")
    );
  });

  it("rejects max-manifests below minimum (1)", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        case "max-manifests":
          return "0";
        default:
          return "";
      }
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Invalid 'max-manifests'")
    );
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("between 1 and 1000")
    );
  });

  it("rejects max-manifests above maximum (1000)", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        case "max-manifests":
          return "1001";
        default:
          return "";
      }
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Invalid 'max-manifests'")
    );
  });

  it("rejects non-numeric max-manifests", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        case "max-manifests":
          return "abc";
        default:
          return "";
      }
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Invalid 'max-manifests'")
    );
  });
});

describe("run() - Recursive Scan Outputs", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("sets recursive-specific outputs", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        default:
          return "";
      }
    });

    mockScanRepository.mockResolvedValue({
      manifests: [
        {
          manifest: { relativePath: "package.json", ecosystem: "npm" },
          status: "success",
          packages: [
            { package: "lodash", risk_level: "LOW", health_score: 90 },
          ],
          counts: { critical: 0, high: 0, medium: 0, low: 1 },
        },
        {
          manifest: { relativePath: "packages/api/package.json", ecosystem: "npm" },
          status: "success",
          packages: [
            { package: "express", risk_level: "MEDIUM", health_score: 70 },
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
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setOutput).toHaveBeenCalledWith("manifests-scanned", 2);
    expect(core.setOutput).toHaveBeenCalledWith("manifests-failed", 0);
    expect(core.setOutput).toHaveBeenCalledWith("truncated", false);
    expect(core.setOutput).toHaveBeenCalledWith("highest-risk", "MEDIUM");
    expect(core.setOutput).toHaveBeenCalledWith("has-issues", false);
    expect(core.setOutput).toHaveBeenCalledWith(
      "per-manifest-results",
      expect.stringContaining("package.json")
    );
  });

  it("warns when scan is truncated", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        case "max-manifests":
          return "5";
        default:
          return "";
      }
    });

    mockScanRepository.mockResolvedValue({
      manifests: [],
      summary: {
        totalManifests: 5,
        successfulManifests: 5,
        failedManifests: 0,
        uniquePackages: 100,
        totalPackages: 150,
        critical: 0,
        high: 0,
        medium: 0,
        low: 100,
      },
      truncated: true,
      rateLimited: false,
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.warning).toHaveBeenCalledWith(
      expect.stringContaining("Manifest limit reached")
    );
    expect(core.setOutput).toHaveBeenCalledWith("truncated", true);
  });

  it("warns when rate limited during recursive scan", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        default:
          return "";
      }
    });

    mockScanRepository.mockResolvedValue({
      manifests: [],
      summary: {
        totalManifests: 3,
        successfulManifests: 2,
        failedManifests: 1,
        uniquePackages: 50,
        totalPackages: 50,
        critical: 0,
        high: 0,
        medium: 0,
        low: 50,
      },
      truncated: false,
      rateLimited: true,
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.warning).toHaveBeenCalledWith(
      expect.stringContaining("Rate limit reached")
    );
  });

  it("aggregates not-found packages across manifests", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        default:
          return "";
      }
    });

    mockScanRepository.mockResolvedValue({
      manifests: [
        {
          manifest: { relativePath: "package.json", ecosystem: "npm" },
          status: "success",
          packages: [],
          counts: { critical: 0, high: 0, medium: 0, low: 0 },
          notFound: ["pkg-a", "pkg-b"],
        },
        {
          manifest: { relativePath: "apps/web/package.json", ecosystem: "npm" },
          status: "success",
          packages: [],
          counts: { critical: 0, high: 0, medium: 0, low: 0 },
          notFound: ["pkg-c"],
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
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setOutput).toHaveBeenCalledWith("not-found-count", 3);
    expect(core.warning).toHaveBeenCalledWith(
      expect.stringContaining("3 package(s) not found")
    );
  });
});

describe("run() - Recursive Scan Threshold Logic", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("fails when recursive scan finds critical packages with fail-on=CRITICAL", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        case "fail-on":
          return "CRITICAL";
        default:
          return "";
      }
    });

    mockScanRepository.mockResolvedValue({
      manifests: [
        {
          manifest: { relativePath: "package.json", ecosystem: "npm" },
          status: "success",
          packages: [
            { package: "vulnerable-pkg", risk_level: "CRITICAL", health_score: 10 },
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
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("CRITICAL")
    );
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("1 manifests")
    );
  });

  it("warns in soft-fail mode for recursive scans", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        case "fail-on":
          return "HIGH";
        case "soft-fail":
          return "true";
        default:
          return "";
      }
    });

    mockScanRepository.mockResolvedValue({
      manifests: [
        {
          manifest: { relativePath: "package.json", ecosystem: "npm" },
          status: "success",
          packages: [
            { package: "risky-pkg", risk_level: "HIGH", health_score: 35 },
          ],
          counts: { critical: 0, high: 1, medium: 0, low: 0 },
        },
      ],
      summary: {
        totalManifests: 1,
        successfulManifests: 1,
        failedManifests: 0,
        uniquePackages: 1,
        totalPackages: 1,
        critical: 0,
        high: 1,
        medium: 0,
        low: 0,
      },
      truncated: false,
      rateLimited: false,
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.warning).toHaveBeenCalledWith(
      expect.stringContaining("soft-fail mode")
    );
    // Should not call setFailed for threshold in soft-fail
    const failedCalls = vi.mocked(core.setFailed).mock.calls;
    const thresholdFails = failedCalls.filter(
      (call) => call[0].includes("HIGH") && !call[0].includes("Authentication")
    );
    expect(thresholdFails.length).toBe(0);
  });
});

describe("run() - Recursive Scan Annotations", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("generates annotations with manifest path as file reference", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        default:
          return "";
      }
    });

    mockScanRepository.mockResolvedValue({
      manifests: [
        {
          manifest: { relativePath: "apps/frontend/package.json", ecosystem: "npm" },
          status: "success",
          packages: [
            {
              package: "risky-dep",
              risk_level: "CRITICAL",
              health_score: 15,
              abandonment_risk: { risk_factors: ["No commits in 2 years"] },
            },
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
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.warning).toHaveBeenCalledWith(
      expect.stringContaining("risky-dep"),
      expect.objectContaining({
        title: "Critical Dependency Risk",
        file: "apps/frontend/package.json",
      })
    );
  });

  it("skips annotations for failed manifests", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        default:
          return "";
      }
    });

    mockScanRepository.mockResolvedValue({
      manifests: [
        {
          manifest: { relativePath: "broken/package.json", ecosystem: "npm" },
          status: "parse_error",
          error: "Invalid JSON",
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
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    // Should not have any package-related warnings
    const warningCalls = vi.mocked(core.warning).mock.calls;
    const packageWarnings = warningCalls.filter(
      (call) => typeof call[0] === "string" && call[0].includes("risk")
    );
    expect(packageWarnings.length).toBe(0);
  });
});

describe("run() - Exclude Patterns", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("uses default excludes when no patterns provided", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        case "exclude-patterns":
          return "";
        default:
          return "";
      }
    });

    mockScanRepository.mockResolvedValue({
      manifests: [],
      summary: {
        totalManifests: 0,
        successfulManifests: 0,
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
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(mockScanRepository).toHaveBeenCalledWith(
      expect.objectContaining({
        excludePatterns: ["node_modules", ".git", "vendor"],
      })
    );
  });

  it("parses comma-separated exclude patterns", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        case "scan-mode":
          return "recursive";
        case "exclude-patterns":
          return "dist, build, coverage";
        default:
          return "";
      }
    });

    mockScanRepository.mockResolvedValue({
      manifests: [],
      summary: {
        totalManifests: 0,
        successfulManifests: 0,
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
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(mockScanRepository).toHaveBeenCalledWith(
      expect.objectContaining({
        excludePatterns: ["dist", "build", "coverage"],
      })
    );
  });
});

describe("run() - Highest Risk Determination", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("sets highest-risk to NONE when all packages are healthy", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 2,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setOutput).toHaveBeenCalledWith("highest-risk", "NONE");
  });

  it("sets highest-risk to LOW when only low-risk packages exist", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 5,
      critical: 0,
      high: 0,
      medium: 0,
      low: 5,
      packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setOutput).toHaveBeenCalledWith("highest-risk", "LOW");
  });

  it("sets highest-risk to MEDIUM when medium is highest", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 5,
      critical: 0,
      high: 0,
      medium: 2,
      low: 3,
      packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setOutput).toHaveBeenCalledWith("highest-risk", "MEDIUM");
  });
});

describe("run() - API Key Required Error", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("handles API key is required error with actionable message", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    const error = new Error("API key is required for this operation");
    vi.mocked(scanDependencies).mockRejectedValue(error);

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("API key is required")
    );
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("pkgwatch.dev/dashboard")
    );
  });
});

describe("run() - Default API Error", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("handles ApiClientError with unknown code gracefully", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    const error = new ApiClientError("Something went wrong", 500, "server_error");
    vi.mocked(scanDependencies).mockRejectedValue(error);

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("API error: Something went wrong")
    );
  });
});

describe("run() - Single Scan Metadata Outputs", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.GITHUB_WORKSPACE = "/workspace";
  });

  afterEach(() => {
    delete process.env.GITHUB_WORKSPACE;
  });

  it("sets recursive-mode outputs to defaults in single mode", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    vi.mocked(scanDependencies).mockResolvedValue({
      total: 1,
      critical: 0,
      high: 0,
      medium: 0,
      low: 1,
      packages: [],
    });

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setOutput).toHaveBeenCalledWith("manifests-scanned", 1);
    expect(core.setOutput).toHaveBeenCalledWith("manifests-failed", 0);
    expect(core.setOutput).toHaveBeenCalledWith("per-manifest-results", "{}");
    expect(core.setOutput).toHaveBeenCalledWith("truncated", false);
  });

  it("outputs full JSON results", async () => {
    vi.mocked(core.getInput).mockImplementation((name: string) => {
      switch (name) {
        case "api-key":
          return "test-key";
        default:
          return "";
      }
    });

    const mockResult = {
      total: 2,
      critical: 1,
      high: 0,
      medium: 0,
      low: 1,
      packages: [
        { package: "bad", risk_level: "CRITICAL", health_score: 10 },
        { package: "good", risk_level: "LOW", health_score: 90 },
      ],
    };

    vi.mocked(scanDependencies).mockResolvedValue(mockResult);

    vi.resetModules();
    await import("../src/index.js");

    await new Promise((r) => setTimeout(r, 50));

    expect(core.setOutput).toHaveBeenCalledWith(
      "results",
      JSON.stringify(mockResult)
    );
  });
});
