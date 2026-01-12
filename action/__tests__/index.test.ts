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
}));

import { scanDependencies } from "../src/scanner.js";
import { generateSummary } from "../src/summary.js";
import { ApiClientError } from "../src/api.js";

// Mock the api module for error handling tests
vi.mock("../src/api.js", async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    ApiClientError: actual.ApiClientError,
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
      expect.stringContaining("pkgwatch.laranjo.dev/dashboard")
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
      expect.stringContaining("pkgwatch.laranjo.dev/pricing")
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
      expect.stringContaining("status.pkgwatch.laranjo.dev")
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
      expect.stringContaining("pkgwatch.laranjo.dev/dashboard")
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
