import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scanRepository, previewRepoScan } from "../repo-scanner.js";
import { ApiClientError } from "../index.js";
import type { ScanResult, PackageHealth } from "../index.js";

// ===========================================
// Test Fixtures
// ===========================================

const PACKAGE_JSON = `{
  "name": "test-project",
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.18.0"
  }
}`;

const PACKAGE_JSON_WITH_DEV = `{
  "name": "test-project",
  "dependencies": { "lodash": "^4.17.21" },
  "devDependencies": { "jest": "^29.0.0" }
}`;

const REQUIREMENTS_TXT = `requests>=2.28.0
flask==2.3.0`;

const MOCK_NPM_HEALTH: PackageHealth[] = [
  {
    package: "lodash",
    health_score: 85,
    risk_level: "LOW",
    abandonment_risk: {},
    is_deprecated: false,
    archived: false,
    last_updated: "2024-01-01T00:00:00Z",
  },
  {
    package: "express",
    health_score: 90,
    risk_level: "LOW",
    abandonment_risk: {},
    is_deprecated: false,
    archived: false,
    last_updated: "2024-01-01T00:00:00Z",
  },
];

const MOCK_PYPI_HEALTH: PackageHealth[] = [
  {
    package: "requests",
    health_score: 75,
    risk_level: "MEDIUM",
    abandonment_risk: {},
    is_deprecated: false,
    archived: false,
    last_updated: "2024-01-01T00:00:00Z",
  },
  {
    package: "flask",
    health_score: 80,
    risk_level: "LOW",
    abandonment_risk: {},
    is_deprecated: false,
    archived: false,
    last_updated: "2024-01-01T00:00:00Z",
  },
];

// ===========================================
// Helper Functions
// ===========================================

function createTestDir(): string {
  const dir = join(tmpdir(), `pkgwatch-scanner-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function createMockScanResult(packages: PackageHealth[], notFound: string[] = []): ScanResult {
  return {
    total: packages.length,
    critical: packages.filter((p) => p.risk_level === "CRITICAL").length,
    high: packages.filter((p) => p.risk_level === "HIGH").length,
    medium: packages.filter((p) => p.risk_level === "MEDIUM").length,
    low: packages.filter((p) => p.risk_level === "LOW").length,
    packages,
    not_found: notFound,
  };
}

// ===========================================
// Mock Setup
// ===========================================

// Use vi.hoisted to ensure mockScan is available during mock hoisting
const { mockScan } = vi.hoisted(() => ({
  mockScan: vi.fn(),
}));

vi.mock("../index.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../index.js")>();

  // Create a mock class that extends the real PkgWatchClient
  class MockPkgWatchClient {
    constructor(_apiKey?: string, _options?: unknown) {
      // Constructor doesn't need to do anything
    }
    scan = mockScan;
  }

  return {
    ...original,
    PkgWatchClient: MockPkgWatchClient,
  };
});

// ===========================================
// Preview Tests (No API Calls)
// ===========================================

describe("previewRepoScan", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("counts packages without making API calls", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    const result = previewRepoScan({ basePath: testDir });

    expect(result.manifests).toHaveLength(1);
    expect(result.packageCounts.npm).toBe(2); // lodash, express
    expect(result.packageCounts.pypi).toBe(0);
    expect(result.packageCounts.total).toBe(2);
  });

  it("counts packages across multiple ecosystems", () => {
    mkdirSync(join(testDir, "frontend"), { recursive: true });
    writeFileSync(join(testDir, "frontend", "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "backend"), { recursive: true });
    writeFileSync(join(testDir, "backend", "requirements.txt"), REQUIREMENTS_TXT);

    const result = previewRepoScan({ basePath: testDir });

    expect(result.manifests).toHaveLength(2);
    expect(result.packageCounts.npm).toBe(2);
    expect(result.packageCounts.pypi).toBe(2);
    expect(result.packageCounts.total).toBe(4);
  });

  it("deduplicates packages across manifests", () => {
    // Two package.json files with overlapping dependencies
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "sub"), { recursive: true });
    writeFileSync(join(testDir, "sub", "package.json"), `{
      "dependencies": { "lodash": "^4.17.21", "axios": "^1.0.0" }
    }`);

    const result = previewRepoScan({ basePath: testDir });

    expect(result.manifests).toHaveLength(2);
    // lodash appears in both, but should be counted once
    expect(result.packageCounts.npm).toBe(3); // lodash, express, axios
  });

  it("respects includeDev option", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON_WITH_DEV);

    const withDev = previewRepoScan({ basePath: testDir, includeDev: true });
    expect(withDev.packageCounts.npm).toBe(2); // lodash, jest

    const withoutDev = previewRepoScan({ basePath: testDir, includeDev: false });
    expect(withoutDev.packageCounts.npm).toBe(1); // lodash only
  });

  it("reports truncation when limit reached", () => {
    // Create many packages
    for (let i = 0; i < 10; i++) {
      const dir = join(testDir, `pkg-${i}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "package.json"), PACKAGE_JSON);
    }

    const result = previewRepoScan({ basePath: testDir, maxManifests: 5 });

    expect(result.manifests.length).toBeLessThanOrEqual(5);
    expect(result.truncated).toBe(true);
  });
});

// ===========================================
// Full Scan Tests (With Mocked API)
// ===========================================

describe("scanRepository", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
    vi.clearAllMocks();

    // Setup default mock behavior
    mockScan.mockImplementation((deps: Record<string, string>, ecosystem: string) => {
      if (ecosystem === "npm") {
        const packages = MOCK_NPM_HEALTH.filter((p) => Object.keys(deps).includes(p.package));
        const notFound = Object.keys(deps).filter(
          (name) => !MOCK_NPM_HEALTH.some((p) => p.package === name)
        );
        return Promise.resolve(createMockScanResult(packages, notFound));
      } else {
        const packages = MOCK_PYPI_HEALTH.filter((p) => Object.keys(deps).includes(p.package));
        const notFound = Object.keys(deps).filter(
          (name) => !MOCK_PYPI_HEALTH.some((p) => p.package === name)
        );
        return Promise.resolve(createMockScanResult(packages, notFound));
      }
    });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("scans a single npm manifest", async () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.manifests).toHaveLength(1);
    expect(result.manifests[0].status).toBe("success");
    expect(result.manifests[0].packages).toHaveLength(2);
    expect(result.summary.totalManifests).toBe(1);
    expect(result.summary.successfulManifests).toBe(1);
    expect(result.summary.uniquePackages).toBe(2);
  });

  it("scans multiple manifests across ecosystems", async () => {
    mkdirSync(join(testDir, "frontend"), { recursive: true });
    writeFileSync(join(testDir, "frontend", "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "backend"), { recursive: true });
    writeFileSync(join(testDir, "backend", "requirements.txt"), REQUIREMENTS_TXT);

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.manifests).toHaveLength(2);
    expect(result.summary.totalManifests).toBe(2);
    expect(result.summary.successfulManifests).toBe(2);

    // Should have called scan twice (once per ecosystem)
    expect(mockScan).toHaveBeenCalledTimes(2);
  });

  it("handles parse errors gracefully", async () => {
    // Valid manifest
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    // Invalid manifest
    mkdirSync(join(testDir, "broken"), { recursive: true });
    writeFileSync(join(testDir, "broken", "package.json"), "not valid json");

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.manifests).toHaveLength(2);

    const successManifest = result.manifests.find((m) => m.status === "success");
    const errorManifest = result.manifests.find((m) => m.status === "parse_error");

    expect(successManifest).toBeDefined();
    expect(errorManifest).toBeDefined();
    expect(errorManifest?.error).toContain("Invalid JSON");
  });

  it("handles empty manifests", async () => {
    writeFileSync(join(testDir, "package.json"), '{"name": "empty"}');

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.manifests).toHaveLength(1);
    expect(result.manifests[0].status).toBe("success");
    expect(result.manifests[0].packages).toHaveLength(0);
    expect(result.manifests[0].counts?.total).toBe(0);
  });

  it("handles rate limiting", async () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    mockScan.mockRejectedValueOnce(
      new ApiClientError("Rate limit exceeded", 429, "rate_limited")
    );

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.rateLimited).toBe(true);
    expect(result.manifests[0].status).toBe("rate_limited");
  });

  it("handles API errors", async () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    mockScan.mockRejectedValueOnce(
      new ApiClientError("Server error", 500, "server_error")
    );

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.manifests[0].status).toBe("api_error");
    expect(result.manifests[0].error).toContain("Server error");
  });

  it("reports not found packages", async () => {
    writeFileSync(join(testDir, "package.json"), `{
      "dependencies": { "lodash": "^4.17.21", "unknown-pkg": "^1.0.0" }
    }`);

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.manifests[0].notFound).toContain("unknown-pkg");
  });

  it("calculates summary counts correctly", async () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "backend"), { recursive: true });
    writeFileSync(join(testDir, "backend", "requirements.txt"), REQUIREMENTS_TXT);

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    // 2 npm (LOW) + 1 pypi (MEDIUM) + 1 pypi (LOW)
    expect(result.summary.low).toBe(3);
    expect(result.summary.medium).toBe(1);
    expect(result.summary.high).toBe(0);
    expect(result.summary.critical).toBe(0);
  });

  it("calls progress callback", async () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    const onProgress = vi.fn();

    await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
      onProgress,
    });

    expect(onProgress).toHaveBeenCalled();
  });

  it("returns quota used", async () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.quotaUsed).toBe(2); // 2 unique packages
  });

  it("deduplicates packages across manifests for quota", async () => {
    // Same lodash in two manifests
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "sub"), { recursive: true });
    writeFileSync(join(testDir, "sub", "package.json"), `{
      "dependencies": { "lodash": "^4.17.21" }
    }`);

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    // lodash + express = 2, not 3
    expect(result.quotaUsed).toBe(2);
  });
});

// ===========================================
// Edge Cases
// ===========================================

describe("edge cases", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
    vi.clearAllMocks();

    // Use simple mock that returns empty results
    mockScan.mockResolvedValue(createMockScanResult([]));
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("handles directory with no manifests", async () => {
    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.manifests).toHaveLength(0);
    expect(result.summary.totalManifests).toBe(0);
    expect(result.quotaUsed).toBe(0);
  });

  it("sorts results by path", async () => {
    mkdirSync(join(testDir, "z-package"), { recursive: true });
    writeFileSync(join(testDir, "z-package", "package.json"), '{"name": "z"}');

    mkdirSync(join(testDir, "a-package"), { recursive: true });
    writeFileSync(join(testDir, "a-package", "package.json"), '{"name": "a"}');

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.manifests[0].manifest.relativePath).toContain("a-package");
    expect(result.manifests[1].manifest.relativePath).toContain("z-package");
  });
});

// ===========================================
// Large Repository Tests
// ===========================================

describe("large repository handling", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
    vi.clearAllMocks();

    mockScan.mockImplementation((deps: Record<string, string>) => {
      const packages = Object.keys(deps).map((name) => ({
        package: name,
        health_score: 75,
        risk_level: "LOW" as const,
        abandonment_risk: {},
        is_deprecated: false,
        archived: false,
        last_updated: "2024-01-01T00:00:00Z",
      }));
      return Promise.resolve(createMockScanResult(packages));
    });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("handles many manifests efficiently", async () => {
    // Create 20 packages
    for (let i = 0; i < 20; i++) {
      const dir = join(testDir, `pkg-${i}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({
          dependencies: { [`dep-${i}`]: "^1.0.0" },
        })
      );
    }

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.summary.totalManifests).toBe(20);
    expect(result.summary.uniquePackages).toBe(20);
  });

  it("handles manifest with many dependencies", async () => {
    const deps: Record<string, string> = {};
    for (let i = 0; i < 100; i++) {
      deps[`package-${i}`] = "^1.0.0";
    }
    writeFileSync(join(testDir, "package.json"), JSON.stringify({ dependencies: deps }));

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.summary.uniquePackages).toBe(100);
    expect(result.quotaUsed).toBe(100);
  });

  it("deduplicates shared dependencies across many manifests", async () => {
    // 10 packages all depending on lodash
    for (let i = 0; i < 10; i++) {
      const dir = join(testDir, `pkg-${i}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({
          dependencies: { lodash: "^4.17.21" },
        })
      );
    }

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    // lodash is shared, so unique count should be 1
    expect(result.summary.uniquePackages).toBe(1);
    expect(result.quotaUsed).toBe(1);
    // But total packages across manifests is 10
    expect(result.summary.totalPackages).toBe(10);
  });
});

// ===========================================
// Nested Dependencies Tests
// ===========================================

describe("nested dependencies handling", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
    vi.clearAllMocks();

    mockScan.mockImplementation((deps: Record<string, string>, ecosystem: string) => {
      if (ecosystem === "npm") {
        const packages = MOCK_NPM_HEALTH.filter((p) => Object.keys(deps).includes(p.package));
        return Promise.resolve(createMockScanResult(packages));
      } else {
        const packages = MOCK_PYPI_HEALTH.filter((p) => Object.keys(deps).includes(p.package));
        return Promise.resolve(createMockScanResult(packages));
      }
    });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("handles nested workspaces", async () => {
    const workspaceConfig = `{
      "name": "root",
      "workspaces": ["packages/*"]
    }`;
    writeFileSync(join(testDir, "package.json"), workspaceConfig);

    // Create workspace packages
    mkdirSync(join(testDir, "packages", "a"), { recursive: true });
    writeFileSync(
      join(testDir, "packages", "a", "package.json"),
      JSON.stringify({ dependencies: { lodash: "^4.17.21" } })
    );

    mkdirSync(join(testDir, "packages", "b"), { recursive: true });
    writeFileSync(
      join(testDir, "packages", "b", "package.json"),
      JSON.stringify({ dependencies: { express: "^4.18.0" } })
    );

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    // Should find root + 2 workspace packages (root has no deps)
    expect(result.manifests.length).toBeGreaterThanOrEqual(2);
  });

  it("handles devDependencies correctly", async () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON_WITH_DEV);

    const resultWithDev = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
      includeDev: true,
    });

    vi.clearAllMocks();
    mockScan.mockImplementation((deps: Record<string, string>) => {
      const packages = MOCK_NPM_HEALTH.filter((p) => Object.keys(deps).includes(p.package));
      return Promise.resolve(createMockScanResult(packages));
    });

    const resultWithoutDev = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
      includeDev: false,
    });

    expect(resultWithDev.summary.uniquePackages).toBeGreaterThanOrEqual(
      resultWithoutDev.summary.uniquePackages
    );
  });
});

// ===========================================
// Error Recovery Tests
// ===========================================

describe("error recovery", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
    vi.clearAllMocks();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("continues scanning after parse error in one manifest", async () => {
    // Valid manifest
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    // Invalid manifest
    mkdirSync(join(testDir, "broken"), { recursive: true });
    writeFileSync(join(testDir, "broken", "package.json"), "not valid json");

    // Another valid manifest
    mkdirSync(join(testDir, "valid"), { recursive: true });
    writeFileSync(join(testDir, "valid", "package.json"), PACKAGE_JSON);

    mockScan.mockResolvedValue(createMockScanResult(MOCK_NPM_HEALTH));

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    // Should have processed 2 valid + 1 parse error
    expect(result.summary.totalManifests).toBe(3);
    expect(result.summary.successfulManifests).toBe(2);
    expect(result.summary.failedManifests).toBe(1);

    const parseError = result.manifests.find((m) => m.status === "parse_error");
    expect(parseError).toBeDefined();
    expect(parseError?.manifest.relativePath).toContain("broken");
  });

  it("handles unexpected API errors gracefully", async () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    mockScan.mockRejectedValue(new Error("Unexpected error"));

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.manifests[0].status).toBe("api_error");
    expect(result.manifests[0].error).toContain("Unexpected error");
    expect(result.warnings.length).toBeGreaterThanOrEqual(1);
  });

  it("handles npm rate limit and skips pypi scan", async () => {
    mkdirSync(join(testDir, "frontend"), { recursive: true });
    writeFileSync(join(testDir, "frontend", "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "backend"), { recursive: true });
    writeFileSync(join(testDir, "backend", "requirements.txt"), REQUIREMENTS_TXT);

    // npm scan fails with rate limit
    mockScan.mockRejectedValueOnce(
      new ApiClientError("Rate limit exceeded", 429, "rate_limited")
    );

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.rateLimited).toBe(true);

    // Both npm and pypi manifests should be marked as rate limited
    const rateLimitedManifests = result.manifests.filter(
      (m) => m.status === "rate_limited"
    );
    expect(rateLimitedManifests).toHaveLength(2);
  });

  it("handles 401 unauthorized error", async () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    mockScan.mockRejectedValueOnce(
      new ApiClientError("Invalid API key", 401, "unauthorized")
    );

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.manifests[0].status).toBe("api_error");
    expect(result.manifests[0].error).toContain("Invalid API key");
  });

  it("handles 403 forbidden error", async () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    mockScan.mockRejectedValueOnce(
      new ApiClientError("Access denied", 403, "forbidden")
    );

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.manifests[0].status).toBe("api_error");
    expect(result.manifests[0].error).toContain("Access denied");
  });
});

// ===========================================
// Risk Level Counting Tests
// ===========================================

describe("risk level counting", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
    vi.clearAllMocks();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("correctly counts all risk levels", async () => {
    const mixedRiskPackages: PackageHealth[] = [
      {
        package: "critical-pkg",
        health_score: 20,
        risk_level: "CRITICAL",
        abandonment_risk: {},
        is_deprecated: true,
        archived: false,
        last_updated: "2024-01-01T00:00:00Z",
      },
      {
        package: "high-pkg",
        health_score: 40,
        risk_level: "HIGH",
        abandonment_risk: {},
        is_deprecated: false,
        archived: false,
        last_updated: "2024-01-01T00:00:00Z",
      },
      {
        package: "medium-pkg",
        health_score: 60,
        risk_level: "MEDIUM",
        abandonment_risk: {},
        is_deprecated: false,
        archived: false,
        last_updated: "2024-01-01T00:00:00Z",
      },
      {
        package: "low-pkg",
        health_score: 85,
        risk_level: "LOW",
        abandonment_risk: {},
        is_deprecated: false,
        archived: false,
        last_updated: "2024-01-01T00:00:00Z",
      },
    ];

    mockScan.mockResolvedValue(createMockScanResult(mixedRiskPackages));

    writeFileSync(
      join(testDir, "package.json"),
      JSON.stringify({
        dependencies: {
          "critical-pkg": "^1.0.0",
          "high-pkg": "^1.0.0",
          "medium-pkg": "^1.0.0",
          "low-pkg": "^1.0.0",
        },
      })
    );

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(result.summary.critical).toBe(1);
    expect(result.summary.high).toBe(1);
    expect(result.summary.medium).toBe(1);
    expect(result.summary.low).toBe(1);
  });

  it("counts only unique packages in summary", async () => {
    // Same high-risk package in two manifests
    mockScan.mockResolvedValue(
      createMockScanResult([
        {
          package: "risky-pkg",
          health_score: 30,
          risk_level: "HIGH",
          abandonment_risk: {},
          is_deprecated: false,
          archived: false,
          last_updated: "2024-01-01T00:00:00Z",
        },
      ])
    );

    writeFileSync(
      join(testDir, "package.json"),
      JSON.stringify({ dependencies: { "risky-pkg": "^1.0.0" } })
    );

    mkdirSync(join(testDir, "sub"), { recursive: true });
    writeFileSync(
      join(testDir, "sub", "package.json"),
      JSON.stringify({ dependencies: { "risky-pkg": "^1.0.0" } })
    );

    const result = await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    // High count should be 1 (unique), not 2
    expect(result.summary.high).toBe(1);
  });
});

// ===========================================
// Progress Callback Tests
// ===========================================

describe("progress callback", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
    vi.clearAllMocks();

    mockScan.mockResolvedValue(createMockScanResult(MOCK_NPM_HEALTH));
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("calls progress with correct counts", async () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "sub"), { recursive: true });
    writeFileSync(join(testDir, "sub", "package.json"), PACKAGE_JSON);

    const progressCalls: Array<{ current: number; total: number; manifest: string }> = [];
    const onProgress = (current: number, total: number, manifest: string) => {
      progressCalls.push({ current, total, manifest });
    };

    await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
      onProgress,
    });

    expect(progressCalls.length).toBeGreaterThan(0);
    // Should show scanning messages
    expect(progressCalls.some((p) => p.manifest.includes("Scanning"))).toBe(true);
  });

  it("progress callback receives increasing values", async () => {
    mkdirSync(join(testDir, "frontend"), { recursive: true });
    writeFileSync(join(testDir, "frontend", "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "backend"), { recursive: true });
    writeFileSync(join(testDir, "backend", "requirements.txt"), REQUIREMENTS_TXT);

    mockScan.mockImplementation((deps: Record<string, string>, ecosystem: string) => {
      if (ecosystem === "npm") {
        return Promise.resolve(createMockScanResult(MOCK_NPM_HEALTH));
      }
      return Promise.resolve(createMockScanResult(MOCK_PYPI_HEALTH));
    });

    const progressValues: number[] = [];
    const onProgress = (current: number) => {
      progressValues.push(current);
    };

    await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
      onProgress,
    });

    // Progress should generally increase
    for (let i = 1; i < progressValues.length; i++) {
      expect(progressValues[i]).toBeGreaterThanOrEqual(progressValues[i - 1]);
    }
  });
});

// ===========================================
// Client Options Tests
// ===========================================

describe("client options", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
    vi.clearAllMocks();
    mockScan.mockResolvedValue(createMockScanResult(MOCK_NPM_HEALTH));
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("passes client options to PkgWatchClient", async () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
      clientOptions: {
        baseUrl: "https://custom.api.com",
        timeout: 60000,
        maxRetries: 5,
      },
    });

    // The mock client is instantiated - we can't easily verify options
    // but this test ensures no errors with custom options
    expect(mockScan).toHaveBeenCalled();
  });
});

// ===========================================
// Mixed Ecosystem Scan Order Tests
// ===========================================

describe("mixed ecosystem scan order", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
    vi.clearAllMocks();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("scans npm before pypi", async () => {
    const callOrder: string[] = [];

    mockScan.mockImplementation((_deps: Record<string, string>, ecosystem: string) => {
      callOrder.push(ecosystem);
      return Promise.resolve(
        createMockScanResult(ecosystem === "npm" ? MOCK_NPM_HEALTH : MOCK_PYPI_HEALTH)
      );
    });

    mkdirSync(join(testDir, "frontend"), { recursive: true });
    writeFileSync(join(testDir, "frontend", "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "backend"), { recursive: true });
    writeFileSync(join(testDir, "backend", "requirements.txt"), REQUIREMENTS_TXT);

    await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    expect(callOrder).toEqual(["npm", "pypi"]);
  });

  it("skips ecosystem scan if no packages of that type", async () => {
    mockScan.mockResolvedValue(createMockScanResult(MOCK_NPM_HEALTH));

    // Only npm packages
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    await scanRepository({
      basePath: testDir,
      apiKey: "pw_test_key",
    });

    // Should only call scan once (for npm)
    expect(mockScan).toHaveBeenCalledTimes(1);
    expect(mockScan).toHaveBeenCalledWith(
      expect.any(Object),
      "npm"
    );
  });
});
