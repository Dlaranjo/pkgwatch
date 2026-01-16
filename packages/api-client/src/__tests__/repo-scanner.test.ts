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
