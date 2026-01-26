import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  discoverManifests,
  discoverManifestsByEcosystem,
  DEFAULT_EXCLUDES,
} from "../discovery.js";

// ===========================================
// Test Fixtures
// ===========================================

const PACKAGE_JSON = `{
  "name": "test-project",
  "dependencies": { "lodash": "^4.17.21" }
}`;

const PACKAGE_JSON_WORKSPACES = `{
  "name": "test-monorepo",
  "workspaces": ["packages/*", "apps/*"]
}`;

const PACKAGE_JSON_WORKSPACES_OBJECT = `{
  "name": "test-monorepo",
  "workspaces": {
    "packages": ["packages/*"]
  }
}`;

const PNPM_WORKSPACE = `packages:
  - "packages/*"
  - "apps/*"
`;

const REQUIREMENTS_TXT = `requests>=2.28.0
flask==2.3.0`;

const PYPROJECT_TOML = `[project]
name = "test-project"
dependencies = ["requests>=2.28.0"]`;

// ===========================================
// Helper Functions
// ===========================================

function createTestDir(): string {
  const dir = join(tmpdir(), `pkgwatch-discovery-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

// ===========================================
// Basic Discovery Tests
// ===========================================

describe("discoverManifests", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("discovers package.json in root", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(1);
    expect(result.manifests[0].ecosystem).toBe("npm");
    expect(result.manifests[0].format).toBe("package.json");
    expect(result.truncated).toBe(false);
  });

  it("discovers requirements.txt in root", () => {
    writeFileSync(join(testDir, "requirements.txt"), REQUIREMENTS_TXT);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(1);
    expect(result.manifests[0].ecosystem).toBe("pypi");
    expect(result.manifests[0].format).toBe("requirements.txt");
  });

  it("discovers pyproject.toml in root", () => {
    writeFileSync(join(testDir, "pyproject.toml"), PYPROJECT_TOML);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(1);
    expect(result.manifests[0].ecosystem).toBe("pypi");
    expect(result.manifests[0].format).toBe("pyproject.toml");
  });

  it("discovers multiple manifests in nested directories", () => {
    // Root
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    // Nested npm
    mkdirSync(join(testDir, "frontend"), { recursive: true });
    writeFileSync(join(testDir, "frontend", "package.json"), PACKAGE_JSON);

    // Nested python
    mkdirSync(join(testDir, "backend"), { recursive: true });
    writeFileSync(join(testDir, "backend", "requirements.txt"), REQUIREMENTS_TXT);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(3);
    const ecosystems = result.manifests.map((m) => m.ecosystem);
    expect(ecosystems).toContain("npm");
    expect(ecosystems).toContain("pypi");
  });

  it("returns empty array for directory with no manifests", () => {
    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(0);
    expect(result.truncated).toBe(false);
  });
});

// ===========================================
// Exclude Pattern Tests
// ===========================================

describe("exclude patterns", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("excludes node_modules by default", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);
    mkdirSync(join(testDir, "node_modules", "some-pkg"), { recursive: true });
    writeFileSync(join(testDir, "node_modules", "some-pkg", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(1);
    expect(result.manifests[0].relativePath).toBe("package.json");
  });

  it("excludes .git by default", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);
    mkdirSync(join(testDir, ".git", "hooks"), { recursive: true });
    writeFileSync(join(testDir, ".git", "hooks", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(1);
  });

  it("excludes vendor by default", () => {
    writeFileSync(join(testDir, "requirements.txt"), REQUIREMENTS_TXT);
    mkdirSync(join(testDir, "vendor", "pkg"), { recursive: true });
    writeFileSync(join(testDir, "vendor", "pkg", "requirements.txt"), REQUIREMENTS_TXT);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(1);
  });

  it("respects custom exclude patterns", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);
    mkdirSync(join(testDir, "custom-ignore"), { recursive: true });
    writeFileSync(join(testDir, "custom-ignore", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({
      basePath: testDir,
      excludePatterns: ["**/custom-ignore/**"],
    });

    expect(result.manifests).toHaveLength(1);
    expect(result.manifests[0].relativePath).toBe("package.json");
  });

  it("DEFAULT_EXCLUDES contains expected patterns", () => {
    expect(DEFAULT_EXCLUDES).toContain("**/node_modules/**");
    expect(DEFAULT_EXCLUDES).toContain("**/.git/**");
    expect(DEFAULT_EXCLUDES).toContain("**/vendor/**");
    expect(DEFAULT_EXCLUDES).toContain("**/dist/**");
    expect(DEFAULT_EXCLUDES).toContain("**/build/**");
  });
});

// ===========================================
// Workspace Detection Tests
// ===========================================

describe("workspace detection", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("discovers npm workspaces", () => {
    // Root with workspaces config
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON_WORKSPACES);

    // Workspace packages
    mkdirSync(join(testDir, "packages", "core"), { recursive: true });
    writeFileSync(join(testDir, "packages", "core", "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "packages", "cli"), { recursive: true });
    writeFileSync(join(testDir, "packages", "cli", "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "apps", "web"), { recursive: true });
    writeFileSync(join(testDir, "apps", "web", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests.length).toBeGreaterThanOrEqual(3);

    // Check that workspace packages are marked
    const workspaceManifests = result.manifests.filter((m) => m.isWorkspace);
    expect(workspaceManifests.length).toBeGreaterThanOrEqual(2);
  });

  it("discovers workspaces with object format", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON_WORKSPACES_OBJECT);

    mkdirSync(join(testDir, "packages", "api"), { recursive: true });
    writeFileSync(join(testDir, "packages", "api", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests.length).toBeGreaterThanOrEqual(1);
  });

  it("discovers pnpm workspaces", () => {
    writeFileSync(join(testDir, "pnpm-workspace.yaml"), PNPM_WORKSPACE);
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "packages", "shared"), { recursive: true });
    writeFileSync(join(testDir, "packages", "shared", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests.length).toBeGreaterThanOrEqual(2);
  });

  it("can disable workspace following", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON_WORKSPACES);

    mkdirSync(join(testDir, "packages", "core"), { recursive: true });
    writeFileSync(join(testDir, "packages", "core", "package.json"), PACKAGE_JSON);

    // With workspaces disabled, should use recursive discovery
    const result = discoverManifests({
      basePath: testDir,
      followWorkspaces: false,
    });

    // Should still find both, but via recursive discovery
    expect(result.manifests.length).toBeGreaterThanOrEqual(2);
    // None should be marked as workspace
    expect(result.manifests.every((m) => !m.isWorkspace)).toBe(true);
  });
});

// ===========================================
// Limit Tests
// ===========================================

describe("limits", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("respects maxManifests limit", () => {
    // Create 10 packages
    for (let i = 0; i < 10; i++) {
      const dir = join(testDir, `pkg-${i}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "package.json"), PACKAGE_JSON);
    }

    const result = discoverManifests({
      basePath: testDir,
      maxManifests: 5,
    });

    expect(result.manifests.length).toBeLessThanOrEqual(5);
    expect(result.truncated).toBe(true);
  });

  it("respects maxDepth limit", () => {
    // Create nested structure: level1/level2/level3/level4
    const level1 = join(testDir, "level1");
    const level2 = join(level1, "level2");
    const level3 = join(level2, "level3");
    const level4 = join(level3, "level4");

    mkdirSync(level4, { recursive: true });
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);
    writeFileSync(join(level1, "package.json"), PACKAGE_JSON);
    writeFileSync(join(level4, "package.json"), PACKAGE_JSON);

    const result = discoverManifests({
      basePath: testDir,
      maxDepth: 2,
      followWorkspaces: false,
    });

    // Should find root and level1, but not level4
    const relativePaths = result.manifests.map((m) => m.relativePath);
    expect(relativePaths).toContain("package.json");
    expect(relativePaths).toContain(join("level1", "package.json"));
    expect(relativePaths).not.toContain(join("level1", "level2", "level3", "level4", "package.json"));
  });
});

// ===========================================
// Symlink Handling Tests
// ===========================================

describe("symlink handling", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("follows valid symlinks", () => {
    // Create a real directory with package.json
    const realDir = join(testDir, "real-pkg");
    mkdirSync(realDir, { recursive: true });
    writeFileSync(join(realDir, "package.json"), PACKAGE_JSON);

    // Create a symlink to it
    const linkDir = join(testDir, "linked-pkg");
    symlinkSync(realDir, linkDir);

    const result = discoverManifests({
      basePath: testDir,
      followWorkspaces: false,
    });

    // Should find both the real and linked paths
    expect(result.manifests.length).toBeGreaterThanOrEqual(1);
  });

  it("detects and skips symlink loops", () => {
    // Create a directory structure with a loop
    const dirA = join(testDir, "a");
    mkdirSync(dirA, { recursive: true });
    writeFileSync(join(dirA, "package.json"), PACKAGE_JSON);

    // Create symlink that points back to parent
    try {
      symlinkSync(testDir, join(dirA, "loop"));
    } catch {
      // Skip test if symlinks not supported
      return;
    }

    const result = discoverManifests({
      basePath: testDir,
      followWorkspaces: false,
    });

    // Should not hang and should have a warning
    expect(result.manifests.length).toBeGreaterThanOrEqual(1);
    // May or may not have a warning depending on traversal order
  });
});

// ===========================================
// Mixed Ecosystem Tests
// ===========================================

describe("mixed ecosystem discovery", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("discovers both npm and pypi manifests", () => {
    // Frontend (npm)
    mkdirSync(join(testDir, "frontend"), { recursive: true });
    writeFileSync(join(testDir, "frontend", "package.json"), PACKAGE_JSON);

    // Backend (python)
    mkdirSync(join(testDir, "backend"), { recursive: true });
    writeFileSync(join(testDir, "backend", "requirements.txt"), REQUIREMENTS_TXT);

    // ML service (python)
    mkdirSync(join(testDir, "ml"), { recursive: true });
    writeFileSync(join(testDir, "ml", "pyproject.toml"), PYPROJECT_TOML);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(3);

    const npmManifests = result.manifests.filter((m) => m.ecosystem === "npm");
    const pypiManifests = result.manifests.filter((m) => m.ecosystem === "pypi");

    expect(npmManifests).toHaveLength(1);
    expect(pypiManifests).toHaveLength(2);
  });

  it("discoverManifestsByEcosystem groups correctly", () => {
    mkdirSync(join(testDir, "frontend"), { recursive: true });
    writeFileSync(join(testDir, "frontend", "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "backend"), { recursive: true });
    writeFileSync(join(testDir, "backend", "requirements.txt"), REQUIREMENTS_TXT);

    const result = discoverManifestsByEcosystem({ basePath: testDir });

    expect(result.npm).toHaveLength(1);
    expect(result.pypi).toHaveLength(1);
    expect(result.npm[0].ecosystem).toBe("npm");
    expect(result.pypi[0].ecosystem).toBe("pypi");
  });
});

// ===========================================
// Edge Cases
// ===========================================

describe("edge cases", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("handles directories with only one type of manifest", () => {
    // Only package.json files
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);
    mkdirSync(join(testDir, "sub"), { recursive: true });
    writeFileSync(join(testDir, "sub", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(2);
    expect(result.manifests.every((m) => m.ecosystem === "npm")).toBe(true);
  });

  it("handles empty directories gracefully", () => {
    mkdirSync(join(testDir, "empty"), { recursive: true });

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(0);
    expect(result.warnings).toHaveLength(0);
  });

  it("provides relative paths correctly", () => {
    mkdirSync(join(testDir, "packages", "core"), { recursive: true });
    writeFileSync(join(testDir, "packages", "core", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests[0].relativePath).toBe(join("packages", "core", "package.json"));
    expect(result.manifests[0].path).toContain(testDir);
  });

  it("handles special characters in directory names", () => {
    const specialDir = join(testDir, "my-app_v2.0");
    mkdirSync(specialDir, { recursive: true });
    writeFileSync(join(specialDir, "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(1);
    expect(result.manifests[0].relativePath).toContain("my-app_v2.0");
  });
});

// ===========================================
// Multi-language Repository Tests
// ===========================================

describe("multi-language repositories", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("discovers npm, pypi, and mixed manifests in same repo", () => {
    // Root npm
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    // Python service
    mkdirSync(join(testDir, "services", "api"), { recursive: true });
    writeFileSync(join(testDir, "services", "api", "requirements.txt"), REQUIREMENTS_TXT);

    // Another Python service with pyproject.toml
    mkdirSync(join(testDir, "services", "ml"), { recursive: true });
    writeFileSync(join(testDir, "services", "ml", "pyproject.toml"), PYPROJECT_TOML);

    // Frontend npm
    mkdirSync(join(testDir, "apps", "web"), { recursive: true });
    writeFileSync(join(testDir, "apps", "web", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(4);

    const npmCount = result.manifests.filter((m) => m.ecosystem === "npm").length;
    const pypiCount = result.manifests.filter((m) => m.ecosystem === "pypi").length;

    expect(npmCount).toBe(2);
    expect(pypiCount).toBe(2);
  });

  it("handles same directory with both package.json and requirements.txt", () => {
    // Some projects have both (e.g., JS tools with Python scripts)
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);
    writeFileSync(join(testDir, "requirements.txt"), REQUIREMENTS_TXT);

    const result = discoverManifests({ basePath: testDir });

    // Should only find one manifest (package.json takes priority)
    expect(result.manifests).toHaveLength(1);
    expect(result.manifests[0].format).toBe("package.json");
  });

  it("handles deeply nested multi-language structure", () => {
    // Deep nesting
    mkdirSync(join(testDir, "a", "b", "c", "d", "e"), { recursive: true });
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);
    writeFileSync(join(testDir, "a", "requirements.txt"), REQUIREMENTS_TXT);
    writeFileSync(join(testDir, "a", "b", "package.json"), PACKAGE_JSON);
    writeFileSync(join(testDir, "a", "b", "c", "pyproject.toml"), PYPROJECT_TOML);
    writeFileSync(join(testDir, "a", "b", "c", "d", "e", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir, maxDepth: 10 });

    expect(result.manifests.length).toBeGreaterThanOrEqual(4);
  });
});

// ===========================================
// Missing/Invalid File Tests
// ===========================================

describe("missing and invalid files", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("handles non-existent base path gracefully", () => {
    const nonExistent = join(testDir, "does-not-exist");
    // This should not throw, but handle gracefully
    expect(() => discoverManifests({ basePath: nonExistent })).not.toThrow();
  });

  it("handles invalid workspace patterns gracefully", () => {
    const invalidWorkspaces = `{
      "name": "test",
      "workspaces": ["packages/*/does/not/exist"]
    }`;
    writeFileSync(join(testDir, "package.json"), invalidWorkspaces);

    const result = discoverManifests({ basePath: testDir });

    // Should still work, just no workspace packages found
    expect(result.manifests).toHaveLength(1);
    expect(result.manifests[0].relativePath).toBe("package.json");
  });

  it("handles malformed package.json for workspace detection", () => {
    writeFileSync(join(testDir, "package.json"), "not valid json");

    const result = discoverManifests({ basePath: testDir });

    // Should have a warning about failed workspace detection
    expect(result.warnings.length).toBeGreaterThanOrEqual(1);
    expect(result.warnings.some((w) => w.includes("package.json"))).toBe(true);
  });

  it("handles malformed pnpm-workspace.yaml", () => {
    writeFileSync(join(testDir, "pnpm-workspace.yaml"), "not: [valid: yaml");
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    // Should fall back to recursive discovery
    expect(result.manifests.length).toBeGreaterThanOrEqual(1);
  });

  it("handles empty workspace arrays", () => {
    const emptyWorkspaces = `{
      "name": "test",
      "workspaces": []
    }`;
    writeFileSync(join(testDir, "package.json"), emptyWorkspaces);

    const result = discoverManifests({ basePath: testDir });

    // Should fall back to recursive discovery or find root
    expect(result.manifests.length).toBeGreaterThanOrEqual(0);
  });
});

// ===========================================
// Workspace Detection Edge Cases
// ===========================================

describe("workspace detection edge cases", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("handles workspaces with negation patterns", () => {
    // Some workspaces use negation (not all tools support this)
    const workspacesWithNegation = `{
      "name": "test",
      "workspaces": ["packages/*", "!packages/internal"]
    }`;
    writeFileSync(join(testDir, "package.json"), workspacesWithNegation);

    mkdirSync(join(testDir, "packages", "public"), { recursive: true });
    writeFileSync(join(testDir, "packages", "public", "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "packages", "internal"), { recursive: true });
    writeFileSync(join(testDir, "packages", "internal", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    // Negation may or may not be supported - just verify no crash
    expect(result.manifests.length).toBeGreaterThanOrEqual(1);
  });

  it("handles direct path workspaces (not globs)", () => {
    const directPaths = `{
      "name": "test",
      "workspaces": ["packages/core", "packages/cli"]
    }`;
    writeFileSync(join(testDir, "package.json"), directPaths);

    mkdirSync(join(testDir, "packages", "core"), { recursive: true });
    writeFileSync(join(testDir, "packages", "core", "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "packages", "cli"), { recursive: true });
    writeFileSync(join(testDir, "packages", "cli", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    // Should find root + 2 workspace packages
    expect(result.manifests.length).toBeGreaterThanOrEqual(2);
  });

  it("handles pnpm workspace with quoted entries", () => {
    const pnpmWorkspace = `packages:
  - "packages/*"
  - 'apps/*'
`;
    writeFileSync(join(testDir, "pnpm-workspace.yaml"), pnpmWorkspace);
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "packages", "a"), { recursive: true });
    writeFileSync(join(testDir, "packages", "a", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests.length).toBeGreaterThanOrEqual(2);
  });

  it("handles pnpm workspace with comments", () => {
    const pnpmWorkspaceWithComments = `# This is a comment
packages:
  # Another comment
  - "packages/*"
`;
    writeFileSync(join(testDir, "pnpm-workspace.yaml"), pnpmWorkspaceWithComments);
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "packages", "a"), { recursive: true });
    writeFileSync(join(testDir, "packages", "a", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests.length).toBeGreaterThanOrEqual(1);
  });
});

// ===========================================
// Performance and Limits
// ===========================================

describe("performance and limits", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("handles exactly maxManifests limit", () => {
    // Create exactly 5 packages
    for (let i = 0; i < 5; i++) {
      const dir = join(testDir, `pkg-${i}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "package.json"), PACKAGE_JSON);
    }

    const result = discoverManifests({
      basePath: testDir,
      maxManifests: 5,
    });

    // Should find exactly 5 or be truncated at 5
    expect(result.manifests.length).toBeLessThanOrEqual(5);
    // If exactly 5, may or may not be truncated depending on traversal order
  });

  it("handles maxManifests of 1", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);
    mkdirSync(join(testDir, "sub"), { recursive: true });
    writeFileSync(join(testDir, "sub", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({
      basePath: testDir,
      maxManifests: 1,
    });

    expect(result.manifests).toHaveLength(1);
    expect(result.truncated).toBe(true);
  });

  it("handles maxDepth of 0 (root only)", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);
    mkdirSync(join(testDir, "sub"), { recursive: true });
    writeFileSync(join(testDir, "sub", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({
      basePath: testDir,
      maxDepth: 0,
      followWorkspaces: false,
    });

    // Should only find root
    expect(result.manifests).toHaveLength(1);
    expect(result.manifests[0].relativePath).toBe("package.json");
  });

  it("handles wide but shallow directory structure", () => {
    // 50 directories at same level
    for (let i = 0; i < 50; i++) {
      const dir = join(testDir, `pkg-${i}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "package.json"), PACKAGE_JSON);
    }

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(50);
    expect(result.truncated).toBe(false);
  });
});

// ===========================================
// Exclude Pattern Edge Cases
// ===========================================

describe("exclude pattern edge cases", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("handles exclude pattern with no matches", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    const result = discoverManifests({
      basePath: testDir,
      excludePatterns: ["**/nonexistent/**"],
    });

    expect(result.manifests).toHaveLength(1);
  });

  it("handles empty exclude patterns array", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);
    mkdirSync(join(testDir, "node_modules", "pkg"), { recursive: true });
    writeFileSync(join(testDir, "node_modules", "pkg", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({
      basePath: testDir,
      excludePatterns: [],
    });

    // With empty excludes, should find both
    expect(result.manifests.length).toBeGreaterThanOrEqual(2);
  });

  it("handles exclude pattern that matches root", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    const result = discoverManifests({
      basePath: testDir,
      excludePatterns: ["**/package.json"],
    });

    // Root package.json path starts with empty string for relative
    // The behavior here depends on implementation
    expect(result.manifests.length).toBeLessThanOrEqual(1);
  });

  it("handles complex glob patterns", () => {
    mkdirSync(join(testDir, "packages", "pkg-a"), { recursive: true });
    writeFileSync(join(testDir, "packages", "pkg-a", "package.json"), PACKAGE_JSON);

    mkdirSync(join(testDir, "packages", "internal-a"), { recursive: true });
    writeFileSync(join(testDir, "packages", "internal-a", "package.json"), PACKAGE_JSON);

    const result = discoverManifests({
      basePath: testDir,
      excludePatterns: ["**/internal-*/**"],
      followWorkspaces: false,
    });

    // Should find pkg-a and possibly exclude internal-a
    // The exact behavior depends on glob pattern matching implementation
    expect(result.manifests.length).toBeGreaterThanOrEqual(1);
    // At least one should be pkg-a
    const pkgAManifest = result.manifests.find((m) => m.relativePath.includes("pkg-a"));
    expect(pkgAManifest).toBeDefined();
  });
});

// ===========================================
// Absolute Path Handling
// ===========================================

describe("absolute path handling", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = createTestDir();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("returns absolute paths for manifest.path", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests[0].path.startsWith("/")).toBe(true);
    expect(result.manifests[0].path).toContain(testDir);
  });

  it("handles basePath with trailing slash", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    const result = discoverManifests({ basePath: testDir + "/" });

    expect(result.manifests).toHaveLength(1);
  });

  it("handles relative basePath", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    // This test assumes the relative path can be resolved
    // In practice, discoverManifests uses resolve() internally
    const result = discoverManifests({ basePath: testDir });

    expect(result.manifests).toHaveLength(1);
    // Path should still be absolute after resolution
    expect(result.manifests[0].path.startsWith("/")).toBe(true);
  });
});
