import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  parsePackageJson,
  parseRequirementsTxt,
  parsePyprojectToml,
  parsePipfile,
  detectDependencyFile,
  readDependencies,
  readDependenciesFromFile,
  DependencyParseError,
} from "../dependencies.js";

// ===========================================
// Test Fixtures
// ===========================================

const PACKAGE_JSON = `{
  "name": "test-project",
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.18.0"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "typescript": "^5.0.0"
  }
}`;

const REQUIREMENTS_TXT = `
# Production dependencies
requests>=2.28.0
flask==2.3.0
django>=4.0,<5.0

# Comments and special cases
numpy  # inline comment
pandas>=2.0.0 ; python_version >= "3.9"

# Skip these
-r base.txt
-e ./local-pkg
git+https://github.com/user/repo.git
./local-path
--extra-index-url https://pypi.example.com
`;

const PYPROJECT_TOML_PEP621 = `
[project]
name = "test-project"
dependencies = [
  "requests>=2.28.0",
  "flask==2.3.0"
]

[project.optional-dependencies]
dev = ["pytest>=7.0", "black>=23.0"]
test = ["coverage>=7.0"]
`;

const PYPROJECT_TOML_POETRY = `
[tool.poetry]
name = "test-project"

[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28.0"
flask = {version = "^2.3.0", optional = true}

[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
black = {version = "^23.0", extras = ["jupyter"]}

[tool.poetry.group.test.dependencies]
coverage = "^7.0"
`;

const PIPFILE = `
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
requests = ">=2.28.0"
flask = "*"
django = {version = ">=4.0"}

[dev-packages]
pytest = "*"
black = ">=23.0"
`;

// ===========================================
// Unit Tests: Individual Parsers
// ===========================================

describe("parsePackageJson", () => {
  it("parses production dependencies", () => {
    const deps = parsePackageJson(PACKAGE_JSON, false);
    expect(deps).toEqual({
      lodash: "^4.17.21",
      express: "^4.18.0",
    });
  });

  it("includes devDependencies when includeDev is true", () => {
    const deps = parsePackageJson(PACKAGE_JSON, true);
    expect(deps).toEqual({
      lodash: "^4.17.21",
      express: "^4.18.0",
      jest: "^29.0.0",
      typescript: "^5.0.0",
    });
  });

  it("handles empty package.json", () => {
    const deps = parsePackageJson("{}", true);
    expect(deps).toEqual({});
  });

  it("throws on invalid JSON", () => {
    expect(() => parsePackageJson("not json", true)).toThrow(DependencyParseError);
  });
});

describe("parseRequirementsTxt", () => {
  it("parses standard requirements", () => {
    const deps = parseRequirementsTxt(REQUIREMENTS_TXT);

    expect(deps.requests).toBe(">=2.28.0");
    expect(deps.flask).toBe("==2.3.0");
    expect(deps.django).toBe(">=4.0,<5.0");
  });

  it("handles inline comments", () => {
    const deps = parseRequirementsTxt(REQUIREMENTS_TXT);
    expect(deps.numpy).toBe("*");
  });

  it("strips environment markers", () => {
    const deps = parseRequirementsTxt(REQUIREMENTS_TXT);
    expect(deps.pandas).toBe(">=2.0.0");
  });

  it("skips recursive includes and special directives", () => {
    const deps = parseRequirementsTxt(REQUIREMENTS_TXT);
    expect(Object.keys(deps)).not.toContain("-r");
    expect(Object.keys(deps)).not.toContain("-e");
    expect(Object.keys(deps)).not.toContain("git+https");
  });

  it("normalizes package names (PEP 503)", () => {
    const content = `
Scikit-Learn>=1.0
My_Package>=2.0
Some.Package>=3.0
`;
    const deps = parseRequirementsTxt(content);
    expect(deps["scikit-learn"]).toBe(">=1.0");
    expect(deps["my-package"]).toBe(">=2.0");
    expect(deps["some-package"]).toBe(">=3.0");
  });

  it("handles extras in brackets", () => {
    const content = "requests[security]>=2.28.0";
    const deps = parseRequirementsTxt(content);
    expect(deps.requests).toBe(">=2.28.0");
  });
});

describe("parsePyprojectToml (PEP 621)", () => {
  it("parses project.dependencies", () => {
    const deps = parsePyprojectToml(PYPROJECT_TOML_PEP621, false);
    expect(deps.requests).toBe(">=2.28.0");
    expect(deps.flask).toBe("==2.3.0");
  });

  it("includes optional-dependencies when includeDev is true", () => {
    const deps = parsePyprojectToml(PYPROJECT_TOML_PEP621, true);
    expect(deps.pytest).toBe(">=7.0");
    expect(deps.black).toBe(">=23.0");
    expect(deps.coverage).toBe(">=7.0");
  });

  it("throws on invalid TOML", () => {
    expect(() => parsePyprojectToml("invalid = [", true)).toThrow(DependencyParseError);
  });
});

describe("parsePyprojectToml (Poetry)", () => {
  it("parses tool.poetry.dependencies", () => {
    const deps = parsePyprojectToml(PYPROJECT_TOML_POETRY, false);
    expect(deps.requests).toBe("^2.28.0");
    expect(deps.flask).toBe("^2.3.0");
  });

  it("skips python version spec", () => {
    const deps = parsePyprojectToml(PYPROJECT_TOML_POETRY, false);
    expect(deps).not.toHaveProperty("python");
  });

  it("includes poetry group dependencies when includeDev is true", () => {
    const deps = parsePyprojectToml(PYPROJECT_TOML_POETRY, true);
    expect(deps.pytest).toBe("^7.0");
    expect(deps.black).toBe("^23.0");
    expect(deps.coverage).toBe("^7.0");
  });
});

describe("parsePipfile", () => {
  it("parses packages section", () => {
    const deps = parsePipfile(PIPFILE, false);
    expect(deps.requests).toBe(">=2.28.0");
    expect(deps.flask).toBe("*");
    expect(deps.django).toBe(">=4.0");
  });

  it("includes dev-packages when includeDev is true", () => {
    const deps = parsePipfile(PIPFILE, true);
    expect(deps.pytest).toBe("*");
    expect(deps.black).toBe(">=23.0");
  });

  it("throws on invalid TOML", () => {
    expect(() => parsePipfile("invalid = [", true)).toThrow(DependencyParseError);
  });
});

// ===========================================
// Integration Tests: File Detection & Reading
// ===========================================

describe("detectDependencyFile", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = join(tmpdir(), `pkgwatch-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("detects package.json", () => {
    writeFileSync(join(testDir, "package.json"), "{}");
    const result = detectDependencyFile(testDir);
    expect(result?.format).toBe("package.json");
    expect(result?.ecosystem).toBe("npm");
  });

  it("detects requirements.txt", () => {
    writeFileSync(join(testDir, "requirements.txt"), "requests>=2.0");
    const result = detectDependencyFile(testDir);
    expect(result?.format).toBe("requirements.txt");
    expect(result?.ecosystem).toBe("pypi");
  });

  it("detects pyproject.toml", () => {
    writeFileSync(join(testDir, "pyproject.toml"), "[project]");
    const result = detectDependencyFile(testDir);
    expect(result?.format).toBe("pyproject.toml");
    expect(result?.ecosystem).toBe("pypi");
  });

  it("detects Pipfile", () => {
    writeFileSync(join(testDir, "Pipfile"), "[packages]");
    const result = detectDependencyFile(testDir);
    expect(result?.format).toBe("Pipfile");
    expect(result?.ecosystem).toBe("pypi");
  });

  it("prefers package.json over Python files", () => {
    writeFileSync(join(testDir, "package.json"), "{}");
    writeFileSync(join(testDir, "requirements.txt"), "requests>=2.0");
    const result = detectDependencyFile(testDir);
    expect(result?.format).toBe("package.json");
  });

  it("prefers pyproject.toml over requirements.txt", () => {
    writeFileSync(join(testDir, "pyproject.toml"), "[project]");
    writeFileSync(join(testDir, "requirements.txt"), "requests>=2.0");
    const result = detectDependencyFile(testDir);
    expect(result?.format).toBe("pyproject.toml");
  });

  it("returns null when no dependency file found", () => {
    const result = detectDependencyFile(testDir);
    expect(result).toBeNull();
  });
});

describe("readDependencies", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = join(tmpdir(), `pkgwatch-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("reads npm project", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);
    const result = readDependencies(testDir);

    expect(result.ecosystem).toBe("npm");
    expect(result.format).toBe("package.json");
    expect(result.count).toBe(4);
    expect(result.dependencies.lodash).toBe("^4.17.21");
  });

  it("reads Python requirements.txt project", () => {
    writeFileSync(join(testDir, "requirements.txt"), REQUIREMENTS_TXT);
    const result = readDependencies(testDir);

    expect(result.ecosystem).toBe("pypi");
    expect(result.format).toBe("requirements.txt");
    expect(result.dependencies.requests).toBe(">=2.28.0");
  });

  it("reads pyproject.toml project", () => {
    writeFileSync(join(testDir, "pyproject.toml"), PYPROJECT_TOML_PEP621);
    const result = readDependencies(testDir);

    expect(result.ecosystem).toBe("pypi");
    expect(result.format).toBe("pyproject.toml");
    expect(result.dependencies.requests).toBe(">=2.28.0");
  });

  it("reads Pipfile project", () => {
    writeFileSync(join(testDir, "Pipfile"), PIPFILE);
    const result = readDependencies(testDir);

    expect(result.ecosystem).toBe("pypi");
    expect(result.format).toBe("Pipfile");
    expect(result.dependencies.requests).toBe(">=2.28.0");
  });

  it("throws when no dependency file found", () => {
    expect(() => readDependencies(testDir)).toThrow(DependencyParseError);
  });

  it("respects includeDev parameter", () => {
    writeFileSync(join(testDir, "package.json"), PACKAGE_JSON);

    const withDev = readDependencies(testDir, true);
    expect(withDev.count).toBe(4);

    const withoutDev = readDependencies(testDir, false);
    expect(withoutDev.count).toBe(2);
  });
});

describe("readDependenciesFromFile", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = join(tmpdir(), `pkgwatch-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("reads specific file path", () => {
    const filePath = join(testDir, "package.json");
    writeFileSync(filePath, PACKAGE_JSON);
    const result = readDependenciesFromFile(filePath);

    expect(result.ecosystem).toBe("npm");
    expect(result.format).toBe("package.json");
  });

  it("throws on unknown file format", () => {
    const filePath = join(testDir, "unknown.yaml");
    writeFileSync(filePath, "foo: bar");
    expect(() => readDependenciesFromFile(filePath)).toThrow(DependencyParseError);
  });

  it("throws on missing file", () => {
    expect(() => readDependenciesFromFile("/nonexistent/file.json")).toThrow(DependencyParseError);
  });
});

// ===========================================
// Edge Cases
// ===========================================

describe("edge cases", () => {
  it("handles empty requirements.txt", () => {
    const deps = parseRequirementsTxt("");
    expect(deps).toEqual({});
  });

  it("handles requirements.txt with only comments", () => {
    const deps = parseRequirementsTxt("# just comments\n# more comments");
    expect(deps).toEqual({});
  });

  it("handles pyproject.toml with no dependencies section", () => {
    const content = `
[project]
name = "test"
version = "1.0.0"
`;
    const deps = parsePyprojectToml(content, true);
    expect(deps).toEqual({});
  });

  it("handles Pipfile with only source section", () => {
    const content = `
[[source]]
url = "https://pypi.org/simple"
`;
    const deps = parsePipfile(content, true);
    expect(deps).toEqual({});
  });

  it("handles package.json with no dependencies", () => {
    const content = `{"name": "test"}`;
    const deps = parsePackageJson(content, true);
    expect(deps).toEqual({});
  });
});
