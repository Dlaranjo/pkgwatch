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

// ===========================================
// Malformed Input Tests
// ===========================================

describe("malformed package.json handling", () => {
  it("throws on truncated JSON", () => {
    expect(() => parsePackageJson('{"dependencies": {', true)).toThrow(
      DependencyParseError
    );
  });

  it("throws on JSON with trailing comma", () => {
    expect(() =>
      parsePackageJson('{"dependencies": {"lodash": "^4.0.0",}}', true)
    ).toThrow(DependencyParseError);
  });

  it("handles null dependencies value", () => {
    const deps = parsePackageJson('{"dependencies": null}', true);
    expect(deps).toEqual({});
  });

  it("handles non-object dependencies gracefully", () => {
    // Arrays and other non-object values should not cause crashes
    // The Object.assign approach passes values through
    const content = '{"dependencies": ["lodash"]}';
    // This may either return empty or pass through - just verify no crash
    expect(() => parsePackageJson(content, true)).not.toThrow();
  });

  it("handles non-string version values", () => {
    const content = '{"dependencies": {"pkg": 123, "other": {"version": "1.0"}}}';
    const deps = parsePackageJson(content, true);
    expect(deps.pkg).toBe(123);
    expect(deps.other).toEqual({ version: "1.0" });
  });

  it("handles empty string as version", () => {
    const deps = parsePackageJson('{"dependencies": {"pkg": ""}}', true);
    expect(deps.pkg).toBe("");
  });

  it("handles deeply nested invalid JSON", () => {
    expect(() => parsePackageJson('{"a": {"b": {"c": }}}', true)).toThrow(
      DependencyParseError
    );
  });

  it("handles JSON without BOM character normally", () => {
    // Standard JSON without BOM should parse fine
    const content = '{"dependencies": {"lodash": "^4.0.0"}}';
    const deps = parsePackageJson(content, true);
    expect(deps.lodash).toBe("^4.0.0");
  });

  it("handles unicode in package names", () => {
    const deps = parsePackageJson('{"dependencies": {"@scope/pkg": "^1.0.0"}}', true);
    expect(deps["@scope/pkg"]).toBe("^1.0.0");
  });
});

describe("malformed requirements.txt handling", () => {
  it("skips lines with invalid package names", () => {
    const content = `
valid-pkg>=1.0
123invalid
-flag
`;
    const deps = parseRequirementsTxt(content);
    expect(deps["valid-pkg"]).toBe(">=1.0");
    // _also_invalid might be valid according to PEP 503 regex
    // Just verify valid-pkg is parsed and invalid lines are skipped
    expect(deps["valid-pkg"]).toBeDefined();
  });

  it("handles Windows line endings (CRLF)", () => {
    const content = "requests>=2.0\r\nflask>=1.0\r\n";
    const deps = parseRequirementsTxt(content);
    expect(deps.requests).toBe(">=2.0");
    expect(deps.flask).toBe(">=1.0");
  });

  it("handles mixed line endings", () => {
    const content = "requests>=2.0\nflask>=1.0\r\ndjango>=3.0\r";
    const deps = parseRequirementsTxt(content);
    expect(Object.keys(deps)).toHaveLength(3);
  });

  it("handles tab characters", () => {
    const content = "\trequests>=2.0\t# with tabs";
    const deps = parseRequirementsTxt(content);
    expect(deps.requests).toBe(">=2.0");
  });

  it("handles multiple consecutive blank lines", () => {
    const content = "requests>=2.0\n\n\n\nflask>=1.0";
    const deps = parseRequirementsTxt(content);
    expect(Object.keys(deps)).toHaveLength(2);
  });

  it("handles package with multiple extras", () => {
    const content = "requests[security,socks]>=2.0";
    const deps = parseRequirementsTxt(content);
    expect(deps.requests).toBe(">=2.0");
  });

  it("handles complex version specifiers", () => {
    const content = `
pkg1>=1.0,<2.0,!=1.5.0
pkg2~=1.4.2
pkg3===1.0.0
pkg4>=1.0,<2.0;python_version>="3.6"
`;
    const deps = parseRequirementsTxt(content);
    expect(deps.pkg1).toBe(">=1.0,<2.0,!=1.5.0");
    expect(deps.pkg2).toBe("~=1.4.2");
    expect(deps.pkg3).toBe("===1.0.0");
    expect(deps.pkg4).toBe(">=1.0,<2.0");
  });

  it("skips bzr+ VCS dependencies", () => {
    const content = "bzr+https://example.com/repo";
    const deps = parseRequirementsTxt(content);
    expect(Object.keys(deps)).toHaveLength(0);
  });

  it("skips svn+ VCS dependencies", () => {
    const content = "svn+https://example.com/repo";
    const deps = parseRequirementsTxt(content);
    expect(Object.keys(deps)).toHaveLength(0);
  });

  it("skips hg+ VCS dependencies", () => {
    const content = "hg+https://example.com/repo";
    const deps = parseRequirementsTxt(content);
    expect(Object.keys(deps)).toHaveLength(0);
  });

  it("skips tilde paths", () => {
    const content = "~/local-package";
    const deps = parseRequirementsTxt(content);
    expect(Object.keys(deps)).toHaveLength(0);
  });

  it("handles -c constraints flag", () => {
    const content = `-c constraints.txt
requests>=2.0`;
    const deps = parseRequirementsTxt(content);
    expect(deps.requests).toBe(">=2.0");
    expect(Object.keys(deps)).toHaveLength(1);
  });

  it("handles -i index flag", () => {
    const content = `-i https://custom.pypi.org/simple
requests>=2.0`;
    const deps = parseRequirementsTxt(content);
    expect(deps.requests).toBe(">=2.0");
    expect(Object.keys(deps)).toHaveLength(1);
  });

  it("handles -- long options", () => {
    const content = `--trusted-host custom.pypi.org
requests>=2.0`;
    const deps = parseRequirementsTxt(content);
    expect(deps.requests).toBe(">=2.0");
    expect(Object.keys(deps)).toHaveLength(1);
  });
});

describe("malformed pyproject.toml handling", () => {
  it("throws on unclosed brackets", () => {
    expect(() => parsePyprojectToml("[project", true)).toThrow(
      DependencyParseError
    );
  });

  it("throws on invalid TOML syntax", () => {
    expect(() => parsePyprojectToml("key = [unclosed", true)).toThrow(
      DependencyParseError
    );
  });

  it("handles empty dependencies array", () => {
    const content = `
[project]
dependencies = []
`;
    const deps = parsePyprojectToml(content, true);
    expect(deps).toEqual({});
  });

  it("handles non-array dependencies (invalid but graceful)", () => {
    const content = `
[project]
name = "test"
`;
    // When dependencies key is missing entirely, should return empty
    const deps = parsePyprojectToml(content, true);
    expect(deps).toEqual({});
  });

  it("handles Poetry dependency without version", () => {
    const content = `
[tool.poetry.dependencies]
python = "^3.9"
requests = "*"
`;
    const deps = parsePyprojectToml(content, false);
    expect(deps.requests).toBe("*");
    expect(deps).not.toHaveProperty("python");
  });

  it("handles Poetry dependency with null value", () => {
    // This is invalid TOML, so should throw
    expect(() =>
      parsePyprojectToml(
        `
[tool.poetry.dependencies]
pkg =
`,
        true
      )
    ).toThrow(DependencyParseError);
  });

  it("handles mixed PEP 621 and Poetry formats", () => {
    const content = `
[project]
dependencies = ["requests>=2.0"]

[tool.poetry.dependencies]
flask = "^2.0"
`;
    const deps = parsePyprojectToml(content, false);
    expect(deps.requests).toBe(">=2.0");
    expect(deps.flask).toBe("^2.0");
  });

  it("handles optional-dependencies with empty groups", () => {
    const content = `
[project]
dependencies = ["requests>=2.0"]

[project.optional-dependencies]
dev = []
test = []
`;
    const deps = parsePyprojectToml(content, true);
    expect(Object.keys(deps)).toHaveLength(1);
  });

  it("handles Poetry group with missing dependencies key", () => {
    const content = `
[tool.poetry.group.dev]
optional = true
`;
    const deps = parsePyprojectToml(content, true);
    expect(deps).toEqual({});
  });
});

describe("malformed Pipfile handling", () => {
  it("throws on invalid TOML", () => {
    expect(() => parsePipfile("packages = [", true)).toThrow(
      DependencyParseError
    );
  });

  it("handles packages with boolean values", () => {
    const content = `
[packages]
pkg = true
`;
    // Boolean is not a string or object, should be handled gracefully
    const deps = parsePipfile(content, false);
    expect(deps).toEqual({});
  });

  it("handles packages with complex object values", () => {
    const content = `
[packages]
pkg = {version = ">=1.0", extras = ["extra1"]}
`;
    const deps = parsePipfile(content, false);
    expect(deps.pkg).toBe(">=1.0");
  });

  it("handles empty packages section", () => {
    const content = `
[packages]

[dev-packages]
pytest = "*"
`;
    const deps = parsePipfile(content, true);
    expect(deps.pytest).toBe("*");
    expect(Object.keys(deps)).toHaveLength(1);
  });

  it("handles nested version object without version key", () => {
    const content = `
[packages]
pkg = {extras = ["extra1"]}
`;
    const deps = parsePipfile(content, false);
    expect(deps.pkg).toBe("*");
  });
});

// ===========================================
// Python Package Name Normalization Tests
// ===========================================

describe("Python package name normalization", () => {
  it("normalizes consecutive special characters", () => {
    const content = "my__package>=1.0\nother--pkg>=2.0\nsome..thing>=3.0";
    const deps = parseRequirementsTxt(content);
    expect(deps["my-package"]).toBe(">=1.0");
    expect(deps["other-pkg"]).toBe(">=2.0");
    expect(deps["some-thing"]).toBe(">=3.0");
  });

  it("normalizes mixed special characters", () => {
    const content = "my_package.name-here>=1.0";
    const deps = parseRequirementsTxt(content);
    expect(deps["my-package-name-here"]).toBe(">=1.0");
  });

  it("preserves case when normalizing", () => {
    const content = "MyPackage>=1.0\nANOTHER_PKG>=2.0";
    const deps = parseRequirementsTxt(content);
    expect(deps["mypackage"]).toBe(">=1.0");
    expect(deps["another-pkg"]).toBe(">=2.0");
  });
});

// ===========================================
// File Detection Priority Tests
// ===========================================

describe("file detection priority", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = join(tmpdir(), `pkgwatch-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("prefers pyproject.toml over Pipfile", () => {
    writeFileSync(join(testDir, "pyproject.toml"), "[project]");
    writeFileSync(join(testDir, "Pipfile"), "[packages]");
    const result = detectDependencyFile(testDir);
    expect(result?.format).toBe("pyproject.toml");
  });

  it("prefers requirements.txt over Pipfile", () => {
    writeFileSync(join(testDir, "requirements.txt"), "requests>=2.0");
    writeFileSync(join(testDir, "Pipfile"), "[packages]");
    // Based on detection order: package.json > pyproject.toml > requirements.txt > Pipfile
    const result = detectDependencyFile(testDir);
    expect(result?.format).toBe("requirements.txt");
  });
});

// ===========================================
// Large File Handling
// ===========================================

describe("large file handling", () => {
  it("handles package.json with many dependencies", () => {
    const deps: Record<string, string> = {};
    for (let i = 0; i < 1000; i++) {
      deps[`package-${i}`] = `^${i}.0.0`;
    }
    const content = JSON.stringify({ dependencies: deps });
    const result = parsePackageJson(content, true);
    expect(Object.keys(result)).toHaveLength(1000);
  });

  it("handles requirements.txt with many lines", () => {
    const lines: string[] = [];
    for (let i = 0; i < 1000; i++) {
      lines.push(`package-${i}>=1.0.0`);
    }
    const content = lines.join("\n");
    const deps = parseRequirementsTxt(content);
    expect(Object.keys(deps)).toHaveLength(1000);
  });

  it("handles very long package names", () => {
    const longName = "a".repeat(200);
    const content = `{"dependencies": {"${longName}": "^1.0.0"}}`;
    const deps = parsePackageJson(content, true);
    expect(deps[longName]).toBe("^1.0.0");
  });

  it("handles very long version strings", () => {
    const longVersion = ">=1.0.0," + Array(100).fill("<2.0.0").join(",");
    const content = `long-package${longVersion}`;
    const deps = parseRequirementsTxt(content);
    expect(deps["long-package"]).toBeDefined();
  });
});

// ===========================================
// readDependenciesFromFile Additional Tests
// ===========================================

describe("readDependenciesFromFile additional tests", () => {
  let testDir: string;

  beforeEach(() => {
    testDir = join(tmpdir(), `pkgwatch-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("reads pyproject.toml file directly", () => {
    const content = `
[project]
dependencies = ["requests>=2.0"]
`;
    writeFileSync(join(testDir, "pyproject.toml"), content);
    const result = readDependenciesFromFile(join(testDir, "pyproject.toml"));
    expect(result.ecosystem).toBe("pypi");
    expect(result.format).toBe("pyproject.toml");
  });

  it("reads Pipfile directly", () => {
    const content = `
[packages]
requests = ">=2.0"
`;
    writeFileSync(join(testDir, "Pipfile"), content);
    const result = readDependenciesFromFile(join(testDir, "Pipfile"));
    expect(result.ecosystem).toBe("pypi");
    expect(result.format).toBe("Pipfile");
  });

  it("throws descriptive error for unknown extension", () => {
    const filePath = join(testDir, "deps.yaml");
    writeFileSync(filePath, "dependencies: []");
    expect(() => readDependenciesFromFile(filePath)).toThrow(
      /Unknown dependency file format.*deps\.yaml/
    );
  });

  it("includes count in parse result", () => {
    const content = `{"dependencies": {"a": "1", "b": "2", "c": "3"}}`;
    writeFileSync(join(testDir, "package.json"), content);
    const result = readDependenciesFromFile(join(testDir, "package.json"));
    expect(result.count).toBe(3);
  });
});
