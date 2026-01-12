/**
 * Dependency File Parser
 *
 * Shared module for reading and parsing dependency files across different
 * ecosystems (npm, pypi) and formats (package.json, requirements.txt,
 * pyproject.toml, Pipfile).
 *
 * Used by CLI and GitHub Action for auto-detecting project dependencies.
 */

import { existsSync, readFileSync } from "node:fs";
import { join, basename } from "node:path";
import * as toml from "smol-toml";

// ===========================================
// Types
// ===========================================

export type Ecosystem = "npm" | "pypi";

export type DependencyFormat =
  | "package.json"
  | "requirements.txt"
  | "pyproject.toml"
  | "Pipfile";

export interface DependencyFile {
  ecosystem: Ecosystem;
  format: DependencyFormat;
  path: string;
}

export interface ParseResult {
  dependencies: Record<string, string>;
  ecosystem: Ecosystem;
  format: DependencyFormat;
  count: number;
}

export class DependencyParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DependencyParseError";
  }
}

// ===========================================
// Detection
// ===========================================

/**
 * Detection order for dependency files.
 * Package.json takes priority for mixed projects (e.g., JS tools in Python repos).
 */
const DETECTION_ORDER: Array<{
  filename: string;
  ecosystem: Ecosystem;
  format: DependencyFormat;
}> = [
  { filename: "package.json", ecosystem: "npm", format: "package.json" },
  { filename: "pyproject.toml", ecosystem: "pypi", format: "pyproject.toml" },
  { filename: "requirements.txt", ecosystem: "pypi", format: "requirements.txt" },
  { filename: "Pipfile", ecosystem: "pypi", format: "Pipfile" },
];

/**
 * Detect dependency file in the given directory.
 * Returns null if no known dependency file is found.
 */
export function detectDependencyFile(basePath: string): DependencyFile | null {
  for (const { filename, ecosystem, format } of DETECTION_ORDER) {
    const fullPath = join(basePath, filename);
    if (existsSync(fullPath)) {
      return { ecosystem, format, path: fullPath };
    }
  }
  return null;
}

// ===========================================
// Parsers
// ===========================================

/**
 * Parse package.json dependencies.
 */
export function parsePackageJson(
  content: string,
  includeDev: boolean
): Record<string, string> {
  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(content);
  } catch {
    throw new DependencyParseError("Invalid JSON in package.json");
  }

  const deps: Record<string, string> = {};

  if (pkg.dependencies) {
    Object.assign(deps, pkg.dependencies);
  }
  if (includeDev && pkg.devDependencies) {
    Object.assign(deps, pkg.devDependencies);
  }

  return deps;
}

/**
 * Normalize Python package name according to PEP 503.
 * Converts to lowercase and replaces underscores/periods/hyphens with hyphens.
 */
function normalizePythonPackageName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

/**
 * Parse a single line from requirements.txt.
 * Returns [packageName, version] or null if line should be skipped.
 */
function parseRequirementsLine(line: string): [string, string] | null {
  // Remove inline comments
  const commentIndex = line.indexOf("#");
  if (commentIndex !== -1) {
    line = line.substring(0, commentIndex);
  }
  line = line.trim();

  // Skip empty lines and comments
  if (!line) return null;

  // Skip special directives
  if (
    line.startsWith("-r") || // Recursive includes
    line.startsWith("-c") || // Constraints files
    line.startsWith("-e") || // Editable installs
    line.startsWith("-i") || // Index URL
    line.startsWith("--")    // Other options
  ) {
    return null;
  }

  // Skip VCS dependencies (git+, hg+, svn+, bzr+)
  if (/^(git|hg|svn|bzr)\+/.test(line)) {
    return null;
  }

  // Skip local paths
  if (line.startsWith(".") || line.startsWith("/") || line.startsWith("~")) {
    return null;
  }

  // Parse package name and version specifier
  // Handle: package, package==1.0, package>=1.0,<2.0, package[extra]>=1.0
  // Also handle environment markers: package>=1.0; python_version >= "3.8"
  const markerIndex = line.indexOf(";");
  if (markerIndex !== -1) {
    line = line.substring(0, markerIndex).trim();
  }

  // Match package name (with optional extras) and version specifiers
  const match = line.match(/^([a-zA-Z0-9][-a-zA-Z0-9._]*)(\[[^\]]+\])?\s*(.*)?$/);
  if (!match) return null;

  const [, packageName, , versionSpec] = match;
  const normalizedName = normalizePythonPackageName(packageName);
  const version = versionSpec?.trim() || "*";

  return [normalizedName, version];
}

/**
 * Parse requirements.txt file.
 */
export function parseRequirementsTxt(content: string): Record<string, string> {
  const deps: Record<string, string> = {};

  for (const line of content.split("\n")) {
    const result = parseRequirementsLine(line);
    if (result) {
      const [name, version] = result;
      deps[name] = version;
    }
  }

  return deps;
}

/**
 * Parse pyproject.toml dependencies (PEP 621 and Poetry formats).
 */
export function parsePyprojectToml(
  content: string,
  includeDev: boolean
): Record<string, string> {
  let parsed: Record<string, unknown>;
  try {
    parsed = toml.parse(content);
  } catch {
    throw new DependencyParseError("Invalid TOML in pyproject.toml");
  }

  const deps: Record<string, string> = {};

  // PEP 621 format: [project.dependencies]
  const project = parsed.project as { dependencies?: string[]; "optional-dependencies"?: Record<string, string[]> } | undefined;
  if (project?.dependencies && Array.isArray(project.dependencies)) {
    for (const dep of project.dependencies) {
      const result = parseRequirementsLine(dep);
      if (result) {
        deps[result[0]] = result[1];
      }
    }
  }

  // PEP 621 optional dependencies (dev group)
  if (includeDev && project?.["optional-dependencies"]) {
    const optDeps = project["optional-dependencies"];
    // Look for common dev dependency group names
    const devGroups = ["dev", "development", "test", "testing"];
    for (const group of devGroups) {
      const groupDeps = optDeps[group];
      if (Array.isArray(groupDeps)) {
        for (const dep of groupDeps) {
          const result = parseRequirementsLine(dep);
          if (result) {
            deps[result[0]] = result[1];
          }
        }
      }
    }
  }

  // Poetry format: [tool.poetry.dependencies]
  const tool = parsed.tool as { poetry?: { dependencies?: Record<string, unknown>; group?: Record<string, { dependencies?: Record<string, unknown> }> } } | undefined;
  const poetry = tool?.poetry;

  if (poetry?.dependencies) {
    for (const [name, value] of Object.entries(poetry.dependencies)) {
      // Skip python version specification
      if (name.toLowerCase() === "python") continue;

      const normalizedName = normalizePythonPackageName(name);

      if (typeof value === "string") {
        deps[normalizedName] = value;
      } else if (typeof value === "object" && value !== null) {
        // Handle complex specs like { version = "^1.0", optional = true }
        const spec = value as { version?: string };
        deps[normalizedName] = spec.version || "*";
      }
    }
  }

  // Poetry dev dependencies: [tool.poetry.group.dev.dependencies]
  if (includeDev && poetry?.group) {
    const devGroups = ["dev", "test"];
    for (const groupName of devGroups) {
      const group = poetry.group[groupName];
      if (group?.dependencies) {
        for (const [name, value] of Object.entries(group.dependencies)) {
          const normalizedName = normalizePythonPackageName(name);
          if (typeof value === "string") {
            deps[normalizedName] = value;
          } else if (typeof value === "object" && value !== null) {
            const spec = value as { version?: string };
            deps[normalizedName] = spec.version || "*";
          }
        }
      }
    }
  }

  return deps;
}

/**
 * Parse Pipfile dependencies.
 */
export function parsePipfile(
  content: string,
  includeDev: boolean
): Record<string, string> {
  let parsed: Record<string, unknown>;
  try {
    parsed = toml.parse(content);
  } catch {
    throw new DependencyParseError("Invalid TOML in Pipfile");
  }

  const deps: Record<string, string> = {};

  // [packages] section
  const packages = parsed.packages as Record<string, unknown> | undefined;
  if (packages) {
    for (const [name, value] of Object.entries(packages)) {
      const normalizedName = normalizePythonPackageName(name);
      if (typeof value === "string") {
        deps[normalizedName] = value === "*" ? "*" : value;
      } else if (typeof value === "object" && value !== null) {
        const spec = value as { version?: string };
        deps[normalizedName] = spec.version || "*";
      }
    }
  }

  // [dev-packages] section
  if (includeDev) {
    const devPackages = parsed["dev-packages"] as Record<string, unknown> | undefined;
    if (devPackages) {
      for (const [name, value] of Object.entries(devPackages)) {
        const normalizedName = normalizePythonPackageName(name);
        if (typeof value === "string") {
          deps[normalizedName] = value === "*" ? "*" : value;
        } else if (typeof value === "object" && value !== null) {
          const spec = value as { version?: string };
          deps[normalizedName] = spec.version || "*";
        }
      }
    }
  }

  return deps;
}

// ===========================================
// Main Entry Point
// ===========================================

/**
 * Read and parse dependencies from a directory.
 * Auto-detects the dependency file format.
 *
 * @param basePath - Directory to search for dependency files
 * @param includeDev - Whether to include dev dependencies (default: true)
 * @returns Parsed dependencies with metadata
 * @throws DependencyParseError if no dependency file found or parsing fails
 */
export function readDependencies(
  basePath: string,
  includeDev = true
): ParseResult {
  const detected = detectDependencyFile(basePath);

  if (!detected) {
    throw new DependencyParseError(
      `No dependency file found in ${basePath}. ` +
        "Looking for: package.json, pyproject.toml, requirements.txt, or Pipfile"
    );
  }

  const content = readFileSync(detected.path, "utf-8");
  let dependencies: Record<string, string>;

  switch (detected.format) {
    case "package.json":
      dependencies = parsePackageJson(content, includeDev);
      break;
    case "requirements.txt":
      dependencies = parseRequirementsTxt(content);
      break;
    case "pyproject.toml":
      dependencies = parsePyprojectToml(content, includeDev);
      break;
    case "Pipfile":
      dependencies = parsePipfile(content, includeDev);
      break;
  }

  return {
    dependencies,
    ecosystem: detected.ecosystem,
    format: detected.format,
    count: Object.keys(dependencies).length,
  };
}

/**
 * Read and parse dependencies from a specific file.
 * File format is auto-detected from the filename.
 *
 * @param filePath - Path to the dependency file
 * @param includeDev - Whether to include dev dependencies (default: true)
 * @returns Parsed dependencies with metadata
 * @throws DependencyParseError if file not found, unknown format, or parsing fails
 */
export function readDependenciesFromFile(
  filePath: string,
  includeDev = true
): ParseResult {
  if (!existsSync(filePath)) {
    throw new DependencyParseError(`File not found: ${filePath}`);
  }

  const filename = basename(filePath);
  const content = readFileSync(filePath, "utf-8");

  let ecosystem: Ecosystem;
  let format: DependencyFormat;
  let dependencies: Record<string, string>;

  switch (filename) {
    case "package.json":
      ecosystem = "npm";
      format = "package.json";
      dependencies = parsePackageJson(content, includeDev);
      break;
    case "requirements.txt":
      ecosystem = "pypi";
      format = "requirements.txt";
      dependencies = parseRequirementsTxt(content);
      break;
    case "pyproject.toml":
      ecosystem = "pypi";
      format = "pyproject.toml";
      dependencies = parsePyprojectToml(content, includeDev);
      break;
    case "Pipfile":
      ecosystem = "pypi";
      format = "Pipfile";
      dependencies = parsePipfile(content, includeDev);
      break;
    default:
      throw new DependencyParseError(
        `Unknown dependency file format: ${filename}. ` +
          "Supported: package.json, requirements.txt, pyproject.toml, Pipfile"
      );
  }

  return {
    dependencies,
    ecosystem,
    format,
    count: Object.keys(dependencies).length,
  };
}
