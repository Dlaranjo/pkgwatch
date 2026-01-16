/**
 * Manifest Discovery Module
 *
 * Recursively discovers dependency manifest files in a repository.
 * Supports npm/yarn/pnpm workspaces and glob-based exclude patterns.
 */

import { existsSync, readdirSync, readFileSync, statSync, lstatSync, realpathSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import picomatch from "picomatch";
import type { Ecosystem, DependencyFormat } from "./dependencies.js";

// ===========================================
// Types
// ===========================================

export interface DiscoveryOptions {
  /** Base path to start discovery from */
  basePath: string;
  /** Glob patterns to exclude from discovery */
  excludePatterns?: string[];
  /** Maximum directory depth to traverse (default: 10) */
  maxDepth?: number;
  /** Maximum manifest files to discover (default: 100) */
  maxManifests?: number;
  /** Follow npm/yarn/pnpm workspace definitions (default: true) */
  followWorkspaces?: boolean;
}

export interface DiscoveredManifest {
  /** Absolute path to the manifest file */
  path: string;
  /** Path relative to basePath */
  relativePath: string;
  /** Package ecosystem (npm or pypi) */
  ecosystem: Ecosystem;
  /** Manifest file format */
  format: DependencyFormat;
  /** True if discovered via workspace configuration */
  isWorkspace?: boolean;
}

export interface DiscoveryResult {
  /** Discovered manifest files */
  manifests: DiscoveredManifest[];
  /** True if maxManifests limit was reached */
  truncated: boolean;
  /** Warning messages (e.g., skipped directories) */
  warnings: string[];
}

// ===========================================
// Constants
// ===========================================

/** Default patterns to exclude from discovery */
export const DEFAULT_EXCLUDES = [
  "**/node_modules/**",
  "**/.git/**",
  "**/vendor/**",
  "**/.venv/**",
  "**/venv/**",
  "**/dist/**",
  "**/build/**",
  "**/fixtures/**",
  "**/__mocks__/**",
  "**/.next/**",
  "**/.nuxt/**",
  "**/coverage/**",
  "**/.cache/**",
  "**/.turbo/**",
  "**/.nx/**",
];

/** Manifest files we're looking for */
const MANIFEST_FILES: Array<{
  filename: string;
  ecosystem: Ecosystem;
  format: DependencyFormat;
}> = [
  { filename: "package.json", ecosystem: "npm", format: "package.json" },
  { filename: "pyproject.toml", ecosystem: "pypi", format: "pyproject.toml" },
  { filename: "requirements.txt", ecosystem: "pypi", format: "requirements.txt" },
  { filename: "Pipfile", ecosystem: "pypi", format: "Pipfile" },
];

const MANIFEST_FILENAMES = new Set(MANIFEST_FILES.map((m) => m.filename));

// ===========================================
// Workspace Detection
// ===========================================

interface WorkspaceConfig {
  patterns: string[];
  source: "npm" | "pnpm";
}

/**
 * Detect workspace configuration from package.json or pnpm-workspace.yaml
 */
function detectWorkspaces(basePath: string, warnings: string[]): WorkspaceConfig | null {
  // Check package.json for npm/yarn workspaces
  const packageJsonPath = join(basePath, "package.json");
  if (existsSync(packageJsonPath)) {
    try {
      const content = readFileSync(packageJsonPath, "utf-8");
      const pkg = JSON.parse(content) as { workspaces?: string[] | { packages?: string[] } };

      if (pkg.workspaces) {
        // Handle both array format and object format ({ packages: [...] })
        const patterns = Array.isArray(pkg.workspaces)
          ? pkg.workspaces
          : pkg.workspaces.packages;

        if (patterns && patterns.length > 0) {
          return { patterns, source: "npm" };
        }
      }
    } catch (err) {
      warnings.push(`Failed to parse package.json for workspaces: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // Check pnpm-workspace.yaml
  const pnpmWorkspacePath = join(basePath, "pnpm-workspace.yaml");
  if (existsSync(pnpmWorkspacePath)) {
    try {
      const content = readFileSync(pnpmWorkspacePath, "utf-8");
      // Simple YAML parsing for packages array
      // Format: packages:\n  - "packages/*"\n  - "apps/*"
      const patterns: string[] = [];
      const lines = content.split("\n");
      let inPackages = false;

      for (const line of lines) {
        if (line.trim() === "packages:") {
          inPackages = true;
          continue;
        }
        if (inPackages) {
          const match = line.match(/^\s+-\s*["']?([^"'\n]+)["']?\s*$/);
          if (match) {
            patterns.push(match[1]);
          } else if (!line.match(/^\s*$/) && !line.match(/^\s+-/)) {
            // Non-empty, non-list line means we've left the packages section
            break;
          }
        }
      }

      if (patterns.length > 0) {
        return { patterns, source: "pnpm" };
      }
    } catch (err) {
      warnings.push(`Failed to parse pnpm-workspace.yaml: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return null;
}

/**
 * Resolve workspace patterns to actual directories
 */
function resolveWorkspacePatterns(basePath: string, patterns: string[], warnings: string[]): string[] {
  const directories: string[] = [];

  for (const pattern of patterns) {
    // Handle glob patterns like "packages/*" or "apps/**"
    if (pattern.includes("*")) {
      // Get the static prefix (before first *)
      const parts = pattern.split("*");
      const prefix = parts[0];
      const prefixPath = join(basePath, prefix);

      if (existsSync(prefixPath)) {
        try {
          const entries = readdirSync(prefixPath, { withFileTypes: true });
          for (const entry of entries) {
            if (entry.isDirectory()) {
              directories.push(join(prefixPath, entry.name));
            }
          }
        } catch (err) {
          warnings.push(`Cannot read workspace directory ${prefixPath}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    } else {
      // Direct path like "packages/core"
      const fullPath = join(basePath, pattern);
      if (existsSync(fullPath)) {
        directories.push(fullPath);
      }
    }
  }

  return directories;
}

// ===========================================
// Discovery Logic
// ===========================================

/**
 * Check if a path matches any of the exclude patterns
 */
function isExcluded(relativePath: string, matchers: picomatch.Matcher[]): boolean {
  // Normalize path separators for cross-platform matching
  const normalized = relativePath.replace(/\\/g, "/");
  return matchers.some((matcher) => matcher(normalized));
}

/**
 * Get manifest info for a filename
 */
function getManifestInfo(
  filename: string
): { ecosystem: Ecosystem; format: DependencyFormat } | null {
  const info = MANIFEST_FILES.find((m) => m.filename === filename);
  return info ? { ecosystem: info.ecosystem, format: info.format } : null;
}

/**
 * Discover manifest files in a single directory (non-recursive)
 */
function discoverInDirectory(
  dirPath: string,
  basePath: string,
  isWorkspace: boolean
): DiscoveredManifest | null {
  // Check each manifest type in priority order
  for (const { filename, ecosystem, format } of MANIFEST_FILES) {
    const fullPath = join(dirPath, filename);
    if (existsSync(fullPath)) {
      return {
        path: fullPath,
        relativePath: relative(basePath, fullPath),
        ecosystem,
        format,
        isWorkspace,
      };
    }
  }
  return null;
}

/**
 * Recursively discover manifest files
 */
function discoverRecursive(
  currentPath: string,
  basePath: string,
  matchers: picomatch.Matcher[],
  maxDepth: number,
  maxManifests: number,
  currentDepth: number,
  visitedInodes: Set<number>,
  results: DiscoveredManifest[],
  warnings: string[]
): boolean {
  // Check if we've hit the manifest limit
  if (results.length >= maxManifests) {
    return true; // Truncated
  }

  // Check depth limit
  if (currentDepth > maxDepth) {
    return false;
  }

  // Get relative path for exclude checking
  const relativePath = relative(basePath, currentPath);

  // Skip excluded directories
  if (relativePath && isExcluded(relativePath, matchers)) {
    return false;
  }

  // Check for symlink loops and containment
  try {
    const stat = lstatSync(currentPath);
    if (stat.isSymbolicLink()) {
      // Resolve the symlink to check containment and loops
      let realPath: string;
      try {
        realPath = realpathSync(currentPath);
      } catch (err) {
        // Broken symlink - target doesn't exist
        warnings.push(`Skipped broken symlink: ${relativePath || currentPath}`);
        return false;
      }

      // Security: Ensure symlink doesn't escape basePath
      if (!realPath.startsWith(basePath)) {
        warnings.push(`Skipped symlink outside repository: ${relativePath || currentPath}`);
        return false;
      }

      const realStat = statSync(currentPath);
      if (visitedInodes.has(realStat.ino)) {
        warnings.push(`Skipped symlink loop: ${relativePath}`);
        return false;
      }
      visitedInodes.add(realStat.ino);
    } else {
      visitedInodes.add(stat.ino);
    }
  } catch (err) {
    warnings.push(`Cannot access ${relativePath || currentPath}: ${err instanceof Error ? err.message : String(err)}`);
    return false;
  }

  // Check for manifest files in current directory
  let entries: string[];
  try {
    entries = readdirSync(currentPath);
  } catch {
    warnings.push(`Permission denied: ${relativePath}`);
    return false;
  }

  // First pass: check for manifest files
  for (const entry of entries) {
    if (MANIFEST_FILENAMES.has(entry)) {
      const info = getManifestInfo(entry);
      if (info) {
        const fullPath = join(currentPath, entry);
        results.push({
          path: fullPath,
          relativePath: relative(basePath, fullPath),
          ecosystem: info.ecosystem,
          format: info.format,
          isWorkspace: false,
        });

        if (results.length >= maxManifests) {
          return true;
        }

        // Found a manifest in this directory - still recurse into subdirectories
        // (monorepos often have nested packages)
        break;
      }
    }
  }

  // Second pass: recurse into subdirectories
  for (const entry of entries) {
    const entryPath = join(currentPath, entry);

    try {
      const stat = statSync(entryPath);
      if (stat.isDirectory()) {
        const truncated = discoverRecursive(
          entryPath,
          basePath,
          matchers,
          maxDepth,
          maxManifests,
          currentDepth + 1,
          visitedInodes,
          results,
          warnings
        );
        if (truncated) {
          return true;
        }
      }
    } catch {
      // Skip entries we can't stat
    }
  }

  return false;
}

// ===========================================
// Main Entry Point
// ===========================================

/**
 * Discover all manifest files in a repository.
 *
 * Uses workspace configuration if available, otherwise falls back to
 * recursive directory traversal.
 *
 * @param options - Discovery options
 * @returns Discovery result with manifests and metadata
 */
export function discoverManifests(options: DiscoveryOptions): DiscoveryResult {
  const {
    basePath,
    excludePatterns = DEFAULT_EXCLUDES,
    maxDepth = 10,
    maxManifests = 100,
    followWorkspaces = true,
  } = options;

  const resolvedBase = resolve(basePath);
  const manifests: DiscoveredManifest[] = [];
  const warnings: string[] = [];

  // Compile exclude patterns
  const matchers = excludePatterns.map((pattern) => picomatch(pattern));

  // Check for workspace configuration
  if (followWorkspaces) {
    const workspaceConfig = detectWorkspaces(resolvedBase, warnings);

    if (workspaceConfig) {
      // First, add the root manifest if it exists
      const rootManifest = discoverInDirectory(resolvedBase, resolvedBase, false);
      if (rootManifest) {
        manifests.push(rootManifest);
      }

      // Resolve workspace patterns and scan each workspace
      const workspaceDirs = resolveWorkspacePatterns(
        resolvedBase,
        workspaceConfig.patterns,
        warnings
      );

      for (const wsDir of workspaceDirs) {
        if (manifests.length >= maxManifests) {
          return { manifests, truncated: true, warnings };
        }

        const relPath = relative(resolvedBase, wsDir);
        if (isExcluded(relPath, matchers)) {
          continue;
        }

        const wsManifest = discoverInDirectory(wsDir, resolvedBase, true);
        if (wsManifest) {
          manifests.push(wsManifest);
        }
      }

      // If we found workspaces, don't do recursive discovery
      // (workspaces define the canonical package locations)
      return { manifests, truncated: false, warnings };
    }
  }

  // No workspaces - fall back to recursive discovery
  const visitedInodes = new Set<number>();
  const truncated = discoverRecursive(
    resolvedBase,
    resolvedBase,
    matchers,
    maxDepth,
    maxManifests,
    0,
    visitedInodes,
    manifests,
    warnings
  );

  return { manifests, truncated, warnings };
}

/**
 * Discover manifests and group by ecosystem
 */
export function discoverManifestsByEcosystem(
  options: DiscoveryOptions
): { npm: DiscoveredManifest[]; pypi: DiscoveredManifest[]; truncated: boolean; warnings: string[] } {
  const result = discoverManifests(options);

  return {
    npm: result.manifests.filter((m) => m.ecosystem === "npm"),
    pypi: result.manifests.filter((m) => m.ecosystem === "pypi"),
    truncated: result.truncated,
    warnings: result.warnings,
  };
}
