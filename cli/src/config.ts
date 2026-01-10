/**
 * Configuration management for PkgWatch CLI.
 *
 * API Key resolution priority:
 * 1. PKGWATCH_API_KEY environment variable (for CI)
 * 2. ~/.pkgwatch/config.json file
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const CONFIG_DIR = join(homedir(), ".pkgwatch");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");

// Expected secure permissions: owner read/write only (0600)
const SECURE_FILE_MODE = 0o600;

interface Config {
  apiKey?: string;
}

/**
 * Validate that a parsed config object has expected types.
 */
function isValidConfig(obj: unknown): obj is Config {
  if (typeof obj !== "object" || obj === null) {
    return false;
  }
  const config = obj as Record<string, unknown>;
  // apiKey must be undefined or a string
  if (config.apiKey !== undefined && typeof config.apiKey !== "string") {
    return false;
  }
  return true;
}

/**
 * Check if config file has secure permissions (owner-only access).
 * Returns true if permissions are acceptable, false if too permissive.
 */
function hasSecurePermissions(filePath: string): boolean {
  try {
    const stats = statSync(filePath);
    const mode = stats.mode & 0o777;
    // Allow 0600 or 0400 (read-only)
    return mode === 0o600 || mode === 0o400;
  } catch {
    return true; // If we can't check, assume it's fine
  }
}

/**
 * Get the API key from environment or config file.
 */
export function getApiKey(): string | undefined {
  // Priority 1: Environment variable
  const envKey = process.env.PKGWATCH_API_KEY;
  if (envKey) {
    return envKey;
  }

  // Priority 2: Config file
  const config = readConfig();
  return config.apiKey;
}

/**
 * Read the config file.
 */
export function readConfig(): Config {
  if (!existsSync(CONFIG_FILE)) {
    return {};
  }

  // Security: Check file permissions before reading
  if (!hasSecurePermissions(CONFIG_FILE)) {
    console.error(
      "Warning: Config file has insecure permissions. " +
      "Run 'chmod 600 ~/.pkgwatch/config.json' to fix."
    );
  }

  try {
    const content = readFileSync(CONFIG_FILE, "utf-8");
    const parsed = JSON.parse(content);

    // Validate the parsed config has expected structure
    if (!isValidConfig(parsed)) {
      console.error("Warning: Config file has invalid format, ignoring.");
      return {};
    }

    return parsed;
  } catch {
    return {};
  }
}

/**
 * Save the config file with secure permissions (0600).
 */
export function saveConfig(config: Config): void {
  // Ensure config directory exists
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }

  // Write config file
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });

  // Ensure permissions are correct (for existing files)
  chmodSync(CONFIG_FILE, 0o600);
}

/**
 * Set the API key in config file.
 */
export function setApiKey(apiKey: string): void {
  const config = readConfig();
  config.apiKey = apiKey;
  saveConfig(config);
}

/**
 * Clear the config file.
 */
export function clearConfig(): void {
  saveConfig({});
}

/**
 * Get the config file path.
 */
export function getConfigPath(): string {
  return CONFIG_FILE;
}

/**
 * Mask API key for display (show first 6 and last 4 chars).
 */
export function maskApiKey(key: string): string {
  if (key.length <= 12) {
    return "***";
  }
  return `${key.slice(0, 6)}...${key.slice(-4)}`;
}
