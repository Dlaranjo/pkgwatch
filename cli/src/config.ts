/**
 * Configuration management for DepHealth CLI.
 *
 * API Key resolution priority:
 * 1. DEPHEALTH_API_KEY environment variable (for CI)
 * 2. ~/.dephealth/config.json file
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const CONFIG_DIR = join(homedir(), ".dephealth");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");

interface Config {
  apiKey?: string;
}

/**
 * Get the API key from environment or config file.
 */
export function getApiKey(): string | undefined {
  // Priority 1: Environment variable
  const envKey = process.env.DEPHEALTH_API_KEY;
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

  try {
    const content = readFileSync(CONFIG_FILE, "utf-8");
    return JSON.parse(content) as Config;
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
