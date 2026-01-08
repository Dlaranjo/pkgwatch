import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, rmSync, existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// Mock home directory before importing config
const testDir = join(tmpdir(), `dephealth-test-${Date.now()}`);
vi.mock("node:os", async () => {
  const actual = await vi.importActual("node:os");
  return {
    ...actual,
    homedir: () => testDir,
  };
});

// Import after mocking
const { getApiKey, setApiKey, clearConfig, maskApiKey, readConfig, getConfigPath } = await import("../config.js");

describe("config", () => {
  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true });
    }
    delete process.env.DEPHEALTH_API_KEY;
  });

  describe("getApiKey", () => {
    it("returns environment variable when set", () => {
      process.env.DEPHEALTH_API_KEY = "dh_env_key";
      expect(getApiKey()).toBe("dh_env_key");
    });

    it("returns config file key when env not set", () => {
      setApiKey("dh_file_key");
      expect(getApiKey()).toBe("dh_file_key");
    });

    it("prefers environment variable over config file", () => {
      process.env.DEPHEALTH_API_KEY = "dh_env_key";
      setApiKey("dh_file_key");
      expect(getApiKey()).toBe("dh_env_key");
    });

    it("returns undefined when no key configured", () => {
      expect(getApiKey()).toBeUndefined();
    });
  });

  describe("setApiKey", () => {
    it("saves key to config file", () => {
      setApiKey("dh_test_key_123");
      const config = readConfig();
      expect(config.apiKey).toBe("dh_test_key_123");
    });

    it("creates config directory if needed", () => {
      const configPath = getConfigPath();
      const configDir = join(testDir, ".dephealth");

      expect(existsSync(configDir)).toBe(false);
      setApiKey("dh_new_key");
      expect(existsSync(configDir)).toBe(true);
    });

    it("sets secure file permissions", () => {
      setApiKey("dh_secure_key");
      const configPath = getConfigPath();
      const stats = statSync(configPath);
      // Check that only owner has access (0600 = 384 decimal)
      expect(stats.mode & 0o777).toBe(0o600);
    });
  });

  describe("clearConfig", () => {
    it("removes api key from config", () => {
      setApiKey("dh_to_clear");
      clearConfig();
      const config = readConfig();
      expect(config.apiKey).toBeUndefined();
    });
  });

  describe("maskApiKey", () => {
    it("masks long keys showing first 6 and last 4 chars", () => {
      expect(maskApiKey("dh_abcdefghijklmnop")).toBe("dh_abc...mnop");
    });

    it("fully masks short keys", () => {
      expect(maskApiKey("dh_short")).toBe("***");
    });

    it("handles exactly 12 char keys", () => {
      expect(maskApiKey("dh_123456789")).toBe("***");
    });

    it("handles 13 char keys (threshold)", () => {
      expect(maskApiKey("dh_1234567890")).toBe("dh_123...7890");
    });
  });

  describe("readConfig", () => {
    it("returns empty object when no config file", () => {
      expect(readConfig()).toEqual({});
    });

    it("returns config when file exists", () => {
      setApiKey("dh_read_test");
      const config = readConfig();
      expect(config.apiKey).toBe("dh_read_test");
    });
  });
});
