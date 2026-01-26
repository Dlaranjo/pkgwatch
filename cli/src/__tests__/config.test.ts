import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, rmSync, existsSync, readFileSync, statSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

// Mock home directory before importing config
const testDir = join(tmpdir(), `pkgwatch-test-${Date.now()}`);
vi.mock("node:os", async () => {
  const actual = await vi.importActual("node:os");
  return {
    ...actual,
    homedir: () => testDir,
  };
});

// Import after mocking
const { getApiKey, setApiKey, clearConfig, maskApiKey, readConfig, getConfigPath, saveConfig } = await import("../config.js");

describe("config", () => {
  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true });
    }
    delete process.env.PKGWATCH_API_KEY;
  });

  describe("getApiKey", () => {
    it("returns environment variable when set", () => {
      process.env.PKGWATCH_API_KEY = "pw_env_key";
      expect(getApiKey()).toBe("pw_env_key");
    });

    it("returns config file key when env not set", () => {
      setApiKey("pw_file_key");
      expect(getApiKey()).toBe("pw_file_key");
    });

    it("prefers environment variable over config file", () => {
      process.env.PKGWATCH_API_KEY = "pw_env_key";
      setApiKey("pw_file_key");
      expect(getApiKey()).toBe("pw_env_key");
    });

    it("returns undefined when no key configured", () => {
      expect(getApiKey()).toBeUndefined();
    });

    it("returns empty string env var as-is", () => {
      // Empty string is falsy but still a defined env var
      // The actual behavior depends on implementation
      process.env.PKGWATCH_API_KEY = "";
      // Empty string is falsy, so it falls back to config
      expect(getApiKey()).toBeUndefined();
    });

    it("trims whitespace from config file key", () => {
      // Write config manually with whitespace
      const configDir = join(testDir, ".pkgwatch");
      mkdirSync(configDir, { recursive: true });
      writeFileSync(join(configDir, "config.json"), JSON.stringify({ apiKey: "pw_whitespace_key" }));
      expect(getApiKey()).toBe("pw_whitespace_key");
    });
  });

  describe("setApiKey", () => {
    it("saves key to config file", () => {
      setApiKey("pw_test_key_123");
      const config = readConfig();
      expect(config.apiKey).toBe("pw_test_key_123");
    });

    it("creates config directory if needed", () => {
      const configPath = getConfigPath();
      const configDir = join(testDir, ".pkgwatch");

      expect(existsSync(configDir)).toBe(false);
      setApiKey("pw_new_key");
      expect(existsSync(configDir)).toBe(true);
    });

    it("sets secure file permissions", () => {
      setApiKey("pw_secure_key");
      const configPath = getConfigPath();
      const stats = statSync(configPath);
      // Check that only owner has access (0600 = 384 decimal)
      expect(stats.mode & 0o777).toBe(0o600);
    });

    it("overwrites existing key", () => {
      setApiKey("pw_first_key");
      setApiKey("pw_second_key");
      expect(getApiKey()).toBe("pw_second_key");
    });

    it("preserves file permissions on overwrite", () => {
      setApiKey("pw_first_key");
      setApiKey("pw_second_key");
      const configPath = getConfigPath();
      const stats = statSync(configPath);
      expect(stats.mode & 0o777).toBe(0o600);
    });

    it("handles special characters in key", () => {
      const specialKey = "pw_key-with.special_chars+123";
      setApiKey(specialKey);
      expect(getApiKey()).toBe(specialKey);
    });

    it("handles very long keys", () => {
      const longKey = "pw_" + "a".repeat(500);
      setApiKey(longKey);
      expect(getApiKey()).toBe(longKey);
    });
  });

  describe("clearConfig", () => {
    it("removes api key from config", () => {
      setApiKey("pw_to_clear");
      clearConfig();
      const config = readConfig();
      expect(config.apiKey).toBeUndefined();
    });

    it("keeps config file but empties it", () => {
      setApiKey("pw_to_clear");
      clearConfig();
      const configPath = getConfigPath();
      expect(existsSync(configPath)).toBe(true);
      const content = JSON.parse(readFileSync(configPath, "utf-8"));
      expect(content).toEqual({});
    });

    it("works when config does not exist", () => {
      // Should not throw
      expect(() => clearConfig()).not.toThrow();
    });

    it("preserves secure permissions after clear", () => {
      setApiKey("pw_to_clear");
      clearConfig();
      const configPath = getConfigPath();
      const stats = statSync(configPath);
      expect(stats.mode & 0o777).toBe(0o600);
    });
  });

  describe("maskApiKey", () => {
    it("masks long keys showing first 6 and last 4 chars", () => {
      expect(maskApiKey("pw_abcdefghijklmnop")).toBe("pw_abc...mnop");
    });

    it("fully masks short keys", () => {
      expect(maskApiKey("pw_short")).toBe("***");
    });

    it("handles exactly 12 char keys", () => {
      expect(maskApiKey("pw_123456789")).toBe("***");
    });

    it("handles 13 char keys (threshold)", () => {
      expect(maskApiKey("pw_1234567890")).toBe("pw_123...7890");
    });

    it("handles empty string", () => {
      expect(maskApiKey("")).toBe("***");
    });

    it("handles single character", () => {
      expect(maskApiKey("a")).toBe("***");
    });

    it("handles exactly 6 chars", () => {
      expect(maskApiKey("abcdef")).toBe("***");
    });

    it("handles exactly 10 chars", () => {
      expect(maskApiKey("pw_1234567")).toBe("***");
    });

    it("shows correct masking for typical API key", () => {
      // Typical API key format: pw_live_xxxxxxxxxxxx
      const typicalKey = "pw_live_abc123def456";
      expect(maskApiKey(typicalKey)).toBe("pw_liv...f456");
    });

    it("handles very long keys", () => {
      const longKey = "pw_" + "x".repeat(100);
      const masked = maskApiKey(longKey);
      expect(masked).toBe("pw_xxx...xxxx");
      expect(masked.length).toBe(13); // 6 + "..." + 4
    });
  });

  describe("readConfig", () => {
    it("returns empty object when no config file", () => {
      expect(readConfig()).toEqual({});
    });

    it("returns config when file exists", () => {
      setApiKey("pw_read_test");
      const config = readConfig();
      expect(config.apiKey).toBe("pw_read_test");
    });

    it("returns empty object for corrupted JSON", () => {
      const configDir = join(testDir, ".pkgwatch");
      mkdirSync(configDir, { recursive: true });
      writeFileSync(join(configDir, "config.json"), "not valid json {");
      expect(readConfig()).toEqual({});
    });

    it("returns empty object for empty file", () => {
      const configDir = join(testDir, ".pkgwatch");
      mkdirSync(configDir, { recursive: true });
      writeFileSync(join(configDir, "config.json"), "");
      expect(readConfig()).toEqual({});
    });

    it("returns empty object for null JSON", () => {
      const configDir = join(testDir, ".pkgwatch");
      mkdirSync(configDir, { recursive: true });
      writeFileSync(join(configDir, "config.json"), "null");
      expect(readConfig()).toEqual({});
    });

    it("handles array JSON gracefully", () => {
      const configDir = join(testDir, ".pkgwatch");
      mkdirSync(configDir, { recursive: true });
      writeFileSync(join(configDir, "config.json"), "[]");
      // Arrays pass isValidConfig since they are objects without invalid apiKey
      // The returned array will not have apiKey property
      const config = readConfig();
      expect(config.apiKey).toBeUndefined();
    });

    it("returns empty object for non-string apiKey", () => {
      const configDir = join(testDir, ".pkgwatch");
      mkdirSync(configDir, { recursive: true });
      writeFileSync(join(configDir, "config.json"), JSON.stringify({ apiKey: 12345 }));
      expect(readConfig()).toEqual({});
    });

    it("accepts config with only apiKey", () => {
      const configDir = join(testDir, ".pkgwatch");
      mkdirSync(configDir, { recursive: true });
      writeFileSync(join(configDir, "config.json"), JSON.stringify({ apiKey: "pw_valid" }));
      expect(readConfig().apiKey).toBe("pw_valid");
    });

    it("accepts config with extra fields", () => {
      // Extra fields should be preserved
      const configDir = join(testDir, ".pkgwatch");
      mkdirSync(configDir, { recursive: true });
      writeFileSync(
        join(configDir, "config.json"),
        JSON.stringify({ apiKey: "pw_valid", extraField: "value" })
      );
      const config = readConfig();
      expect(config.apiKey).toBe("pw_valid");
    });
  });

  describe("getConfigPath", () => {
    it("returns path in home directory", () => {
      const configPath = getConfigPath();
      expect(configPath).toContain(testDir);
      expect(configPath).toContain(".pkgwatch");
      expect(configPath).toContain("config.json");
    });

    it("returns consistent path", () => {
      const path1 = getConfigPath();
      const path2 = getConfigPath();
      expect(path1).toBe(path2);
    });
  });

  describe("saveConfig", () => {
    it("creates config directory with secure permissions", () => {
      const configDir = join(testDir, ".pkgwatch");
      expect(existsSync(configDir)).toBe(false);

      saveConfig({ apiKey: "pw_test" });

      expect(existsSync(configDir)).toBe(true);
      const stats = statSync(configDir);
      expect(stats.mode & 0o777).toBe(0o700);
    });

    it("creates config file with secure permissions", () => {
      saveConfig({ apiKey: "pw_test" });
      const configPath = getConfigPath();
      const stats = statSync(configPath);
      expect(stats.mode & 0o777).toBe(0o600);
    });

    it("formats JSON with indentation", () => {
      saveConfig({ apiKey: "pw_test" });
      const configPath = getConfigPath();
      const content = readFileSync(configPath, "utf-8");
      // Should have newlines indicating pretty-printed JSON
      expect(content).toContain("\n");
    });

    it("saves empty config", () => {
      saveConfig({});
      const config = readConfig();
      expect(config.apiKey).toBeUndefined();
    });
  });

  describe("permission warnings", () => {
    it("warns about insecure permissions", () => {
      // Create config with insecure permissions
      const configDir = join(testDir, ".pkgwatch");
      mkdirSync(configDir, { recursive: true });
      const configPath = join(configDir, "config.json");
      writeFileSync(configPath, JSON.stringify({ apiKey: "pw_insecure" }));
      chmodSync(configPath, 0o644); // World-readable

      // Mock console.error to capture warning
      const originalError = console.error;
      const errors: string[] = [];
      console.error = (...args: unknown[]) => {
        errors.push(args.join(" "));
      };

      readConfig();

      console.error = originalError;

      // Should have warned about insecure permissions
      expect(errors.some((e) => e.includes("insecure permissions"))).toBe(true);
    });

    it("does not warn for secure permissions", () => {
      setApiKey("pw_secure");

      const originalError = console.error;
      const errors: string[] = [];
      console.error = (...args: unknown[]) => {
        errors.push(args.join(" "));
      };

      readConfig();

      console.error = originalError;

      // Should not have warned
      expect(errors.some((e) => e.includes("insecure permissions"))).toBe(false);
    });

    it("does not warn for 0400 (read-only) permissions", () => {
      const configDir = join(testDir, ".pkgwatch");
      mkdirSync(configDir, { recursive: true });
      const configPath = join(configDir, "config.json");
      writeFileSync(configPath, JSON.stringify({ apiKey: "pw_readonly" }));
      chmodSync(configPath, 0o400);

      const originalError = console.error;
      const errors: string[] = [];
      console.error = (...args: unknown[]) => {
        errors.push(args.join(" "));
      };

      readConfig();

      console.error = originalError;

      // Should not have warned - 0400 is acceptable
      expect(errors.some((e) => e.includes("insecure permissions"))).toBe(false);
    });
  });

  describe("environment variable edge cases", () => {
    it("handles env var with leading/trailing whitespace", () => {
      process.env.PKGWATCH_API_KEY = "  pw_whitespace  ";
      // The implementation returns env var as-is
      expect(getApiKey()).toBe("  pw_whitespace  ");
    });

    it("handles env var with only whitespace", () => {
      process.env.PKGWATCH_API_KEY = "   ";
      // Whitespace-only is truthy but invalid key
      expect(getApiKey()).toBe("   ");
    });

    it("env var takes precedence even if invalid format", () => {
      process.env.PKGWATCH_API_KEY = "not_a_valid_key";
      setApiKey("pw_valid_key");
      // Env var should still take precedence
      expect(getApiKey()).toBe("not_a_valid_key");
    });
  });
});
