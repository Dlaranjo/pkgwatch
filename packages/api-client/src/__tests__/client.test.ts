import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  PkgWatchClient,
  ApiClientError,
  getRiskColor,
  formatBytes,
} from "../index.js";

// ===========================================
// Constructor Validation Tests
// ===========================================

describe("PkgWatchClient", () => {
  describe("constructor", () => {
    it("throws error for empty API key", () => {
      expect(() => new PkgWatchClient("")).toThrow(
        "API key is required and cannot be empty"
      );
    });

    it("throws error for whitespace-only API key", () => {
      expect(() => new PkgWatchClient("   ")).toThrow(
        "API key is required and cannot be empty"
      );
    });

    it("throws error for API key without pw_ prefix", () => {
      expect(() => new PkgWatchClient("invalid_key")).toThrow(
        "Invalid API key format. Keys should start with 'pw_'"
      );
    });

    it("accepts valid API key with pw_ prefix", () => {
      expect(() => new PkgWatchClient("pw_test123")).not.toThrow();
    });

    it("throws error for HTTP baseUrl (non-localhost)", () => {
      expect(
        () =>
          new PkgWatchClient("pw_test123", {
            baseUrl: "http://api.example.com",
          })
      ).toThrow("baseUrl must use HTTPS for security");
    });

    it("allows HTTP localhost for development", () => {
      expect(
        () =>
          new PkgWatchClient("pw_test123", {
            baseUrl: "http://localhost:3000",
          })
      ).not.toThrow();
    });

    it("allows HTTP 127.0.0.1 for development", () => {
      expect(
        () =>
          new PkgWatchClient("pw_test123", {
            baseUrl: "http://127.0.0.1:3000",
          })
      ).not.toThrow();
    });

    it("rejects SSRF attempt via localhost.attacker.com", () => {
      expect(
        () =>
          new PkgWatchClient("pw_test123", {
            baseUrl: "http://localhost.attacker.com",
          })
      ).toThrow("baseUrl must use HTTPS for security");
    });

    it("rejects SSRF attempt via localhost@attacker.com", () => {
      expect(
        () =>
          new PkgWatchClient("pw_test123", {
            baseUrl: "http://localhost@attacker.com",
          })
      ).toThrow("baseUrl must use HTTPS for security");
    });

    it("allows HTTPS baseUrl", () => {
      expect(
        () =>
          new PkgWatchClient("pw_test123", {
            baseUrl: "https://api.example.com",
          })
      ).not.toThrow();
    });

    it("uses default baseUrl when not specified", () => {
      const client = new PkgWatchClient("pw_test123");
      // We can't directly access private fields, but we can verify no error
      expect(client).toBeInstanceOf(PkgWatchClient);
    });
  });
});

// ===========================================
// Utility Function Tests
// ===========================================

describe("getRiskColor", () => {
  it("returns red for CRITICAL", () => {
    expect(getRiskColor("CRITICAL")).toBe("red");
  });

  it("returns red for HIGH", () => {
    expect(getRiskColor("HIGH")).toBe("red");
  });

  it("returns yellow for MEDIUM", () => {
    expect(getRiskColor("MEDIUM")).toBe("yellow");
  });

  it("returns green for LOW", () => {
    expect(getRiskColor("LOW")).toBe("green");
  });

  it("returns blue for unknown values", () => {
    expect(getRiskColor("UNKNOWN")).toBe("blue");
  });

  it("returns blue for empty string", () => {
    expect(getRiskColor("")).toBe("blue");
  });
});

describe("formatBytes", () => {
  it("returns '0 B' for 0", () => {
    expect(formatBytes(0)).toBe("0 B");
  });

  it("returns '0 B' for negative numbers", () => {
    expect(formatBytes(-100)).toBe("0 B");
  });

  it("returns '0 B' for NaN", () => {
    expect(formatBytes(NaN)).toBe("0 B");
  });

  it("returns '0 B' for Infinity", () => {
    expect(formatBytes(Infinity)).toBe("0 B");
  });

  it("formats bytes correctly", () => {
    expect(formatBytes(500)).toBe("500 B");
  });

  it("formats kilobytes correctly", () => {
    expect(formatBytes(1024)).toBe("1 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
  });

  it("formats megabytes correctly", () => {
    expect(formatBytes(1048576)).toBe("1 MB");
    expect(formatBytes(1572864)).toBe("1.5 MB");
  });

  it("formats gigabytes correctly", () => {
    expect(formatBytes(1073741824)).toBe("1 GB");
  });

  it("formats terabytes correctly", () => {
    expect(formatBytes(1099511627776)).toBe("1 TB");
  });

  it("caps at terabytes for very large values", () => {
    // Petabyte-scale value should still show TB
    expect(formatBytes(1125899906842624)).toBe("1024 TB");
  });
});

// ===========================================
// ApiClientError Tests
// ===========================================

describe("ApiClientError", () => {
  it("creates error with correct properties", () => {
    const error = new ApiClientError("Test message", 401, "unauthorized");
    expect(error.message).toBe("Test message");
    expect(error.status).toBe(401);
    expect(error.code).toBe("unauthorized");
    expect(error.name).toBe("ApiClientError");
  });

  it("is instanceof Error", () => {
    const error = new ApiClientError("Test", 500, "server_error");
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(ApiClientError);
  });
});
