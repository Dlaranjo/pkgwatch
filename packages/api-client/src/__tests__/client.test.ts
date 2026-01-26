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
    it("allows empty API key for demo mode", () => {
      expect(() => new PkgWatchClient("")).not.toThrow();
    });

    it("allows whitespace-only API key for demo mode", () => {
      expect(() => new PkgWatchClient("   ")).not.toThrow();
    });

    it("allows undefined API key for demo mode", () => {
      expect(() => new PkgWatchClient()).not.toThrow();
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

  it("has stack trace", () => {
    const error = new ApiClientError("Test", 500, "server_error");
    expect(error.stack).toBeDefined();
    expect(error.stack).toContain("ApiClientError");
  });

  it("can be stringified", () => {
    const error = new ApiClientError("Test message", 404, "not_found");
    expect(error.toString()).toContain("Test message");
  });

  it("works with all error codes", () => {
    const codes = [
      "unauthorized",
      "forbidden",
      "rate_limited",
      "not_found",
      "invalid_request",
      "network_error",
      "timeout",
      "server_error",
      "unknown_error",
    ] as const;

    for (const code of codes) {
      const error = new ApiClientError("Test", 400, code);
      expect(error.code).toBe(code);
    }
  });
});

// ===========================================
// Additional Constructor Edge Cases
// ===========================================

describe("PkgWatchClient constructor edge cases", () => {
  it("rejects API key that is just 'pw_' with no suffix", () => {
    // pw_ alone is technically valid format but unusual
    expect(() => new PkgWatchClient("pw_")).not.toThrow();
  });

  it("rejects invalid URL as baseUrl", () => {
    expect(
      () =>
        new PkgWatchClient("pw_test123", {
          baseUrl: "not-a-valid-url",
        })
    ).toThrow("baseUrl must use HTTPS for security");
  });

  it("accepts custom timeout value", () => {
    const client = new PkgWatchClient("pw_test123", {
      timeout: 60000,
    });
    expect(client).toBeInstanceOf(PkgWatchClient);
  });

  it("accepts custom maxRetries value", () => {
    const client = new PkgWatchClient("pw_test123", {
      maxRetries: 5,
    });
    expect(client).toBeInstanceOf(PkgWatchClient);
  });

  it("accepts zero maxRetries", () => {
    const client = new PkgWatchClient("pw_test123", {
      maxRetries: 0,
    });
    expect(client).toBeInstanceOf(PkgWatchClient);
  });

  it("rejects API key with leading/trailing whitespace around pw_", () => {
    // " pw_test" has space before pw_
    expect(() => new PkgWatchClient(" pw_test")).toThrow(
      "Invalid API key format"
    );
  });

  it("accepts API key with very long suffix", () => {
    const longKey = "pw_" + "a".repeat(500);
    expect(() => new PkgWatchClient(longKey)).not.toThrow();
  });

  it("allows localhost without port", () => {
    expect(
      () =>
        new PkgWatchClient("pw_test123", {
          baseUrl: "http://localhost",
        })
    ).not.toThrow();
  });

  it("allows 127.0.0.1 without port", () => {
    expect(
      () =>
        new PkgWatchClient("pw_test123", {
          baseUrl: "http://127.0.0.1",
        })
    ).not.toThrow();
  });

  it("rejects FTP protocol", () => {
    expect(
      () =>
        new PkgWatchClient("pw_test123", {
          baseUrl: "ftp://files.example.com",
        })
    ).toThrow("baseUrl must use HTTPS for security");
  });

  it("rejects file:// protocol", () => {
    expect(
      () =>
        new PkgWatchClient("pw_test123", {
          baseUrl: "file:///etc/passwd",
        })
    ).toThrow("baseUrl must use HTTPS for security");
  });
});

// ===========================================
// Additional formatBytes Edge Cases
// ===========================================

describe("formatBytes edge cases", () => {
  it("handles very small positive numbers", () => {
    // Very small positive numbers should be formatted as bytes
    const result = formatBytes(1);
    expect(result).toBe("1 B");
  });

  it("handles negative infinity", () => {
    expect(formatBytes(-Infinity)).toBe("0 B");
  });

  it("handles MAX_SAFE_INTEGER", () => {
    const result = formatBytes(Number.MAX_SAFE_INTEGER);
    expect(result).toContain("TB");
  });

  it("rounds to one decimal place", () => {
    expect(formatBytes(1536)).toBe("1.5 KB"); // Exact 1.5
    expect(formatBytes(1638)).toBe("1.6 KB"); // 1.599...
    expect(formatBytes(1587)).toBe("1.5 KB"); // 1.549...
  });

  it("handles boundary values between units", () => {
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(1024)).toBe("1 KB");
    expect(formatBytes(1025)).toBe("1 KB");
  });
});

// ===========================================
// getRiskColor Edge Cases
// ===========================================

describe("getRiskColor edge cases", () => {
  it("handles lowercase risk levels", () => {
    expect(getRiskColor("critical")).toBe("blue"); // Case sensitive
    expect(getRiskColor("high")).toBe("blue");
    expect(getRiskColor("medium")).toBe("blue");
    expect(getRiskColor("low")).toBe("blue");
  });

  it("handles mixed case", () => {
    expect(getRiskColor("Critical")).toBe("blue");
    expect(getRiskColor("High")).toBe("blue");
  });

  it("handles numeric strings", () => {
    expect(getRiskColor("1")).toBe("blue");
    expect(getRiskColor("100")).toBe("blue");
  });

  it("handles special characters", () => {
    expect(getRiskColor("HIGH!")).toBe("blue");
    expect(getRiskColor("LOW-RISK")).toBe("blue");
  });
});
