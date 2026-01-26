import { describe, it, expect } from "vitest";
import { getRiskColor, formatBytes, ApiClientError, DependencyParseError } from "../api.js";

describe("api utilities", () => {
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

    it("returns blue for unknown levels", () => {
      expect(getRiskColor("UNKNOWN")).toBe("blue");
      expect(getRiskColor("")).toBe("blue");
    });

    it("is case sensitive", () => {
      // lowercase versions should return blue (unknown)
      expect(getRiskColor("critical")).toBe("blue");
      expect(getRiskColor("high")).toBe("blue");
      expect(getRiskColor("medium")).toBe("blue");
      expect(getRiskColor("low")).toBe("blue");
    });

    it("handles mixed case as unknown", () => {
      expect(getRiskColor("Critical")).toBe("blue");
      expect(getRiskColor("HiGh")).toBe("blue");
    });

    it("handles whitespace as unknown", () => {
      expect(getRiskColor(" CRITICAL")).toBe("blue");
      expect(getRiskColor("HIGH ")).toBe("blue");
      expect(getRiskColor(" ")).toBe("blue");
    });
  });

  describe("formatBytes", () => {
    it("formats 0 bytes", () => {
      expect(formatBytes(0)).toBe("0 B");
    });

    it("formats bytes under 1KB", () => {
      expect(formatBytes(500)).toBe("500 B");
      expect(formatBytes(1)).toBe("1 B");
      expect(formatBytes(1023)).toBe("1023 B");
    });

    it("formats kilobytes", () => {
      expect(formatBytes(1024)).toBe("1 KB");
      expect(formatBytes(1536)).toBe("1.5 KB");
      expect(formatBytes(10240)).toBe("10 KB");
    });

    it("formats megabytes", () => {
      expect(formatBytes(1048576)).toBe("1 MB");
      expect(formatBytes(2621440)).toBe("2.5 MB");
      expect(formatBytes(104857600)).toBe("100 MB");
    });

    it("formats gigabytes", () => {
      expect(formatBytes(1073741824)).toBe("1 GB");
      expect(formatBytes(5368709120)).toBe("5 GB");
    });

    it("formats terabytes", () => {
      expect(formatBytes(1099511627776)).toBe("1 TB");
    });

    it("handles negative numbers as 0 B", () => {
      expect(formatBytes(-1)).toBe("0 B");
      expect(formatBytes(-1000)).toBe("0 B");
    });

    it("handles NaN as 0 B", () => {
      expect(formatBytes(NaN)).toBe("0 B");
    });

    it("handles Infinity as 0 B", () => {
      expect(formatBytes(Infinity)).toBe("0 B");
      expect(formatBytes(-Infinity)).toBe("0 B");
    });

    it("handles very large numbers", () => {
      // Petabyte-scale should cap at TB
      const petabyte = 1024 * 1099511627776;
      expect(formatBytes(petabyte)).toBe("1024 TB");
    });
  });

  describe("ApiClientError", () => {
    it("creates error with status and code", () => {
      const error = new ApiClientError("Not found", 404, "not_found");
      expect(error.message).toBe("Not found");
      expect(error.status).toBe(404);
      expect(error.code).toBe("not_found");
      expect(error.name).toBe("ApiClientError");
    });

    it("is instanceof Error", () => {
      const error = new ApiClientError("Test", 500, "server_error");
      expect(error instanceof Error).toBe(true);
      expect(error instanceof ApiClientError).toBe(true);
    });

    it("has correct name property for stack traces", () => {
      const error = new ApiClientError("Test error", 400, "invalid_request");
      expect(error.name).toBe("ApiClientError");
      // Stack trace should include ApiClientError name
      expect(error.stack).toContain("ApiClientError");
    });

    it("preserves all error codes", () => {
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
        const error = new ApiClientError("Test", 0, code);
        expect(error.code).toBe(code);
      }
    });

    it("handles 0 status for network errors", () => {
      const error = new ApiClientError("Network error", 0, "network_error");
      expect(error.status).toBe(0);
    });

    it("handles high status codes", () => {
      const error = new ApiClientError("Gateway timeout", 504, "server_error");
      expect(error.status).toBe(504);
    });
  });

  describe("DependencyParseError", () => {
    it("creates error with message", () => {
      const error = new DependencyParseError("Invalid package.json");
      expect(error.message).toBe("Invalid package.json");
      expect(error.name).toBe("DependencyParseError");
    });

    it("is instanceof Error", () => {
      const error = new DependencyParseError("Test");
      expect(error instanceof Error).toBe(true);
      expect(error instanceof DependencyParseError).toBe(true);
    });

    it("can be distinguished from ApiClientError", () => {
      const parseError = new DependencyParseError("Parse failed");
      const apiError = new ApiClientError("API failed", 500, "server_error");

      expect(parseError instanceof DependencyParseError).toBe(true);
      expect(parseError instanceof ApiClientError).toBe(false);
      expect(apiError instanceof ApiClientError).toBe(true);
      expect(apiError instanceof DependencyParseError).toBe(false);
    });
  });
});
