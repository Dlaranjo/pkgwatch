import { describe, it, expect } from "vitest";
import { getRiskColor, formatBytes, ApiClientError } from "../api.js";

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
  });

  describe("formatBytes", () => {
    it("formats 0 bytes", () => {
      expect(formatBytes(0)).toBe("0 B");
    });

    it("formats bytes under 1KB", () => {
      expect(formatBytes(500)).toBe("500 B");
    });

    it("formats kilobytes", () => {
      expect(formatBytes(1024)).toBe("1 KB");
      expect(formatBytes(1536)).toBe("1.5 KB");
    });

    it("formats megabytes", () => {
      expect(formatBytes(1048576)).toBe("1 MB");
      expect(formatBytes(2621440)).toBe("2.5 MB");
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
  });
});
