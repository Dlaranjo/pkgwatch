import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { PkgWatchClient, ApiClientError } from "../src/api.js";

// Mock global fetch
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe("PkgWatchClient", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("scan", () => {
    it("sends POST request with dependencies", async () => {
      const mockResponse = {
        total: 2,
        critical: 0,
        high: 1,
        medium: 1,
        low: 0,
        packages: [],
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const client = new PkgWatchClient("pw_test-api-key");
      const result = await client.scan({ lodash: "^4.17.21" });

      expect(mockFetch).toHaveBeenCalledWith(
        "https://api.pkgwatch.dev/scan",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "X-API-Key": "pw_test-api-key",
            "Content-Type": "application/json",
          }),
          body: JSON.stringify({ dependencies: { lodash: "^4.17.21" }, ecosystem: "npm" }),
        })
      );
      expect(result).toEqual(mockResponse);
    });

    it("throws ApiClientError on 401", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
        json: () =>
          Promise.resolve({ error: "unauthorized", message: "Invalid API key" }),
      });

      const client = new PkgWatchClient("pw_bad-key");

      try {
        await client.scan({ lodash: "^4.17.21" });
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(ApiClientError);
        expect((error as ApiClientError).code).toBe("unauthorized");
        expect((error as ApiClientError).status).toBe(401);
      }
    });

    it("throws ApiClientError on 429 rate limit", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 429,
        statusText: "Too Many Requests",
        json: () =>
          Promise.resolve({ error: "rate_limit", message: "Rate limit exceeded" }),
      });

      // Use maxRetries: 0 to skip retry delays in test
      const client = new PkgWatchClient("pw_test-key", { maxRetries: 0 });

      try {
        await client.scan({});
        expect.fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(ApiClientError);
        expect((error as ApiClientError).code).toBe("rate_limited");
      }
    });

    it("handles network errors", async () => {
      mockFetch.mockRejectedValue(new Error("Network failure"));

      // Use maxRetries: 0 to skip retry delays in test
      const client = new PkgWatchClient("pw_test-key", { maxRetries: 0 });

      await expect(client.scan({})).rejects.toThrow("Network error");
    });
  });
});

describe("PkgWatchClient - API Key Validation", () => {
  it("rejects API keys without pw_ prefix", () => {
    expect(() => new PkgWatchClient("invalid-key")).toThrow(
      "Invalid API key format. Keys should start with 'pw_'"
    );
  });

  it("accepts empty API keys for demo mode", () => {
    // Empty string enables demo mode - should not throw
    expect(() => new PkgWatchClient("")).not.toThrow();
  });

  it("accepts whitespace-only API keys for demo mode", () => {
    // Whitespace-only treated as empty, enables demo mode - should not throw
    expect(() => new PkgWatchClient("   ")).not.toThrow();
  });

  it("accepts valid pw_ prefixed keys", () => {
    // Should not throw - we don't make actual requests, just verify construction
    expect(() => new PkgWatchClient("pw_valid_key")).not.toThrow();
  });
});

describe("ApiClientError", () => {
  it("creates error with message, status, and code", () => {
    const error = new ApiClientError("Test error", 404, "not_found");

    expect(error.message).toBe("Test error");
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
