import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { DepHealthClient, ApiClientError } from "../src/api.js";

// Mock global fetch
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe("DepHealthClient", () => {
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

      const client = new DepHealthClient("test-api-key");
      const result = await client.scan({ lodash: "^4.17.21" });

      expect(mockFetch).toHaveBeenCalledWith(
        "https://api.dephealth.laranjo.dev/v1/scan",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "X-API-Key": "test-api-key",
            "Content-Type": "application/json",
          }),
          body: JSON.stringify({ dependencies: { lodash: "^4.17.21" } }),
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

      const client = new DepHealthClient("bad-key");

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
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        statusText: "Too Many Requests",
        json: () =>
          Promise.resolve({ error: "rate_limit", message: "Rate limit exceeded" }),
      });

      const client = new DepHealthClient("test-key");

      try {
        await client.scan({});
      } catch (error) {
        expect(error).toBeInstanceOf(ApiClientError);
        expect((error as ApiClientError).code).toBe("rate_limited");
      }
    });

    it("handles network errors", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network failure"));

      const client = new DepHealthClient("test-key");

      await expect(client.scan({})).rejects.toThrow("Network error");
    });
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
