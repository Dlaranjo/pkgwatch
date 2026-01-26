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

describe("PkgWatchClient - Error Handling", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("throws ApiClientError on 403 forbidden", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      statusText: "Forbidden",
      json: () => Promise.resolve({ error: "forbidden", message: "Access denied" }),
    });

    const client = new PkgWatchClient("pw_test-key", { maxRetries: 0 });

    try {
      await client.scan({ lodash: "^4.0.0" });
      expect.fail("Should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiClientError);
      expect((error as ApiClientError).code).toBe("forbidden");
      expect((error as ApiClientError).status).toBe(403);
    }
  });

  it("throws ApiClientError on 404 not found", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: "Not Found",
      json: () => Promise.resolve({ message: "Package not found" }),
    });

    const client = new PkgWatchClient("pw_test-key", { maxRetries: 0 });

    try {
      await client.scan({});
      expect.fail("Should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiClientError);
      expect((error as ApiClientError).code).toBe("not_found");
      expect((error as ApiClientError).status).toBe(404);
    }
  });

  it("throws ApiClientError on 400 invalid request", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      statusText: "Bad Request",
      json: () => Promise.resolve({ error: { message: "Invalid ecosystem" } }),
    });

    const client = new PkgWatchClient("pw_test-key", { maxRetries: 0 });

    try {
      await client.scan({});
      expect.fail("Should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiClientError);
      expect((error as ApiClientError).code).toBe("invalid_request");
      expect((error as ApiClientError).message).toBe("Invalid ecosystem");
    }
  });

  it("handles timeout with AbortError", async () => {
    const abortError = new Error("Aborted");
    abortError.name = "AbortError";
    mockFetch.mockRejectedValue(abortError);

    const client = new PkgWatchClient("pw_test-key", { maxRetries: 0, timeout: 100 });

    try {
      await client.scan({});
      expect.fail("Should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiClientError);
      expect((error as ApiClientError).code).toBe("timeout");
    }
  });

  it("handles invalid JSON response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.reject(new Error("Invalid JSON")),
    });

    const client = new PkgWatchClient("pw_test-key", { maxRetries: 0 });

    try {
      await client.scan({});
      expect.fail("Should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiClientError);
      expect((error as ApiClientError).code).toBe("server_error");
      expect((error as ApiClientError).message).toBe("Invalid JSON response from API");
    }
  });

  it("handles empty response body", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve(null),
    });

    const client = new PkgWatchClient("pw_test-key", { maxRetries: 0 });

    try {
      await client.scan({});
      expect.fail("Should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiClientError);
      expect((error as ApiClientError).message).toBe("Empty response from API");
    }
  });

  it("falls back to statusText when JSON parsing fails on error response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      json: () => Promise.reject(new Error("Not JSON")),
    });

    const client = new PkgWatchClient("pw_test-key", { maxRetries: 0 });

    try {
      await client.scan({});
      expect.fail("Should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(ApiClientError);
      expect((error as ApiClientError).message).toBe("Internal Server Error");
      expect((error as ApiClientError).code).toBe("server_error");
    }
  });
});

describe("PkgWatchClient - baseUrl Validation", () => {
  it("rejects non-HTTPS baseUrl", () => {
    expect(() => new PkgWatchClient("pw_test-key", { baseUrl: "http://api.example.com" }))
      .toThrow("baseUrl must use HTTPS for security");
  });

  it("allows localhost without HTTPS", () => {
    expect(() => new PkgWatchClient("pw_test-key", { baseUrl: "http://localhost:3000" }))
      .not.toThrow();
  });

  it("allows 127.0.0.1 without HTTPS", () => {
    expect(() => new PkgWatchClient("pw_test-key", { baseUrl: "http://127.0.0.1:3000" }))
      .not.toThrow();
  });

  it("rejects localhost.attacker.com without HTTPS", () => {
    expect(() => new PkgWatchClient("pw_test-key", { baseUrl: "http://localhost.attacker.com" }))
      .toThrow("baseUrl must use HTTPS for security");
  });

  it("accepts HTTPS baseUrl", () => {
    expect(() => new PkgWatchClient("pw_test-key", { baseUrl: "https://custom-api.example.com" }))
      .not.toThrow();
  });
});

describe("PkgWatchClient - Retry Behavior", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("retries on 5xx server errors", async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        statusText: "Service Unavailable",
        json: () => Promise.resolve({ message: "Service unavailable" }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ total: 1, packages: [] }),
      });

    const client = new PkgWatchClient("pw_test-key", { maxRetries: 2 });

    const scanPromise = client.scan({});

    // Advance timers to trigger retry
    await vi.advanceTimersByTimeAsync(2000);

    const result = await scanPromise;
    expect(result.total).toBe(1);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("stops retrying after max retries exceeded", async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      json: () => Promise.resolve({ message: "Server error" }),
    });

    const client = new PkgWatchClient("pw_test-key", { maxRetries: 2 });

    // Start the scan and let it run
    let caughtError: Error | null = null;
    const scanPromise = client.scan({}).catch((e) => {
      caughtError = e;
    });

    // Advance through all retry attempts with enough time for exponential backoff
    // Retry delays: 1s + jitter (up to 2s), 2s + jitter (up to 3s), etc.
    await vi.advanceTimersByTimeAsync(10000);

    // Wait for the promise to settle
    await scanPromise;

    expect(caughtError).toBeInstanceOf(ApiClientError);
    expect((caughtError as unknown as ApiClientError).code).toBe("server_error");
    expect(mockFetch).toHaveBeenCalledTimes(3); // 1 initial + 2 retries
  });

  it("retries on network errors", async () => {
    mockFetch
      .mockRejectedValueOnce(new Error("Network failure"))
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ total: 0, packages: [] }),
      });

    const client = new PkgWatchClient("pw_test-key", { maxRetries: 2 });

    const scanPromise = client.scan({});

    // Advance timers to trigger retry
    await vi.advanceTimersByTimeAsync(2000);

    const result = await scanPromise;
    expect(result.total).toBe(0);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("does not retry on 4xx errors (except 429)", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      json: () => Promise.resolve({ message: "Invalid API key" }),
    });

    const client = new PkgWatchClient("pw_test-key", { maxRetries: 3 });

    await expect(client.scan({})).rejects.toBeInstanceOf(ApiClientError);
    expect(mockFetch).toHaveBeenCalledTimes(1); // No retries
  });
});

describe("PkgWatchClient - scan with ecosystem", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("sends npm ecosystem by default", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ total: 1, packages: [] }),
    });

    const client = new PkgWatchClient("pw_test-key");
    await client.scan({ lodash: "^4.0.0" });

    expect(mockFetch).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        body: JSON.stringify({ dependencies: { lodash: "^4.0.0" }, ecosystem: "npm" }),
      })
    );
  });

  it("sends pypi ecosystem when specified", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ total: 1, packages: [] }),
    });

    const client = new PkgWatchClient("pw_test-key");
    await client.scan({ requests: "^2.28.0" }, "pypi");

    expect(mockFetch).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        body: JSON.stringify({ dependencies: { requests: "^2.28.0" }, ecosystem: "pypi" }),
      })
    );
  });
});

describe("PkgWatchClient - Demo Mode", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not send X-API-Key header in demo mode (empty key)", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ total: 1, packages: [] }),
    });

    const client = new PkgWatchClient("");
    await client.scan({ lodash: "^4.0.0" });

    const fetchCall = mockFetch.mock.calls[0];
    const headers = fetchCall[1]?.headers as Record<string, string>;
    expect(headers["X-API-Key"]).toBeUndefined();
  });

  it("does not send X-API-Key header in demo mode (whitespace key)", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ total: 1, packages: [] }),
    });

    const client = new PkgWatchClient("   ");
    await client.scan({ lodash: "^4.0.0" });

    const fetchCall = mockFetch.mock.calls[0];
    const headers = fetchCall[1]?.headers as Record<string, string>;
    expect(headers["X-API-Key"]).toBeUndefined();
  });

  it("sends X-API-Key header when valid key provided", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ total: 1, packages: [] }),
    });

    const client = new PkgWatchClient("pw_my_api_key");
    await client.scan({ lodash: "^4.0.0" });

    const fetchCall = mockFetch.mock.calls[0];
    const headers = fetchCall[1]?.headers as Record<string, string>;
    expect(headers["X-API-Key"]).toBe("pw_my_api_key");
  });
});
