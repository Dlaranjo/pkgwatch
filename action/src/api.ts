/**
 * DepHealth API client for GitHub Action.
 *
 * Note: This is a copy of the API client from @dephealth/cli.
 * Consider importing from CLI package when monorepo setup is complete.
 */

const API_BASE = "https://api.dephealth.laranjo.dev/v1";

// API Response Types

export interface PackageHealth {
  package: string;
  ecosystem: string;
  latest_version: string;
  health_score: number;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  abandonment_risk: {
    probability: number;
    time_horizon_months: number;
    risk_factors: string[];
    components: {
      bus_factor_risk: number;
      inactivity_risk: number;
      adoption_risk: number;
      release_risk: number;
    };
  };
  components: {
    maintainer_health: number;
    evolution_health: number;
    community_health: number;
    user_centric: number;
  };
  confidence: {
    score: number;
    level: string;
  };
  signals: {
    weekly_downloads: number;
    dependents_count: number;
    stars: number;
    days_since_last_commit: number;
    commits_90d: number;
    active_contributors_90d: number;
    maintainer_count: number;
    is_deprecated: boolean;
    archived: boolean;
    openssf_score: number | null;
  };
  advisories: string[];
  last_published: string;
  repository_url: string;
  last_updated: string;
}

export interface ScanResult {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  packages: PackageHealth[];
}

interface ApiError {
  error: string;
  message: string;
  status?: number;
}

/**
 * API client for DepHealth.
 */
export class DepHealthClient {
  private apiKey: string;

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${API_BASE}${path}`;
    const headers: HeadersInit = {
      "X-API-Key": this.apiKey,
      "Content-Type": "application/json",
      ...options.headers,
    };

    // 30 second timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);

    let response: Response;
    try {
      response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal,
      });
    } catch (error) {
      clearTimeout(timeout);
      if (error instanceof Error && error.name === "AbortError") {
        throw new ApiClientError("Request timed out after 30 seconds", 0, "timeout");
      }
      throw new ApiClientError(
        "Network error: Unable to reach DepHealth API",
        0,
        "network_error"
      );
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      let errorBody: ApiError;
      try {
        errorBody = (await response.json()) as ApiError;
      } catch {
        errorBody = {
          error: "unknown_error",
          message: response.statusText,
          status: response.status,
        };
      }

      // Map HTTP status codes to error codes
      let code = errorBody.error;
      if (response.status === 401) {
        code = "unauthorized";
      } else if (response.status === 429) {
        code = "rate_limited";
      }

      throw new ApiClientError(
        errorBody.message || response.statusText,
        response.status,
        code
      );
    }

    return response.json() as Promise<T>;
  }

  /**
   * Scan dependencies from a package.json.
   */
  async scan(dependencies: Record<string, string>): Promise<ScanResult> {
    return this.request<ScanResult>("/scan", {
      method: "POST",
      body: JSON.stringify({ dependencies }),
    });
  }
}

/**
 * Custom error class for API errors.
 */
export class ApiClientError extends Error {
  status: number;
  code: string;

  constructor(message: string, status: number, code: string) {
    super(message);
    this.name = "ApiClientError";
    this.status = status;
    this.code = code;
  }
}
