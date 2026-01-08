/**
 * DepHealth API Client
 *
 * Shared client for CLI, GitHub Action, and other integrations.
 * Uses native fetch (Node 20+).
 */

const DEFAULT_API_BASE = "https://api.dephealth.laranjo.dev/v1";
const DEFAULT_TIMEOUT_MS = 30000;

// ===========================================
// Types
// ===========================================

export interface PackageHealth {
  package: string;
  health_score: number;
  risk_level: RiskLevel;
  abandonment_risk: AbandonmentRisk;
  is_deprecated: boolean;
  archived: boolean;
  last_updated: string;
}

export interface PackageHealthFull extends PackageHealth {
  ecosystem: string;
  latest_version: string;
  components: HealthComponents;
  confidence: Confidence;
  signals: Signals;
  advisories: string[];
  last_published: string;
  repository_url: string;
}

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface AbandonmentRisk {
  probability?: number;
  time_horizon_months?: number;
  risk_factors?: string[];
  components?: {
    bus_factor_risk: number;
    inactivity_risk: number;
    adoption_risk: number;
    release_risk: number;
  };
}

export interface HealthComponents {
  maintainer_health: number;
  evolution_health: number;
  community_health: number;
  user_centric: number;
}

export interface Confidence {
  score: number;
  level: string;
}

export interface Signals {
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
}

export interface ScanResult {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  packages: PackageHealth[];
  not_found?: string[];
}

export interface UsageStats {
  tier: string;
  usage: {
    requests_this_month: number;
    monthly_limit: number;
    remaining: number;
    usage_percentage: number;
  };
  reset: {
    date: string;
    seconds_until_reset: number;
  };
}

export interface ClientOptions {
  baseUrl?: string;
  timeout?: number;
}

// ===========================================
// Error Classes
// ===========================================

export type ErrorCode =
  | "unauthorized"
  | "rate_limited"
  | "not_found"
  | "invalid_request"
  | "network_error"
  | "timeout"
  | "server_error"
  | "unknown_error";

export class ApiClientError extends Error {
  status: number;
  code: ErrorCode;

  constructor(message: string, status: number, code: ErrorCode) {
    super(message);
    this.name = "ApiClientError";
    this.status = status;
    this.code = code;
  }
}

// ===========================================
// Client
// ===========================================

export class DepHealthClient {
  private apiKey: string;
  private baseUrl: string;
  private timeout: number;

  constructor(apiKey: string, options: ClientOptions = {}) {
    this.apiKey = apiKey;
    this.baseUrl = options.baseUrl ?? DEFAULT_API_BASE;
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: HeadersInit = {
      "X-API-Key": this.apiKey,
      "Content-Type": "application/json",
      ...options.headers,
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    let response: Response;
    try {
      response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal,
      });
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof Error && error.name === "AbortError") {
        throw new ApiClientError(
          `Request timed out after ${this.timeout / 1000} seconds`,
          0,
          "timeout"
        );
      }
      throw new ApiClientError(
        "Network error: Unable to reach DepHealth API",
        0,
        "network_error"
      );
    } finally {
      clearTimeout(timeoutId);
    }

    if (!response.ok) {
      const code = this.mapStatusToCode(response.status);
      let message = response.statusText;

      try {
        const errorBody = await response.json() as { error?: { message?: string }; message?: string };
        message = errorBody.error?.message ?? errorBody.message ?? message;
      } catch {
        // Use statusText if body parsing fails
      }

      throw new ApiClientError(message, response.status, code);
    }

    return response.json() as Promise<T>;
  }

  private mapStatusToCode(status: number): ErrorCode {
    switch (status) {
      case 401:
        return "unauthorized";
      case 429:
        return "rate_limited";
      case 404:
        return "not_found";
      case 400:
        return "invalid_request";
      default:
        return status >= 500 ? "server_error" : "unknown_error";
    }
  }

  /**
   * Get health score for a single package.
   */
  async getPackage(name: string, ecosystem = "npm"): Promise<PackageHealthFull> {
    const encodedName = encodeURIComponent(name);
    return this.request<PackageHealthFull>(`/packages/${ecosystem}/${encodedName}`);
  }

  /**
   * Scan dependencies and get health scores.
   */
  async scan(dependencies: Record<string, string>): Promise<ScanResult> {
    return this.request<ScanResult>("/scan", {
      method: "POST",
      body: JSON.stringify({ dependencies }),
    });
  }

  /**
   * Get API usage statistics.
   */
  async getUsage(): Promise<UsageStats> {
    return this.request<UsageStats>("/usage");
  }
}

// ===========================================
// Utility Functions
// ===========================================

/**
 * Get color hint for risk level.
 */
export function getRiskColor(level: RiskLevel | string): "red" | "yellow" | "green" | "blue" {
  switch (level) {
    case "CRITICAL":
    case "HIGH":
      return "red";
    case "MEDIUM":
      return "yellow";
    case "LOW":
      return "green";
    default:
      return "blue";
  }
}

/**
 * Format bytes to human-readable size.
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}
