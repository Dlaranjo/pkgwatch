/**
 * PkgWatch API Client
 *
 * Shared client for CLI, GitHub Action, and other integrations.
 * Uses native fetch (Node 20+).
 */

const DEFAULT_API_BASE = "https://api.pkgwatch.dev";
const DEFAULT_TIMEOUT_MS = 30000;
const DEFAULT_MAX_RETRIES = 3;

// ===========================================
// Types
// ===========================================

export interface PackageHealth {
  package: string;
  health_score: number | null;
  risk_level: RiskLevel;
  abandonment_risk: AbandonmentRisk;
  is_deprecated: boolean;
  archived: boolean;
  last_updated: string;
  // Data completeness indicator
  data_quality?: DataQualityCompact;
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
  openssf_checks?: OpenSSFChecks;
  usage_alert?: UsageAlert;
  // Full data quality info (overrides compact from PackageHealth)
  data_quality?: DataQuality;
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
  security_health: number;
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
  true_bus_factor?: number;
  bus_factor_confidence?: "LOW" | "MEDIUM" | "HIGH";
}

export interface OpenSSFChecks {
  summary: Record<string, { score: number; status: "pass" | "partial" | "fail" }>;
  all_checks: Array<{ name: string; score: number; reason: string }>;
}

export interface UsageAlert {
  level: "warning" | "critical" | "exceeded";
  percent: number;
  message: string;
}

// Data quality types for completeness transparency
export type AssessmentCategory = "VERIFIED" | "PARTIAL" | "UNVERIFIED" | "UNAVAILABLE";

export interface DataQuality {
  status?: "complete" | "partial" | "minimal" | "abandoned_minimal";
  assessment: AssessmentCategory;
  missing_sources?: string[];
  has_repository: boolean;
  explanation?: string;
}

export interface DataQualityCompact {
  assessment: AssessmentCategory;
  has_repository: boolean;
}

export interface DataQualitySummary {
  verified_count: number;
  partial_count: number;
  unverified_count: number;
  unavailable_count?: number;
}

export interface DiscoveryInfo {
  queued: number;
  skipped: number;
  message: string;
}

export interface ScanResult {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  packages: PackageHealth[];
  not_found?: string[];
  usage_alert?: UsageAlert;
  // Data quality breakdown
  data_quality?: DataQualitySummary;
  verified_risk_count?: number;
  unverified_risk_count?: number;
  // Discovery info when packages are queued for collection
  discovery?: DiscoveryInfo;
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
  limits_by_tier: Record<string, number>;
}

export interface ClientOptions {
  baseUrl?: string;
  timeout?: number;
  maxRetries?: number;
}

// ===========================================
// Error Classes
// ===========================================

export type ErrorCode =
  | "unauthorized"
  | "forbidden"
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

export class PkgWatchClient {
  private apiKey: string | undefined;
  private baseUrl: string;
  private timeout: number;
  private maxRetries: number;

  constructor(apiKey?: string, options: ClientOptions = {}) {
    // Validate API key format if provided
    if (apiKey && apiKey.trim() !== "" && !apiKey.startsWith("pw_")) {
      throw new Error("Invalid API key format. Keys should start with 'pw_'");
    }

    // Store undefined if empty string was passed
    this.apiKey = apiKey && apiKey.trim() !== "" ? apiKey : undefined;

    // Validate baseUrl uses HTTPS (except localhost for development)
    const baseUrl = options.baseUrl ?? DEFAULT_API_BASE;
    if (baseUrl && !baseUrl.startsWith("https://")) {
      // Use URL parsing to prevent SSRF via hostnames like localhost.attacker.com
      let isLocalhost = false;
      try {
        const parsed = new URL(baseUrl);
        isLocalhost = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
      } catch {
        // Invalid URL - will fail HTTPS check
      }
      if (!isLocalhost) {
        throw new Error("baseUrl must use HTTPS for security");
      }
    }

    this.baseUrl = baseUrl;
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
    this.maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
  }

  /**
   * Sleep for specified milliseconds.
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Calculate retry delay with exponential backoff and jitter.
   * Jitter prevents thundering herd when many clients retry simultaneously.
   */
  private getRetryDelay(attempt: number): number {
    const baseDelay = Math.pow(2, attempt) * 1000; // 1s, 2s, 4s
    const jitter = Math.random() * 1000; // 0-1s random jitter
    return baseDelay + jitter;
  }

  /**
   * Check if status code is retryable.
   */
  private isRetryableStatus(status: number): boolean {
    // Retry on server errors (5xx) and rate limits (429)
    return status >= 500 || status === 429;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: HeadersInit = {
      "Content-Type": "application/json",
      ...options.headers,
    };

    // Only add API key header if configured (demo mode works without it)
    if (this.apiKey) {
      (headers as Record<string, string>)["X-API-Key"] = this.apiKey;
    }

    let lastError: ApiClientError | null = null;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
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
          lastError = new ApiClientError(
            `Request timed out after ${this.timeout / 1000} seconds`,
            0,
            "timeout"
          );
        } else {
          lastError = new ApiClientError(
            "Network error: Unable to reach PkgWatch API",
            0,
            "network_error"
          );
        }

        // Retry on network errors
        if (attempt < this.maxRetries) {
          await this.sleep(this.getRetryDelay(attempt));
          continue;
        }
        throw lastError;
      } finally {
        clearTimeout(timeoutId);
      }

      // Check for retryable status codes (5xx, 429)
      if (!response.ok && this.isRetryableStatus(response.status)) {
        if (attempt < this.maxRetries) {
          await this.sleep(this.getRetryDelay(attempt));
          continue;
        }
      }

      // Handle non-retryable errors or final attempt
      if (!response.ok) {
        const code = this.mapStatusToCode(response.status);
        let message = response.statusText;

        try {
          const errorBody = (await response.json()) as {
            error?: { message?: string };
            message?: string;
          };
          message = errorBody.error?.message ?? errorBody.message ?? message;
        } catch {
          // Use statusText if body parsing fails
        }

        throw new ApiClientError(message, response.status, code);
      }

      try {
        const data = await response.json();
        // Basic validation to catch malformed responses early
        if (data === null || data === undefined) {
          throw new ApiClientError(
            "Empty response from API",
            response.status,
            "server_error"
          );
        }
        return data as T;
      } catch (error) {
        if (error instanceof ApiClientError) {
          throw error;
        }
        throw new ApiClientError(
          "Invalid JSON response from API",
          response.status,
          "server_error"
        );
      }
    }

    // Should not reach here, but TypeScript needs this
    throw lastError ?? new ApiClientError("Max retries exceeded", 0, "network_error");
  }

  private mapStatusToCode(status: number): ErrorCode {
    switch (status) {
      case 400:
        return "invalid_request";
      case 401:
        return "unauthorized";
      case 403:
        return "forbidden";
      case 404:
        return "not_found";
      case 429:
        return "rate_limited";
      default:
        return status >= 500 ? "server_error" : "unknown_error";
    }
  }

  /**
   * Get health score for a single package.
   */
  async getPackage(name: string, ecosystem = "npm"): Promise<PackageHealthFull> {
    const encodedEcosystem = encodeURIComponent(ecosystem);
    const encodedName = encodeURIComponent(name);
    return this.request<PackageHealthFull>(`/packages/${encodedEcosystem}/${encodedName}`);
  }

  /**
   * Scan dependencies and get health scores.
   *
   * @param dependencies - Map of package names to version specifiers
   * @param ecosystem - Package ecosystem: "npm" (default) or "pypi"
   */
  async scan(dependencies: Record<string, string>, ecosystem = "npm"): Promise<ScanResult> {
    return this.request<ScanResult>("/scan", {
      method: "POST",
      body: JSON.stringify({ dependencies, ecosystem }),
    });
  }

  /**
   * Get API usage statistics.
   */
  async getUsage(): Promise<UsageStats> {
    return this.request<UsageStats>("/usage");
  }

  /**
   * Check API health status.
   * @returns Object with health status and optional version info
   */
  async healthCheck(): Promise<{ healthy: boolean; version?: string }> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const response = await fetch(`${this.baseUrl}/health`, {
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        return { healthy: false };
      }

      const data = (await response.json()) as { status?: string; version?: string };
      return {
        healthy: data.status === "healthy",
        version: data.version,
      };
    } catch {
      return { healthy: false };
    }
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
  // Handle edge cases
  if (!Number.isFinite(bytes) || Number.isNaN(bytes) || bytes < 0) {
    return "0 B";
  }
  if (bytes === 0) {
    return "0 B";
  }

  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(
    Math.floor(Math.log(bytes) / Math.log(k)),
    sizes.length - 1
  );
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

// ===========================================
// Dependency Parser Re-exports
// ===========================================

export {
  type Ecosystem,
  type DependencyFormat,
  type DependencyFile,
  type ParseResult,
  DependencyParseError,
  detectDependencyFile,
  parsePackageJson,
  parseRequirementsTxt,
  parsePyprojectToml,
  parsePipfile,
  readDependencies,
  readDependenciesFromFile,
} from "./dependencies.js";

// ===========================================
// Discovery Module Re-exports
// ===========================================

export {
  type DiscoveryOptions,
  type DiscoveredManifest,
  type DiscoveryResult,
  DEFAULT_EXCLUDES,
  discoverManifests,
  discoverManifestsByEcosystem,
} from "./discovery.js";

// ===========================================
// Repo Scanner Re-exports
// ===========================================

export {
  type ManifestStatus,
  type ManifestScanResult,
  type RepoScanSummary,
  type RepoScanResult,
  type RepoScanOptions,
  scanRepository,
  previewRepoScan,
} from "./repo-scanner.js";
