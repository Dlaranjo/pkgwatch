# @pkgwatch/api-client

TypeScript client library for the PkgWatch API.

## Installation

```bash
npm install @pkgwatch/api-client
```

## Usage

```typescript
import { PkgWatchClient, ApiClientError } from '@pkgwatch/api-client';

// Initialize client
const client = new PkgWatchClient('pw_your_api_key');

// Get npm package health (full details)
const result = await client.getPackage('lodash');
console.log(result.health_score);  // 85
console.log(result.risk_level);    // "LOW"
console.log(result.components);    // { maintainer_health: 90, ... }

// Get Python package health
const pyResult = await client.getPackage('requests', 'pypi');
console.log(pyResult.health_score);

// Scan package.json dependencies
const scan = await client.scan({
  lodash: '^4.17.21',
  express: '^4.18.0',
});
console.log(scan.total);          // 2
console.log(scan.critical);       // 0

// Get usage statistics
const usage = await client.getUsage();
console.log(usage.usage.requests_this_month);
console.log(usage.usage.monthly_limit);
```

## Error Handling

```typescript
try {
  const result = await client.getPackage('nonexistent-package-xyz');
} catch (error) {
  if (error instanceof ApiClientError) {
    console.log(error.code);    // 'not_found'
    console.log(error.message); // 'Package not found'
    console.log(error.status);  // 404
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `unauthorized` | 401 | Invalid or expired API key |
| `forbidden` | 403 | Insufficient permissions |
| `not_found` | 404 | Package not found |
| `rate_limited` | 429 | API quota exceeded |
| `invalid_request` | 400 | Malformed request |
| `server_error` | 5xx | Server-side error |
| `network_error` | - | Network connectivity issue |
| `timeout` | - | Request timed out |

## Configuration

```typescript
const client = new PkgWatchClient(apiKey, {
  baseUrl: 'https://api.pkgwatch.dev/v1',  // Default
  timeout: 30000,  // 30 seconds default
  maxRetries: 3,   // Automatic retry with exponential backoff
});
```

### Retry Behavior

The client automatically retries on:
- 5xx server errors
- 429 rate limit responses
- Network errors and timeouts

Retries use exponential backoff with jitter (1s + jitter, 2s + jitter, 4s + jitter).

## Types

### PackageHealth (summary)

```typescript
interface PackageHealth {
  package: string;
  health_score: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  abandonment_risk: AbandonmentRisk;
  is_deprecated: boolean;
  archived: boolean;
  last_updated: string;
}
```

### PackageHealthFull (from getPackage)

```typescript
interface PackageHealthFull extends PackageHealth {
  ecosystem: string;
  latest_version: string;
  components: HealthComponents;
  confidence: Confidence;
  signals: Signals;
  advisories: string[];
  last_published: string;
  repository_url: string;
}

interface HealthComponents {
  maintainer_health: number;
  evolution_health: number;
  community_health: number;
  user_centric: number;
  security_health: number;
}
```

### ScanResult

```typescript
interface ScanResult {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  packages: PackageHealth[];
  not_found?: string[];
}
```

### UsageStats

```typescript
interface UsageStats {
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
```

## Utility Functions

```typescript
import { getRiskColor, formatBytes } from '@pkgwatch/api-client';

// Get color hint for terminal output
getRiskColor('CRITICAL');  // 'red'
getRiskColor('HIGH');      // 'red'
getRiskColor('MEDIUM');    // 'yellow'
getRiskColor('LOW');       // 'green'

// Format bytes for display
formatBytes(1024);         // '1 KB'
formatBytes(1048576);      // '1 MB'
```

## Security

- API keys must start with `pw_` prefix
- HTTPS is enforced (HTTP only allowed for localhost development)
- API keys are never logged

## License

Proprietary - All rights reserved
