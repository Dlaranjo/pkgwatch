# @dephealth/api-client

TypeScript client library for the DepHealth API.

## Installation

```bash
npm install @dephealth/api-client
```

## Usage

```typescript
import { DepHealthClient, ApiClientError } from '@dephealth/api-client';

// Initialize client
const client = new DepHealthClient('dh_your_api_key');

// Get package health
const result = await client.getPackage('lodash');
console.log(result.health_score);  // 85.2
console.log(result.risk_level);    // "LOW"

// Scan package.json dependencies
const scan = await client.scan({
  dependencies: {
    lodash: '^4.17.21',
    express: '^4.18.0',
  }
});
console.log(scan.total);          // 2
console.log(scan.critical);       // 0

// Get usage statistics
const usage = await client.getUsage();
console.log(usage.requests_this_month);
console.log(usage.monthly_limit);
```

## Error Handling

```typescript
try {
  const result = await client.getPackage('nonexistent-package-xyz');
} catch (error) {
  if (error instanceof ApiClientError) {
    console.log(error.code);    // 'package_not_found'
    console.log(error.message); // 'Package not found'
    console.log(error.status);  // 404
  }
}
```

## Configuration

```typescript
const client = new DepHealthClient(apiKey, {
  baseUrl: 'https://api.dephealth.laranjo.dev/v1',  // Default
  timeout: 30000,  // 30 seconds default
  maxRetries: 3,   // Automatic retry on failure
});
```

## Types

```typescript
interface PackageHealth {
  package: string;
  ecosystem: string;
  health_score: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  abandonment_risk: {
    probability: number;
    time_horizon_months: number;
  };
  components: {
    maintainer_health: number;
    user_centric: number;
    evolution: number;
    community: number;
    security: number;
  };
}

interface ScanResult {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  packages: PackageHealth[];
  not_found: string[];
}

interface UsageInfo {
  tier: string;
  requests_this_month: number;
  monthly_limit: number;
  reset_date: string;
}
```

## Rate Limiting

The client automatically handles rate limit headers. Check remaining requests:

```typescript
// After any API call, check rate limit headers
console.log(client.lastRateLimitInfo);
// { limit: 5000, remaining: 4999, reset: 1704067200 }
```

## License

MIT
