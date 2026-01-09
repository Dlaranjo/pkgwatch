# Agent Prompt: AWS Infrastructure Optimization

## Context

You are working on DepHealth, a dependency health intelligence platform built on AWS serverless infrastructure. The infrastructure needs optimization for cold starts, caching, and cost efficiency.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 4: AWS Infrastructure Review)

## Your Mission

Optimize the AWS infrastructure for better performance, lower latency, and cost efficiency. Focus on Lambda cold starts, API Gateway caching, and resource configuration.

## Current Infrastructure

### Lambda Configuration
| Handler | Memory | Timeout | Cold Start Est. |
|---------|--------|---------|-----------------|
| API handlers | 256 MB | 30s | ~1500ms |
| Scan handler | 512 MB | 60s | ~1000ms |
| Package collector | 256 MB | 5 min | ~1500ms |
| Score calculator | 256 MB | 2 min | ~800ms |

### Key Files
- `infrastructure/lib/api-stack.ts` - API Gateway + Lambda
- `infrastructure/lib/storage-stack.ts` - DynamoDB + S3
- `infrastructure/lib/pipeline-stack.ts` - SQS + EventBridge

## Critical Optimizations

### 1. Increase Lambda Memory (HIGH PRIORITY - Quick Win)

**Location:** `infrastructure/lib/api-stack.ts`

**Current:**
```typescript
const commonLambdaProps = {
  runtime: lambda.Runtime.PYTHON_3_12,
  memorySize: 256,  // Too low
  timeout: cdk.Duration.seconds(30),
};
```

**Change to:**
```typescript
const commonLambdaProps = {
  runtime: lambda.Runtime.PYTHON_3_12,
  memorySize: 512,  // Doubles vCPU, ~40% faster cold starts
  timeout: cdk.Duration.seconds(30),
};
```

**For scan handler:**
```typescript
const scanHandler = new lambda.Function(this, "ScanHandler", {
  memorySize: 1024,  // Heavy batch operations need more resources
  timeout: cdk.Duration.seconds(90),
});
```

**Cost Impact:** Minimal - faster execution offsets higher memory cost.

### 2. Enable API Gateway Response Compression (HIGH PRIORITY - Quick Win)

**Location:** `infrastructure/lib/api-stack.ts`

**Add to RestApi configuration:**
```typescript
this.api = new apigateway.RestApi(this, "DepHealthApi", {
  restApiName: "DepHealth API",
  minimumCompressionSize: 1024,  // Compress responses > 1KB
  deployOptions: {
    stageName: "v1",
    // ... existing options
  },
});
```

**Impact:** 60-80% reduction in response payload size.

### 3. Add Provisioned Concurrency for Critical Endpoints (MEDIUM PRIORITY)

**Location:** `infrastructure/lib/api-stack.ts`

**Implementation:**
```typescript
// For GetPackageHandler - most called endpoint
const getPackageVersion = getPackageHandler.currentVersion;
const getPackageAlias = new lambda.Alias(this, 'GetPackageAlias', {
  aliasName: 'live',
  version: getPackageVersion,
  provisionedConcurrentExecutions: 5,
});

// Update API Gateway integration to use alias
packageNameResource.addMethod(
  "GET",
  new apigateway.LambdaIntegration(getPackageAlias),
  // ... existing options
);
```

**Cost:** ~$35/month for 5 provisioned instances.
**Benefit:** Eliminates cold starts for 95%+ of requests.

### 4. Enable API Gateway Caching (MEDIUM PRIORITY)

**Location:** `infrastructure/lib/api-stack.ts`

**Implementation:**
```typescript
deployOptions: {
  stageName: "v1",
  cachingEnabled: true,
  cacheClusterEnabled: true,
  cacheClusterSize: "0.5",  // 0.5 GB cache
  cacheTtl: cdk.Duration.minutes(5),
  // Per-method cache settings
  methodOptions: {
    '/packages/{ecosystem}/{name}/GET': {
      cachingEnabled: true,
      cacheTtl: cdk.Duration.minutes(5),
      cacheDataEncrypted: true,
    },
  },
},
```

**Cost:** ~$15-20/month for 0.5GB cache.
**Benefit:** Eliminates Lambda invocations for repeated queries.

### 5. Lower WAF Rate Limit Threshold (MEDIUM PRIORITY)

**Location:** `infrastructure/lib/api-stack.ts`

**Current:**
```typescript
{
  name: "RateLimitRule",
  action: { block: {} },
  statement: {
    rateBasedStatement: {
      limit: 500,  // 500 requests per 5 minutes = 100/min per IP
    },
  },
},
```

**Change to:**
```typescript
{
  name: "RateLimitRule",
  action: { block: {} },
  statement: {
    rateBasedStatement: {
      limit: 100,  // 100 requests per 5 minutes = 20/min per IP
    },
  },
},
```

**Rationale:** Legitimate CI/CD usage is ~10-20 requests/minute. Current limit is too permissive.

### 6. Add CloudWatch Latency Alarms (LOW PRIORITY)

**Location:** `infrastructure/lib/api-stack.ts`

**Add latency monitoring:**
```typescript
// P95 latency alarm
new cloudwatch.Alarm(this, "ApiLatencyAlarm", {
  alarmName: "dephealth-api-latency-p95",
  metric: this.api.metricLatency({
    statistic: "p95",
    period: cdk.Duration.minutes(5),
  }),
  threshold: 2000,  // 2 seconds
  evaluationPeriods: 3,
  alarmDescription: "API P95 latency exceeds 2 seconds",
});

// Add to dashboard
new cloudwatch.GraphWidget({
  title: "API Latency Percentiles",
  left: [
    this.api.metricLatency({ statistic: "p50" }),
    this.api.metricLatency({ statistic: "p90" }),
    this.api.metricLatency({ statistic: "p99" }),
  ],
});
```

### 7. Optimize Lambda Layers (LOW PRIORITY - Future)

**Concept:** Extract common dependencies to Lambda Layer for faster cold starts.

**Implementation:**
```typescript
const sharedLayer = new lambda.LayerVersion(this, 'SharedDepsLayer', {
  code: lambda.Code.fromAsset('layers/shared'),
  compatibleRuntimes: [lambda.Runtime.PYTHON_3_12],
  description: 'Shared dependencies: boto3, httpx',
});

// Apply to handlers
const commonLambdaProps = {
  layers: [sharedLayer],
  // ...
};
```

**Benefit:** 20-30% reduction in cold start time.

## Cost Optimization

### Current Estimated Costs
| Service | Monthly Cost |
|---------|-------------|
| Lambda (API) | $5-10 |
| Lambda (Pipeline) | $5-15 |
| DynamoDB | $1-5 |
| API Gateway | $3-10 |
| WAF | $6 |
| S3 | $0.50 |
| Secrets Manager | $1.60 |
| CloudWatch | $5-10 |
| **Total** | **$27-58** |

### Optimization Opportunities
1. **CloudWatch Logs retention:** Reduce from 30 days to 14 days
2. **S3 raw data retention:** Reduce from 30 days to 7 days
3. **Lambda Power Tuning:** Use AWS Lambda Power Tuning tool to find optimal memory

## Files to Modify

| File | Changes |
|------|---------|
| `infrastructure/lib/api-stack.ts` | Memory, compression, caching, provisioned concurrency |
| `infrastructure/lib/pipeline-stack.ts` | Collector Lambda memory |
| `infrastructure/lib/storage-stack.ts` | S3 lifecycle rules |

## Deployment Process

After making changes:
```bash
cd /home/iebt/projects/startup-experiment/work/dephealth/infrastructure

# Preview changes
npx cdk diff

# Deploy (requires AWS credentials)
npx cdk deploy --all
```

**Warning:** Some changes (like adding cache cluster) may require stack replacement. Review `cdk diff` output carefully.

## Success Criteria

1. Lambda memory increased to 512MB for API handlers
2. Response compression enabled (> 1KB)
3. Provisioned concurrency for GetPackageHandler
4. API Gateway caching enabled
5. WAF rate limit lowered to 100/5min
6. Latency monitoring dashboard created
7. Cold starts reduced from ~1500ms to ~500ms

## Performance Testing

After deployment, test cold start times:
```bash
# Force cold start by updating function config
aws lambda update-function-configuration \
  --function-name dephealth-GetPackageHandler \
  --environment Variables={FORCE_COLD_START=$(date +%s)}

# Time the request
time curl https://api.dephealth.laranjo.dev/v1/packages/npm/lodash \
  -H "X-API-Key: your-key"
```

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 4 for full infrastructure analysis.
