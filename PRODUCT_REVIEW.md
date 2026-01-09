# DepHealth Product Review

**Review Date:** 2026-01-08
**Review Type:** Comprehensive Multi-Agent Analysis
**Agents Used:** 14 Opus Explorer Agents
**Overall Score:** 7.2/10

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Security Review](#1-security-review)
3. [API Design Review](#2-api-design-review)
4. [Scoring Algorithm Review](#3-scoring-algorithm-review)
5. [AWS Infrastructure Review](#4-aws-infrastructure-review)
6. [DynamoDB Schema Review](#5-dynamodb-schema-review)
7. [CLI/Action UX Review](#6-cliaction-ux-review)
8. [Performance Review](#7-performance-review)
9. [Testing Review](#8-testing-review)
10. [Error Handling Review](#9-error-handling-review)
11. [Rate Limiting/Billing Review](#10-rate-limitingbilling-review)
12. [Landing Page Review](#11-landing-page-review)
13. [Code Quality Review](#12-code-quality-review)
14. [Data Pipeline Review](#13-data-pipeline-review)
15. [Documentation Review](#14-documentation-review)
16. [Priority Matrix](#priority-matrix)
17. [Architecture Diagram](#architecture-diagram)

---

## Executive Summary

DepHealth is a dependency health intelligence platform that predicts npm package abandonment risk. The product consists of:

- **Backend:** Python Lambda functions (API, collectors, scoring)
- **Infrastructure:** AWS CDK (DynamoDB, SQS, API Gateway, WAF)
- **Clients:** TypeScript CLI, GitHub Action, API client
- **Website:** Astro landing page with Terraform S3/CloudFront

### Strengths
- Sophisticated scoring algorithm with continuous mathematical functions
- Secure passwordless authentication with timing normalization
- Well-designed tiered data collection pipeline
- Comprehensive monitoring with CloudWatch alarms

### Critical Issues
- Security race conditions in API key management
- Zero test coverage for data collectors
- Email-based API signup creates conversion friction
- Missing OpenAPI documentation

---

## 1. Security Review

**Score: 8/10**

### Files Reviewed
- `functions/api/signup.py`
- `functions/api/magic_link.py`
- `functions/api/verify_email.py`
- `functions/api/auth_callback.py`
- `functions/shared/auth.py`
- `infrastructure/lib/api-stack.ts`

### Strengths

| Feature | Implementation | Location |
|---------|----------------|----------|
| Timing Normalization | 1.5s minimum response time | `signup.py:24`, `magic_link.py:37` |
| API Key Hashing | SHA-256, shown only once | `auth.py:46-47` |
| Constant-time Comparison | `hmac.compare_digest()` | `auth_callback.py:185` |
| Cookie Security | HttpOnly, Secure, SameSite=Strict | `auth_callback.py:147` |
| WAF Protection | CommonRuleSet, KnownBadInputs, IP Reputation | `api-stack.ts:520-536` |

### Critical Issues

#### 1.1 Magic Link Token Scan (MEDIUM)
```python
# auth_callback.py:88-93 - O(n) table scan
response = table.scan(
    FilterExpression=Attr("magic_token").eq(token),
)
```
**Fix:** Add GSI on `magic_token` field.

#### 1.2 API Key Creation Race Condition (HIGH)
```python
# create_api_key.py:59-74 - Check-then-act without atomic protection
response = table.query(KeyConditionExpression=Key("pk").eq(user_id))
active_keys = [i for i in items if i.get("sk") != "PENDING"]
if len(active_keys) >= MAX_KEYS_PER_USER:
    return error
# RACE WINDOW HERE
api_key = generate_api_key(...)
```
**Fix:** Use DynamoDB transaction or conditional put with count check.

#### 1.3 Magic Link Token Reuse (HIGH)
```python
# auth_callback.py:124-129 - Missing conditional expression
table.update_item(
    Key={"pk": user_id, "sk": user["sk"]},
    UpdateExpression="REMOVE magic_token, magic_expires",
    # MISSING: ConditionExpression="attribute_exists(magic_token)"
)
```
**Fix:** Add `ConditionExpression` to prevent replay attacks.

### Recommendations
1. Add `magic-token-index` GSI to replace scan
2. Use transactions for API key creation
3. Add conditional expression to magic token consumption
4. Consider adding burst rate limiting (per-second/minute)

---

## 2. API Design Review

**Score: 7/10**

### Files Reviewed
- `functions/api/*.py` (all handlers)
- `functions/shared/errors.py`
- `functions/shared/response_utils.py`
- `infrastructure/lib/api-stack.ts`

### Current Endpoints

| Endpoint | Method | Handler | Status |
|----------|--------|---------|--------|
| `/health` | GET | health.py | Good |
| `/packages/{ecosystem}/{name}` | GET | get_package.py | Good |
| `/scan` | POST | post_scan.py | Should be `/scans` |
| `/usage` | GET | get_usage.py | Good |
| `/webhooks/stripe` | POST | stripe_webhook.py | Good |
| `/signup` | POST | signup.py | Good |
| `/verify` | GET | verify_email.py | Move to `/auth/verify` |
| `/auth/magic-link` | POST | magic_link.py | Good |
| `/auth/callback` | GET | auth_callback.py | Good |
| `/auth/me` | GET | auth_me.py | Good |
| `/api-keys` | GET, POST | get_api_keys.py, create_api_key.py | Good |
| `/api-keys/{key_id}` | DELETE | revoke_api_key.py | Good |

### Critical Issues

#### 2.1 No OpenAPI Specification
No machine-readable API documentation exists.

**Fix:** Create `/docs/openapi.yaml`

#### 2.2 Duplicated Error Response Functions
Local `_error_response` defined in 6+ handlers instead of using shared module.

**Files with duplication:**
- `post_scan.py:234-240`
- `get_package.py:316-326`
- `signup.py:213-219`
- `magic_link.py:190-196`
- `verify_email.py:133-146`
- `auth_callback.py:200-213`

**Fix:** Consolidate to `shared/response_utils.py`

#### 2.3 Missing Rate Limit Reset Header
```python
# Current headers in get_package.py:293-307
"X-RateLimit-Limit": str(user["monthly_limit"])
"X-RateLimit-Remaining": str(remaining)
# MISSING: "X-RateLimit-Reset": unix_timestamp
```

### Recommendations
1. Create OpenAPI 3.0 specification
2. Consolidate all error response functions
3. Rename `/scan` to `/scans`
4. Move `/verify` under `/auth/verify`
5. Add `X-RateLimit-Reset` header

---

## 3. Scoring Algorithm Review

**Score: 8/10**

### Files Reviewed
- `functions/scoring/health_score.py`
- `functions/scoring/abandonment_risk.py`
- `functions/scoring/score_package.py`

### Component Weights

| Component | Weight | Calculation |
|-----------|--------|-------------|
| Maintainer Health | 25% | Commit recency (exp decay 90d) + Bus factor (sigmoid) |
| User-Centric | 30% | Downloads (log10) + Dependents (log10) + Stars (log10) |
| Evolution | 20% | Release recency (exp decay 180d) + Commit activity |
| Community | 10% | Contributor count (log10) |
| Security | 15% | OpenSSF score + Vulnerabilities (sigmoid) + Policy |

### Strengths
- Continuous functions prevent gaming
- Maturity factor protects stable packages
- Defensive programming with input validation

### Issues

#### 3.1 No Empirical Calibration
Weights are heuristic, not validated against historical abandonment data.

#### 3.2 Linear Time Scaling
```python
# abandonment_risk.py - Linear scaling is naive
time_factor = min(months / 12, 2.0)
adjusted_risk = min(risk_score * time_factor, 0.95)
```
**Fix:** Use Weibull survival function for proper survival analysis.

#### 3.3 Missing Signals
- Issue response time
- PR merge velocity
- Funding/sustainability indicators
- Maintainer burnout signals

### Recommendations
1. Collect ground truth data on abandoned packages
2. Implement proper survival analysis
3. Add issue response time signal
4. Add PR velocity signal
5. Add confidence intervals to predictions

---

## 4. AWS Infrastructure Review

**Score: 7.5/10**

### Files Reviewed
- `infrastructure/lib/api-stack.ts`
- `infrastructure/lib/storage-stack.ts`
- `infrastructure/lib/pipeline-stack.ts`

### Current Configuration

| Resource | Configuration | Issue |
|----------|---------------|-------|
| Lambda Memory | 256MB (API), 512MB (scan) | Should be 512MB+ for cold starts |
| Lambda Timeout | 30s (API), 60s (scan), 5min (collector) | Appropriate |
| DynamoDB | PAY_PER_REQUEST | Good for variable load |
| WAF | 500 req/5min per IP | Consider lowering |
| API Gateway | 50 RPS, 100 burst | Appropriate |

### Critical Issues

#### 4.1 No Provisioned Concurrency
Cold starts are 500-2000ms for Python 3.12.

```typescript
// Recommended addition to api-stack.ts
const version = getPackageHandler.currentVersion;
new lambda.Alias(this, 'GetPackageAlias', {
  aliasName: 'prod',
  version,
  provisionedConcurrentExecutions: 5,
});
```

#### 4.2 No API Gateway Caching
Every request hits Lambda.

```typescript
// Add to api-stack.ts deployOptions
cachingEnabled: true,
cacheTtl: cdk.Duration.minutes(5),
cacheClusterEnabled: true,
cacheClusterSize: "0.5",
```

#### 4.3 No Multi-Region DR
Single region deployment with no disaster recovery.

### Recommendations
1. Add provisioned concurrency for critical endpoints
2. Enable API Gateway response caching
3. Increase Lambda memory to 512MB
4. Consider multi-region for production

---

## 5. DynamoDB Schema Review

**Score: 7/10**

### Files Reviewed
- `infrastructure/lib/storage-stack.ts`
- `functions/shared/db.py`
- `functions/shared/auth.py`
- `functions/shared/dynamo.py`

### Current Schema

**Packages Table:**
| PK Pattern | SK | Purpose |
|------------|----|---------|
| `{ecosystem}#{name}` | `LATEST` | Current package data |

**GSIs:**
- `risk-level-index` (risk_level, last_updated) - ALL projection
- `tier-index` (tier, last_updated) - KEYS_ONLY projection

**API Keys Table:**
| PK Pattern | SK | Purpose |
|------------|----|---------|
| `user_{email_hash}` | `{key_hash}` | API key record |
| `user_{email_hash}` | `PENDING` | Unverified signup |
| `SYSTEM#RESET_STATE` | `monthly_reset` | Reset checkpoint |

**GSIs:**
- `key-hash-index` (key_hash) - ALL projection
- `email-index` (email) - ALL projection
- `verification-token-index` (verification_token) - KEYS_ONLY
- `stripe-customer-index` (stripe_customer_id) - ALL projection

### Critical Issues

#### 5.1 Magic Token Scan
No GSI on `magic_token` field, causing O(n) scan in `auth_callback.py:88-93`.

#### 5.2 TTL Not Enabled
TTL attribute set in code but NOT enabled on table in CloudFormation.

```typescript
// Add to storage-stack.ts
timeToLiveAttribute: "ttl",
```

#### 5.3 UnprocessedKeys Not Handled
```python
# dynamo.py batch_get_packages() - Missing retry for unprocessed
response = dynamodb.batch_get_item(RequestItems={...})
# MISSING: Handle response.get("UnprocessedKeys", {})
```

#### 5.4 Hot Partition Risk
- `tier-index`: Only 3 values (1, 2, 3)
- `risk-level-index`: Only 4 values (CRITICAL, HIGH, MEDIUM, LOW)

### Recommendations
1. Add `magic-token-index` GSI
2. Enable TTL on API keys table
3. Handle `UnprocessedKeys` in batch operations
4. Consider write sharding for high-volume scenarios

---

## 6. CLI/Action UX Review

**Score: 7.5/10**

### Files Reviewed
- `cli/src/index.ts`
- `cli/src/config.ts`
- `cli/src/api.ts`
- `action/src/index.ts`
- `action/src/scanner.ts`
- `action/src/summary.ts`
- `packages/api-client/src/index.ts`

### Current Commands

```
dephealth
  check <package>     Check single package
  scan [path]         Scan package.json
  usage               Show API usage
  config
    set               Set API key
    show              Show config
    clear             Clear config
```

### Strengths
- Excellent error messages with actionable guidance
- Well-defined exit codes (0, 1, 2)
- Security-first approach (key masking, path traversal prevention)
- Job summary generation in Action

### Issues

#### 6.1 Missing Commands
| Command | Purpose |
|---------|---------|
| `dephealth init` | Interactive onboarding |
| `dephealth doctor` | Diagnose configuration |
| `dephealth explain <pkg>` | Deep dive on single package |

#### 6.2 No Command Aliases
```typescript
// Should add
.command("check <package>")
.alias("c")
```

#### 6.3 No Progress Bar for Large Scans
```typescript
// Current: just spinner
ora(text).start();

// Should add: progress bar for 100+ deps
[=====>    ] 56/200 packages
```

#### 6.4 API Key Not Validated on Set
```typescript
// Current: just saves key
setApiKey(key);
console.log(pc.green("API key saved!"));

// Should: validate before saving
const client = new DepHealthClient(key);
await client.getUsage();  // Test the key
```

### Recommendations
1. Add command aliases
2. Add `dephealth doctor` command
3. Add progress bar for large scans
4. Validate API key on `config set`
5. Add offline mode with cached results

---

## 7. Performance Review

**Score: 6/10**

### Files Reviewed
- `functions/api/get_package.py`
- `functions/api/post_scan.py`
- `functions/collectors/package_collector.py`
- `functions/collectors/github_collector.py`
- `functions/collectors/depsdev_collector.py`
- `infrastructure/lib/api-stack.ts`

### Current Latency Estimates

| Component | p50 | p95 (warm) | p95 (cold) |
|-----------|-----|------------|------------|
| API Gateway overhead | 5ms | 15ms | 15ms |
| Lambda cold start | 0ms | 0ms | 800-1200ms |
| DynamoDB GetItem | 10ms | 25ms | 25ms |
| API key validation | 15ms | 30ms | 30ms |
| **Total** | **35ms** | **75ms** | **1100ms** |

### Critical Issues

#### 7.1 Cold Starts Too Slow
256MB memory = ~1500ms cold start. 512MB = ~800ms. 1024MB = ~500ms.

#### 7.2 No Caching Layer
Every request hits DynamoDB directly.

```python
# Recommended: In-Lambda LRU cache
_package_cache = {}
_cache_ttl = 300  # 5 minutes

def get_cached_package(pk: str):
    if pk in _package_cache:
        item, timestamp = _package_cache[pk]
        if time.time() - timestamp < _cache_ttl:
            return item
    # ... fetch from DynamoDB
```

#### 7.3 Sequential External API Calls
deps.dev makes 4 sequential calls when 3 could be parallel:
```python
# Current: sequential
pkg_data = await get_package()
version_data = await get_version()  # These 3 could be parallel
project_data = await get_project()
dependents_data = await get_dependents()

# Fix: parallel after initial call
version_data, project_data, dependents_data = await asyncio.gather(
    get_version(), get_project(), get_dependents()
)
```

#### 7.4 No Connection Pooling
```python
# Current: new client per request
async with httpx.AsyncClient(timeout=30) as client:
    # Client destroyed after scope

# Fix: module-level client
_http_client = httpx.AsyncClient(
    limits=httpx.Limits(max_keepalive_connections=20),
    http2=True,
)
```

#### 7.5 No Response Compression
```typescript
// Add to api-stack.ts
minimumCompressionSize: 1024,  // Compress responses > 1KB
```

### Recommendations
1. Increase Lambda memory to 512MB+
2. Add in-Lambda caching for hot packages
3. Enable API Gateway response caching
4. Parallelize deps.dev API calls
5. Add HTTP connection pooling
6. Enable response compression

---

## 8. Testing Review

**Score: 6.5/10**

### Files Reviewed
- `tests/*.py` (all test files)
- `action/__tests__/*.ts`
- `cli/src/__tests__/*.ts`

### Current Coverage

| Component | Coverage | Quality |
|-----------|----------|---------|
| `scoring/health_score.py` | Excellent (1588 lines) | Comprehensive |
| `scoring/abandonment_risk.py` | Excellent | Edge cases covered |
| `api/get_package.py` | Good | Happy path + errors |
| `api/post_scan.py` | Good | Happy path + errors |
| `shared/auth.py` | Good | Core flows tested |
| `collectors/*.py` | **ZERO** | Critical gap |
| `api/stripe_webhook.py` | **ZERO** | Critical gap |
| `api/dlq_processor.py` | **ZERO** | Critical gap |

### Critical Gaps

#### 8.1 Collector Tests Missing
No tests for:
- `package_collector.py`
- `github_collector.py`
- `npm_collector.py`
- `depsdev_collector.py`
- `bundlephobia_collector.py`
- `refresh_dispatcher.py`

#### 8.2 Integration Tests Missing
No end-to-end tests for:
- Package scoring flow
- Auth flow (signup -> verify -> login)
- Stripe billing flow

#### 8.3 Security Tests Incomplete
Missing tests for:
- Path traversal in Action
- SQL/NoSQL injection
- XSS in package names
- Rate limit bypass

### Recommendations
1. Add collector tests with mocked HTTP (use `responses` or `httpretty`)
2. Add DLQ processor tests
3. Add Stripe webhook tests
4. Add integration tests for critical paths
5. Add security fuzzing tests

---

## 9. Error Handling Review

**Score: 7.5/10**

### Files Reviewed
- `functions/shared/errors.py`
- `functions/shared/response_utils.py`
- `functions/collectors/dlq_processor.py`
- `functions/collectors/package_collector.py`
- All API handlers

### Exception Hierarchy

```python
APIError (base)
├── InvalidAPIKeyError (401)
├── RateLimitExceededError (429)
├── PackageNotFoundError (404)
├── InvalidEcosystemError (400)
├── InvalidRequestError (400)
└── InternalError (500)
```

### Strengths
- Well-designed exception hierarchy
- DLQ processor with exponential backoff (60s-900s)
- Graceful degradation when data sources fail
- Retry tracking with `_retry_count` field

### Issues

#### 9.1 No Circuit Breaker
No circuit breaker for external APIs (GitHub, deps.dev, npm).

```python
# Recommended implementation
class CircuitBreaker:
    def __init__(self, failure_threshold=5, reset_timeout=60):
        self.failures = 0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    def record_failure(self):
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.state = "OPEN"

    def can_execute(self) -> bool:
        if self.state == "OPEN":
            # Check if timeout elapsed
            return False
        return True
```

#### 9.2 Duplicated Retry Logic
`retry_with_backoff` duplicated in:
- `depsdev_collector.py:46-76`
- `npm_collector.py:45-68`
- `bundlephobia_collector.py`

**Fix:** Create `shared/retry.py`

#### 9.3 No Error Classification in DLQ
All errors treated equally; 404 (permanent) retried same as 500 (transient).

```python
# Recommended
TRANSIENT_ERRORS = ["timeout", "500", "503", "rate_limited"]
PERMANENT_ERRORS = ["404", "invalid_package"]

def should_retry(error: str) -> bool:
    return any(e in error.lower() for e in TRANSIENT_ERRORS)
```

#### 9.4 No Alerting on Permanent DLQ Failures
Failures stored in DynamoDB but no CloudWatch metric emitted.

### Recommendations
1. Implement circuit breaker pattern
2. Consolidate retry logic to shared module
3. Add error classification in DLQ processor
4. Add CloudWatch metrics for permanent failures
5. Add structured logging with correlation IDs

---

## 10. Rate Limiting/Billing Review

**Score: 6.5/10**

### Files Reviewed
- `functions/shared/auth.py`
- `functions/api/stripe_webhook.py`
- `functions/api/reset_usage.py`
- `functions/api/get_package.py`
- `functions/api/post_scan.py`

### Tier Configuration

| Tier | Monthly Limit | Price |
|------|--------------|-------|
| Free | 5,000 | $0 |
| Starter | 25,000 | Coming soon |
| Pro | 100,000 | Coming soon |
| Business | 500,000 | Coming soon |

### Strengths
- Atomic check-and-increment with DynamoDB conditional expressions
- Sharded counters for GitHub rate limiting (10 shards)
- Proper Stripe webhook signature verification
- Monthly reset with checkpointing

### Critical Issues

#### 10.1 API Key Creation Race Condition
See Security Review section 1.2.

#### 10.2 API Key Revocation Race Condition
```python
# revoke_api_key.py:79-91 - Check-then-delete without atomic protection
active_keys = [i for i in items if i.get("sk") != "PENDING"]
if len(active_keys) <= 1:
    return error
# RACE WINDOW HERE
table.delete_item(Key={"pk": user_id, "sk": target_key["sk"]})
```

#### 10.3 No Usage Alerts
No notification when users approach limits (80%, 90%, 100%).

#### 10.4 No Usage Reset on Upgrade
When tier upgrades, usage counter is NOT reset.

#### 10.5 Email-Based API Signup
```astro
<!-- CTA.astro:21 - Major friction -->
<a href="mailto:hello@laranjo.dev?subject=DepHealth API Key Request...">
  Get Free API Key
</a>
```
**Fix:** Implement self-service registration.

### Recommendations
1. Fix race conditions with transactions
2. Add usage alerts at 80%, 90%, 100%
3. Reset usage on tier upgrade
4. Implement self-service API key signup
5. Add soft overage mode option

---

## 11. Landing Page Review

**Score: 5.5/10**

### Files Reviewed
- `landing-page/src/pages/*.astro`
- `landing-page/src/components/*.astro`
- `landing-page/src/layouts/Layout.astro`
- `landing-page/src/styles/global.css`
- `landing-page/terraform/main.tf`
- `landing-page/deploy.sh`

### Current Pages

| Page | Status | Notes |
|------|--------|-------|
| `index.astro` | Good | Well-structured landing page |
| `docs.astro` | Good | Comprehensive API docs |
| `methodology.astro` | Excellent | Builds technical credibility |
| `/pricing` | **Missing** | No dedicated pricing page |
| `/about` | **Missing** | No company information |
| `/privacy` | **Missing** | Required for enterprise |
| `/terms` | **Missing** | Required for enterprise |

### Critical Issues

#### 11.1 Email-Based API Signup
See Rate Limiting section 10.5.

#### 11.2 No Analytics
No page view or event tracking.

```astro
<!-- Missing from Layout.astro head -->
<script defer data-domain="dephealth.laranjo.dev" src="https://plausible.io/js/script.js"></script>
```

#### 11.3 Missing SEO Elements
```astro
<!-- Missing from Layout.astro -->
<link rel="canonical" href={Astro.url.href} />
<meta property="og:image" content="https://dephealth.laranjo.dev/og-image.png" />
<link rel="sitemap" href="/sitemap.xml" />
```

Missing files:
- `/robots.txt`
- `/sitemap.xml`
- `/og-image.png`

#### 11.4 No Mobile Navigation
Navbar hides CLI link on mobile without hamburger menu alternative.

#### 11.5 Minimal Footer
```astro
<!-- Current footer - only 9 lines -->
<footer class="py-8 border-t border-[#1a1a1f] text-center text-sm text-zinc-500">
  <p>Built by <a href="https://laranjo.dev">Laranjo</a></p>
</footer>
```
Missing: social links, newsletter, secondary nav, legal links.

#### 11.6 No Trust Signals
- No testimonials
- No company logos
- No security badges
- No uptime SLA

### Recommendations
1. Implement self-service API signup
2. Add analytics (Plausible or Fathom)
3. Add SEO elements (og:image, sitemap, robots.txt)
4. Add mobile hamburger menu
5. Expand footer with standard elements
6. Add testimonials/social proof
7. Create pricing, about, privacy, terms pages

---

## 12. Code Quality Review

**Score: 7/10**

### Files Reviewed
- All Python files in `functions/`
- All TypeScript files in `cli/`, `action/`, `packages/`, `infrastructure/`

### Python Quality

| Aspect | Status | Notes |
|--------|--------|-------|
| PEP 8 Style | Good | Some line length violations |
| Type Hints | Partial | Good in scoring, missing in handlers |
| Docstrings | Excellent | Comprehensive in scoring modules |
| Import Organization | Good | Consistent grouping |

### TypeScript Quality

| Aspect | Status | Notes |
|--------|--------|-------|
| Strict Mode | Enabled | All packages |
| ESLint | Not configured | Missing linter |
| JSDoc | Minimal | Needs improvement |

### Critical Issues

#### 12.1 Code Duplication
Duplicated functions:
- `decimal_default`: `post_scan.py:23-27`, `response_utils.py:17-21`
- `_error_response`: 6+ handlers
- `retry_with_backoff`: 4 collectors

#### 12.2 High Complexity Handlers
`get_package.py` handler is 135 lines with cyclomatic complexity >10.

**Fix:** Extract to smaller functions:
```python
def handler(event, context):
    request = parse_request(event)
    auth_result = authenticate(request)
    rate_limit_result = check_rate_limit(auth_result)
    package_data = fetch_package(request)
    return format_response(package_data, auth_result)
```

#### 12.3 print() Instead of Logger
```python
# shared/auth.py:123 - Should use logger
print(f"Error validating API key: {e}")

# shared/dynamo.py:33 - Should use logger
print(f"Error fetching package: {e}")
```

#### 12.4 Lambda Handlers Missing Type Hints
```python
# Current
def handler(event, context):

# Should be
def handler(event: APIGatewayEvent, context: LambdaContext) -> LambdaResponse:
```

### Recommendations
1. Extract shared utilities to eliminate duplication
2. Refactor high-complexity handlers
3. Replace print() with logger
4. Add type hints to Lambda handlers
5. Add ESLint configuration for TypeScript

---

## 13. Data Pipeline Review

**Score: 7/10**

### Files Reviewed
- `functions/collectors/package_collector.py`
- `functions/collectors/refresh_dispatcher.py`
- `functions/collectors/dlq_processor.py`
- `functions/collectors/github_collector.py`
- `functions/collectors/npm_collector.py`
- `functions/collectors/depsdev_collector.py`
- `infrastructure/lib/pipeline-stack.ts`

### Tiered Refresh Strategy

| Tier | Packages | Frequency | Schedule |
|------|----------|-----------|----------|
| 1 | Top 100 | Daily | 2:00 AM UTC |
| 2 | 101-500 | Every 3 days | 3:00 AM UTC |
| 3 | 501-2500 | Weekly | 4:00 AM Sundays |

### SQS Configuration

```typescript
visibilityTimeout: 6 minutes  // > Lambda timeout (5 min)
maxReceiveCount: 3            // Before DLQ
batchSize: 10
maxConcurrency: 10
```

### Strengths
- Parallel data collection (npm + bundlephobia)
- Graceful degradation when sources fail
- Sharded GitHub rate limiting (10 shards)
- DLQ with exponential backoff

### Critical Issues

#### 13.1 Race Condition in Rate Limit
```python
# package_collector.py:98-135 - Read-then-write pattern
total_calls = _get_total_github_calls(window_key)
if total_calls >= GITHUB_HOURLY_LIMIT:
    return False
# RACE WINDOW: Another Lambda could also pass check
table.update_item(...)  # Increment
```

**Fix:** Use conditional expression:
```python
table.update_item(
    ConditionExpression="attribute_not_exists(calls) OR calls < :limit",
)
```

#### 13.2 No Input Validation
Message body assumed well-formed; no schema validation.

```python
# Recommended
def validate_message(message: dict) -> bool:
    if message.get("ecosystem") not in ["npm", "pypi", "cargo"]:
        return False
    name = message.get("name", "")
    if not name or len(name) > 214:
        return False
    return True
```

#### 13.3 No Error Classification
All errors treated equally in DLQ processor. See Error Handling section 9.3.

#### 13.4 No Jitter in Scheduled Refreshes
All Tier 1 packages dispatched at exactly 2:00 AM UTC.

```python
# Add jitter to refresh_dispatcher.py
delay = random.randint(0, 60)  # 0-60 second jitter
entries.append({
    "DelaySeconds": delay,
})
```

### Recommendations
1. Fix race condition with atomic rate limit check
2. Add input validation for SQS messages
3. Implement error classification
4. Add jitter to scheduled refreshes
5. Add circuit breaker for external APIs

---

## 14. Documentation Review

**Score: 5.5/10**

### Files Reviewed
- All `*.md` files in project
- Code comments and docstrings
- `landing-page/src/pages/docs.astro`

### Current Documentation

| Document | Status | Quality |
|----------|--------|---------|
| Root README.md | Exists | Excellent |
| CLI README.md | Exists | Good |
| Action README.md | Exists | Excellent |
| API Client README.md | **Missing** | - |
| Infrastructure README.md | **Missing** | - |
| Functions README.md | **Missing** | - |
| Landing Page README.md | **Missing** | - |
| CONTRIBUTING.md | **Missing** | - |
| CHANGELOG.md | **Missing** | - |
| OpenAPI Spec | **Missing** | - |
| ADRs | **Missing** | - |

### Critical Gaps

#### 14.1 No OpenAPI Specification
No machine-readable API documentation for client generation.

#### 14.2 Missing Component READMEs
No documentation for:
- `packages/api-client/`
- `infrastructure/`
- `functions/`
- `landing-page/`

#### 14.3 No Contributing Guide
No guidance for:
- Development setup
- Code style
- PR process
- Testing requirements

#### 14.4 No Environment Variable Documentation
Variables scattered across code without central reference:
- `PACKAGES_TABLE`
- `API_KEYS_TABLE`
- `STRIPE_SECRET_ARN`
- `GITHUB_TOKEN`

### Recommendations
1. Create OpenAPI 3.0 specification
2. Add README.md to each major directory
3. Create CONTRIBUTING.md
4. Create CHANGELOG.md
5. Create .env.example with all variables documented
6. Create Architecture Decision Records

---

## Priority Matrix

### Critical (Do This Week)

| # | Issue | Impact | Effort | Location |
|---|-------|--------|--------|----------|
| 1 | Add magic_token GSI | Eliminates O(n) scan on login | Low | `storage-stack.ts` |
| 2 | Fix API key creation race | Security vulnerability | Medium | `create_api_key.py` |
| 3 | Enable TTL on API keys table | PENDING records never cleanup | Low | `storage-stack.ts` |
| 4 | Fix magic link token reuse | Security vulnerability | Low | `auth_callback.py` |

### High Priority (Do This Sprint)

| # | Issue | Impact | Effort | Location |
|---|-------|--------|--------|----------|
| 5 | Add collector tests | 0% coverage on critical code | High | `tests/` |
| 6 | Self-service API signup | Major conversion friction | High | `landing-page/` |
| 7 | Increase Lambda memory | 50% faster cold starts | Low | `api-stack.ts` |
| 8 | Add OpenAPI specification | Enterprise adoption blocker | Medium | `docs/openapi.yaml` |
| 9 | Consolidate error_response | DRY violation | Medium | `shared/` |
| 10 | Handle UnprocessedKeys | Data loss at scale | Low | `dynamo.py` |

### Medium Priority (Do This Month)

| # | Issue | Impact | Effort | Location |
|---|-------|--------|--------|----------|
| 11 | Implement circuit breakers | Cascade failure prevention | Medium | `shared/` |
| 12 | Add analytics | Can't measure conversion | Low | `landing-page/` |
| 13 | Parallelize deps.dev calls | 60% faster collection | Medium | `depsdev_collector.py` |
| 14 | Add in-Lambda caching | 50% fewer DynamoDB reads | Low | `get_package.py` |
| 15 | Fix rate limit race condition | Potential to exceed limits | Medium | `package_collector.py` |
| 16 | Add usage alerts | User experience | Medium | `auth.py` |
| 17 | Add structured logging | Observability | Medium | `shared/` |

### Low Priority (Backlog)

| # | Issue | Impact | Effort | Location |
|---|-------|--------|--------|----------|
| 18 | Enable response compression | 70% smaller payloads | Low | `api-stack.ts` |
| 19 | Add command aliases | CLI UX | Low | `cli/src/index.ts` |
| 20 | Add progress bar | CLI UX for large scans | Low | `cli/src/index.ts` |
| 21 | Add mobile navigation | Landing page UX | Low | `Navbar.astro` |
| 22 | Add SEO elements | Search visibility | Low | `Layout.astro` |
| 23 | Create CONTRIBUTING.md | Developer onboarding | Low | Root |
| 24 | Create CHANGELOG.md | Version tracking | Low | Root |
| 25 | Add ADRs | Architecture documentation | Medium | `docs/` |

---

## Architecture Diagram

```
                    ┌─────────────────────────────────────────────────────────────┐
                    │                    LANDING PAGE                              │
                    │   Astro + CloudFront + S3 + Terraform                       │
                    │   dephealth.laranjo.dev                                     │
                    └─────────────────────────────────────────────────────────────┘
                                              │
                    ┌─────────────────────────▼─────────────────────────┐
                    │                    WAF WebACL                      │
                    │   CommonRuleSet + KnownBadInputs + RateLimit      │
                    │   500 req/5min per IP                             │
                    └─────────────────────────┬─────────────────────────┘
                                              │
                    ┌─────────────────────────▼─────────────────────────┐
                    │              API Gateway (REST)                    │
                    │     api.dephealth.laranjo.dev/v1                  │
                    │     50 RPS / 100 burst                            │
                    └─────────────────────────┬─────────────────────────┘
                                              │
        ┌─────────────────────────────────────┼─────────────────────────────────────┐
        │                                     │                                     │
        ▼                                     ▼                                     ▼
   ┌─────────┐                         ┌─────────────┐                       ┌───────────┐
   │  Auth   │                         │  Package    │                       │   Admin   │
   │ Lambdas │                         │  Lambdas    │                       │  Lambdas  │
   │         │                         │             │                       │           │
   │ signup  │                         │ get_package │                       │ stripe_   │
   │ verify  │                         │ post_scan   │                       │ webhook   │
   │ magic_  │                         │ get_usage   │                       │ reset_    │
   │ link    │                         │             │                       │ usage     │
   │ callback│                         │             │                       │           │
   │ auth_me │                         │             │                       │           │
   │ api_keys│                         │             │                       │           │
   └────┬────┘                         └──────┬──────┘                       └─────┬─────┘
        │                                     │                                     │
        └──────────────────┬──────────────────┴─────────────────────────────────────┘
                           │
                           ▼
              ┌────────────────────────────┐
              │      DynamoDB Tables       │
              │                            │
              │  dephealth-packages        │
              │  ├── pk: {eco}#{name}      │
              │  ├── sk: LATEST            │
              │  ├── GSI: risk-level-index │
              │  ├── GSI: tier-index       │
              │  └── Streams: NEW_IMAGE    │
              │                            │
              │  dephealth-api-keys        │
              │  ├── pk: user_{hash}       │
              │  ├── sk: {key_hash}|PENDING│
              │  ├── GSI: key-hash-index   │
              │  ├── GSI: email-index      │
              │  ├── GSI: verification-idx │
              │  └── GSI: stripe-cust-idx  │
              └──────────────┬─────────────┘
                             │
                             │ DynamoDB Streams
                             ▼
              ┌────────────────────────────┐
              │    Score Calculator        │
              │       Lambda               │
              │                            │
              │  health_score.py           │
              │  abandonment_risk.py       │
              └────────────────────────────┘


    ╔════════════════════════════════════════════════════════════════════════════╗
    ║                      DATA COLLECTION PIPELINE                              ║
    ╚════════════════════════════════════════════════════════════════════════════╝

    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                        EventBridge Schedules                                │
    │                                                                             │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
    │  │ Daily 2AM    │  │ 3-Day 3AM    │  │ Weekly 4AM   │  │ Every 15min  │    │
    │  │ Tier 1       │  │ Tier 2       │  │ Tier 3       │  │ DLQ Process  │    │
    │  │ (Top 100)    │  │ (101-500)    │  │ (501-2500)   │  │              │    │
    │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
    └─────────┼─────────────────┼─────────────────┼─────────────────┼────────────┘
              │                 │                 │                 │
              └─────────────────┼─────────────────┘                 │
                                │                                   │
                                ▼                                   │
              ┌─────────────────────────────────────┐               │
              │      Refresh Dispatcher Lambda      │               │
              │  - Queries tier-index GSI           │               │
              │  - Sends batches of 10 to SQS       │               │
              └───────────────────┬─────────────────┘               │
                                  │                                 │
                                  ▼                                 │
              ┌─────────────────────────────────────┐               │
              │     SQS Queue (package-queue)       │               │
              │  - Visibility: 6 min                │               │
              │  - DLQ: max 3 receives              │               │
              └───────────────────┬─────────────────┘               │
                                  │                                 │
                    ┌─────────────┴─────────────┐                   │
                    │  maxConcurrency: 10       │                   │
                    │  batchSize: 10            │                   │
                    ▼                           ▼                   │
              ┌─────────────────────────────────────┐               │
              │     Package Collector Lambda        │               │
              │  - deps.dev (primary, no limit)     │               │
              │  - npm registry (~1K/hr)            │               │
              │  - GitHub API (5K/hr sharded)       │               │
              │  - bundlephobia (bundle size)       │               │
              │  - Semaphore: 5 concurrent/Lambda   │               │
              └───────────────────┬─────────────────┘               │
                                  │                                 │
                    ┌─────────────┴─────────────┐                   │
                    ▼                           ▼                   │
              ┌───────────────┐         ┌───────────────┐           │
              │   DynamoDB    │         │  S3 Bucket    │           │
              │   (packages)  │         │  (raw-data)   │           │
              │               │         │  30 day TTL   │           │
              └───────────────┘         └───────────────┘           │
                                                                    │
                                                                    │
              ┌─────────────────────────────────────┐               │
              │     SQS DLQ (package-dlq)           │◄──────────────┘
              │  - 14 day retention                 │
              │  - Failed after 3 attempts          │
              └───────────────────┬─────────────────┘
                                  │
                                  ▼
              ┌─────────────────────────────────────┐
              │     DLQ Processor Lambda            │
              │  - Exponential backoff (60s-900s)   │
              │  - Max 5 total retries              │
              │  - Stores permanent failures        │
              │    in DynamoDB as FAILED#...       │
              └─────────────────────────────────────┘


    ╔════════════════════════════════════════════════════════════════════════════╗
    ║                           CLIENTS                                          ║
    ╚════════════════════════════════════════════════════════════════════════════╝

    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                                                                             │
    │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐ │
    │  │  @dephealth/cli │  │ dephealth/action│  │    @dephealth/api-client    │ │
    │  │                 │  │                 │  │                             │ │
    │  │  Commands:      │  │  Inputs:        │  │  Methods:                   │ │
    │  │  - check        │  │  - api-key      │  │  - getPackage()             │ │
    │  │  - scan         │  │  - fail-on      │  │  - scan()                   │ │
    │  │  - usage        │  │  - working-dir  │  │  - getUsage()               │ │
    │  │  - config       │  │                 │  │                             │ │
    │  │                 │  │  Outputs:       │  │  Used by:                   │ │
    │  │  Exit codes:    │  │  - total        │  │  - CLI                      │ │
    │  │  0 = success    │  │  - critical     │  │  - GitHub Action            │ │
    │  │  1 = risk found │  │  - high         │  │  - Direct integration       │ │
    │  │  2 = CLI error  │  │  - risk-summary │  │                             │ │
    │  │                 │  │                 │  │                             │ │
    │  └─────────────────┘  └─────────────────┘  └─────────────────────────────┘ │
    │                                                                             │
    └─────────────────────────────────────────────────────────────────────────────┘


    ╔════════════════════════════════════════════════════════════════════════════╗
    ║                         MONITORING                                         ║
    ╚════════════════════════════════════════════════════════════════════════════╝

              ┌─────────────────────────────────────┐
              │          SNS Alert Topic            │
              │    (dephealth-alerts)               │
              └───────────────────┬─────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
        ▼                         ▼                         ▼
  ┌───────────┐             ┌───────────┐             ┌───────────┐
  │  Lambda   │             │  DynamoDB │             │    API    │
  │  Alarms   │             │  Alarms   │             │  Alarms   │
  │           │             │           │             │           │
  │ - Errors  │             │ - Throttle│             │ - 5XX     │
  │ - Duration│             │           │             │ - 4XX     │
  │ - Throttle│             │           │             │           │
  └───────────┘             └───────────┘             └───────────┘

              ┌─────────────────────────────────────┐
              │      CloudWatch Dashboard           │
              │                                     │
              │  - SQS Queue Depth                  │
              │  - Messages Processed               │
              │  - Lambda Invocations/Errors        │
              │  - DynamoDB Consumed Capacity       │
              │  - API Gateway Latency              │
              └─────────────────────────────────────┘
```

---

## Appendix: File Reference

### Backend (Python)
```
functions/
├── api/
│   ├── get_package.py      # GET /packages/{ecosystem}/{name}
│   ├── post_scan.py        # POST /scan
│   ├── get_usage.py        # GET /usage
│   ├── signup.py           # POST /signup
│   ├── verify_email.py     # GET /verify
│   ├── magic_link.py       # POST /auth/magic-link
│   ├── auth_callback.py    # GET /auth/callback
│   ├── auth_me.py          # GET /auth/me
│   ├── get_api_keys.py     # GET /api-keys
│   ├── create_api_key.py   # POST /api-keys
│   ├── revoke_api_key.py   # DELETE /api-keys/{id}
│   ├── stripe_webhook.py   # POST /webhooks/stripe
│   ├── reset_usage.py      # Monthly usage reset
│   └── health.py           # GET /health
├── collectors/
│   ├── package_collector.py    # Main orchestrator
│   ├── refresh_dispatcher.py   # Schedule trigger
│   ├── dlq_processor.py        # Dead letter queue
│   ├── github_collector.py     # GitHub API
│   ├── npm_collector.py        # npm registry
│   ├── depsdev_collector.py    # deps.dev API
│   └── bundlephobia_collector.py
├── scoring/
│   ├── health_score.py         # Health score calculation
│   ├── abandonment_risk.py     # Risk prediction
│   └── score_package.py        # Stream handler
└── shared/
    ├── auth.py                 # Authentication utilities
    ├── errors.py               # Exception hierarchy
    ├── response_utils.py       # Response formatting
    ├── dynamo.py               # DynamoDB utilities
    └── types.py                # TypedDict definitions
```

### Infrastructure (TypeScript)
```
infrastructure/
├── lib/
│   ├── api-stack.ts        # API Gateway + Lambda
│   ├── storage-stack.ts    # DynamoDB + S3
│   └── pipeline-stack.ts   # SQS + EventBridge
└── bin/
    └── app.ts              # CDK app entry
```

### Clients (TypeScript)
```
cli/
├── src/
│   ├── index.ts            # CLI commands
│   ├── config.ts           # Config management
│   └── api.ts              # API client re-export

action/
├── src/
│   ├── index.ts            # Action entry
│   ├── scanner.ts          # Package.json scanner
│   └── summary.ts          # Job summary generator
└── action.yml              # Action metadata

packages/api-client/
└── src/
    └── index.ts            # Shared API client
```

### Landing Page (Astro)
```
landing-page/
├── src/
│   ├── pages/
│   │   ├── index.astro     # Main landing
│   │   ├── docs.astro      # API documentation
│   │   └── methodology.astro
│   ├── components/
│   │   ├── Navbar.astro
│   │   ├── Hero.astro
│   │   ├── LiveDemo.astro
│   │   ├── Features.astro
│   │   ├── CTA.astro
│   │   └── Footer.astro
│   └── layouts/
│       └── Layout.astro
├── terraform/
│   └── main.tf             # CloudFront + S3
└── deploy.sh               # Deployment script
```

---

*Generated by 14 Opus Explorer Agents on 2026-01-08*
