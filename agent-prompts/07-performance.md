# Agent Prompt: Performance Optimization

## Context

You are working on DepHealth, a dependency health intelligence platform. The system needs performance optimization to reduce latency and improve user experience.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 7: Performance Review)

## Your Mission

Optimize application performance through caching, connection pooling, parallel processing, and code-level optimizations.

## Current Performance Baseline

| Metric | Current | Target |
|--------|---------|--------|
| GET /packages p50 (warm) | ~150ms | <50ms |
| GET /packages p95 (cold) | ~1500ms | <500ms |
| POST /scan (100 deps) | ~1500ms | <500ms |
| Collection per package | ~3000ms | <1500ms |

## Critical Optimizations

### 1. Add In-Lambda Caching (HIGH PRIORITY)

**Location:** `functions/api/get_package.py`

**Problem:** Every request fetches from DynamoDB, even for frequently accessed packages.

**Solution:** Implement LRU cache for hot packages:

```python
import time
from typing import Optional, Tuple

# Module-level cache
_package_cache: dict[str, Tuple[dict, float]] = {}
_CACHE_TTL = 300  # 5 minutes
_CACHE_MAX_SIZE = 100

def _get_cached_package(pk: str) -> Optional[dict]:
    """Get package from cache if fresh."""
    if pk in _package_cache:
        item, timestamp = _package_cache[pk]
        if time.time() - timestamp < _CACHE_TTL:
            return item
        # Expired - remove
        del _package_cache[pk]
    return None

def _set_cached_package(pk: str, item: dict) -> None:
    """Cache package with TTL."""
    # Evict oldest if at capacity
    if len(_package_cache) >= _CACHE_MAX_SIZE:
        oldest_key = min(_package_cache.keys(), key=lambda k: _package_cache[k][1])
        del _package_cache[oldest_key]

    _package_cache[pk] = (item, time.time())

# In handler, use cache first:
def handler(event, context):
    # ... auth logic ...

    pk = f"{ecosystem}#{name}"

    # Try cache first
    item = _get_cached_package(pk)
    if item is None:
        # Cache miss - fetch from DynamoDB
        response = table.get_item(Key={"pk": pk, "sk": "LATEST"})
        item = response.get("Item")
        if item:
            _set_cached_package(pk, item)

    # ... response logic ...
```

**Expected Impact:** 70% reduction in DynamoDB reads for hot packages.

### 2. Parallelize deps.dev API Calls (HIGH PRIORITY)

**Location:** `functions/collectors/depsdev_collector.py`

**Problem:** 4 sequential API calls when 3 could be parallel.

**Current (sequential):**
```python
pkg_data = await retry_with_backoff(client.get, pkg_url)
version_data = await retry_with_backoff(client.get, version_url)  # Sequential
project_data = await retry_with_backoff(client.get, project_url)  # Sequential
dependents_data = await retry_with_backoff(client.get, dependents_url)  # Sequential
```

**Optimized (parallel after initial call):**
```python
async def get_package_info(name: str, ecosystem: str = "npm") -> Optional[dict]:
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        # First call to get version (needed for version URL)
        pkg_url = f"{DEPSDEV_API}/systems/{ecosystem}/packages/{quote(name, safe='')}"
        pkg_data = await retry_with_backoff(client.get, pkg_url)

        if not pkg_data:
            return None

        latest_version = pkg_data.get("defaultVersion", "")

        # Parallel calls for version, project, and dependents
        version_url = f"{pkg_url}/versions/{quote(latest_version, safe='')}"
        project_key = pkg_data.get("projectKey", "")
        project_url = f"{DEPSDEV_API}/projects/{quote(project_key, safe='')}" if project_key else None
        dependents_url = f"{pkg_url}/dependents"

        tasks = [retry_with_backoff(client.get, version_url)]

        if project_url:
            tasks.append(retry_with_backoff(client.get, project_url))
        else:
            tasks.append(asyncio.coroutine(lambda: None)())  # Placeholder

        tasks.append(retry_with_backoff(client.get, dependents_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        version_data = results[0] if not isinstance(results[0], Exception) else {}
        project_data = results[1] if not isinstance(results[1], Exception) else {}
        dependents_data = results[2] if not isinstance(results[2], Exception) else {}

        # ... merge data ...
```

**Expected Impact:** 60% reduction in deps.dev collection time.

### 3. Add HTTP Connection Pooling (HIGH PRIORITY)

**Location:** `functions/collectors/` - all collectors

**Problem:** New HTTP client created per request, no connection reuse.

**Current:**
```python
async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
    # Client destroyed after scope
```

**Optimized (module-level client):**
```python
# At module level
_http_client: Optional[httpx.AsyncClient] = None

def get_http_client() -> httpx.AsyncClient:
    """Get or create shared HTTP client with connection pooling."""
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(
            timeout=45.0,
            limits=httpx.Limits(
                max_keepalive_connections=20,
                max_connections=100,
                keepalive_expiry=30.0,
            ),
            http2=True,  # Enable HTTP/2 multiplexing
        )
    return _http_client

# Usage - don't use 'async with', client persists across invocations
async def get_npm_metadata(name: str) -> dict:
    client = get_http_client()
    url = f"{NPM_REGISTRY}/{encode_package_name(name)}"
    resp = await client.get(url)
    return resp.json()
```

**Warning:** Lambda reuses execution context, so the client persists. This is intentional for connection pooling.

**Expected Impact:** 100-200ms reduction per external API call (no TCP/TLS handshake).

### 4. Lazy Initialize boto3 Clients (MEDIUM PRIORITY)

**Location:** All Lambda handlers

**Problem:** boto3 clients initialized at module level, adding to cold start time.

**Current:**
```python
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(PACKAGES_TABLE)
```

**Optimized:**
```python
_dynamodb = None
_table = None

def get_table():
    """Lazy initialize DynamoDB table."""
    global _dynamodb, _table
    if _table is None:
        _dynamodb = boto3.resource("dynamodb")
        _table = _dynamodb.Table(PACKAGES_TABLE)
    return _table

# Usage in handler
def handler(event, context):
    table = get_table()
    response = table.get_item(...)
```

**Expected Impact:** 100-200ms reduction in cold start time.

### 5. Concurrent DynamoDB Batch Reads in Scan (MEDIUM PRIORITY)

**Location:** `functions/api/post_scan.py`

**Problem:** Batch reads are sequential.

**Current:**
```python
for i in range(0, len(dep_list), 25):
    batch = dep_list[i:i + 25]
    response = dynamodb.batch_get_item(...)
    # Process results
```

**Optimized (concurrent batches):**
```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

def _batch_get_sync(batch_keys: list) -> dict:
    """Synchronous batch get for thread pool."""
    response = dynamodb.batch_get_item(
        RequestItems={PACKAGES_TABLE: {"Keys": batch_keys}}
    )
    return response

async def _batch_get_all(all_keys: list) -> list:
    """Fetch all batches concurrently using thread pool."""
    loop = asyncio.get_event_loop()

    # Split into batches of 25 (DynamoDB limit)
    batches = [all_keys[i:i + 25] for i in range(0, len(all_keys), 25)]

    # Use thread pool for concurrent boto3 calls (boto3 is not async-native)
    with ThreadPoolExecutor(max_workers=10) as executor:
        tasks = [
            loop.run_in_executor(executor, _batch_get_sync, batch)
            for batch in batches
        ]
        results = await asyncio.gather(*tasks)

    return results

# In handler
def handler(event, context):
    # ... setup ...

    keys = [{"pk": f"npm#{name}", "sk": "LATEST"} for name in dep_list]

    # Run concurrent batches
    loop = asyncio.new_event_loop()
    try:
        results = loop.run_until_complete(_batch_get_all(keys))
    finally:
        loop.close()

    # ... process results ...
```

**Expected Impact:** 50% reduction in scan latency for large dependency lists.

### 6. Add Response Payload Sparse Fields (LOW PRIORITY)

**Location:** `functions/api/get_package.py`

**Problem:** Full response is ~3KB, but CLI only needs ~300 bytes.

**Implementation:**
```python
def handler(event, context):
    # ... existing logic ...

    # Check for fields parameter
    query_params = event.get("queryStringParameters") or {}
    requested_fields = query_params.get("fields")

    if requested_fields:
        # Parse comma-separated fields
        field_set = set(requested_fields.split(","))

        # Filter response to requested fields
        full_response = build_full_response(item)
        sparse_response = {
            k: v for k, v in full_response.items()
            if k in field_set
        }
        return success_response(sparse_response, headers=cors_headers)

    # ... existing full response logic ...
```

**Usage:**
```
GET /packages/npm/lodash?fields=health_score,risk_level,abandonment_risk
```

**Expected Impact:** 60-80% reduction in response size for CLI requests.

### 7. Add Jitter to Retry Delays (MEDIUM PRIORITY)

**Location:** All collectors - retry logic

**Problem:** No jitter causes thundering herd when multiple Lambdas retry simultaneously.

**Current:**
```python
delay = 2 ** attempt
await asyncio.sleep(delay)
```

**Optimized:**
```python
import random

base_delay = 2 ** attempt
jitter = random.uniform(0, base_delay * 0.3)  # 0-30% jitter
delay = base_delay + jitter
await asyncio.sleep(delay)
```

**Expected Impact:** Prevents thundering herd, more even load distribution.

## Files to Modify

| File | Changes |
|------|---------|
| `functions/api/get_package.py` | Add in-Lambda cache, sparse fields |
| `functions/api/post_scan.py` | Concurrent batch reads |
| `functions/collectors/depsdev_collector.py` | Parallel API calls |
| `functions/collectors/npm_collector.py` | Connection pooling, jitter |
| `functions/collectors/github_collector.py` | Connection pooling, jitter |
| `functions/collectors/bundlephobia_collector.py` | Connection pooling, jitter |
| `functions/collectors/package_collector.py` | Use shared HTTP client |

## Testing Requirements

After optimizations:
```bash
cd /home/iebt/projects/startup-experiment/work/dephealth
pytest tests/ -v
```

Performance testing:
```bash
# Measure cold start
aws lambda update-function-configuration \
  --function-name dephealth-GetPackageHandler \
  --environment Variables={FORCE_COLD_START=$(date +%s)}

time curl https://api.dephealth.laranjo.dev/v1/packages/npm/lodash \
  -H "X-API-Key: your-key"

# Measure warm request
for i in {1..10}; do
  time curl https://api.dephealth.laranjo.dev/v1/packages/npm/lodash \
    -H "X-API-Key: your-key" 2>&1 | grep real
done
```

## Success Criteria

1. In-Lambda caching implemented for GET /packages
2. deps.dev calls parallelized (3 of 4 calls parallel)
3. HTTP connection pooling in all collectors
4. Lazy boto3 initialization in handlers
5. Concurrent batch reads in scan endpoint
6. Sparse fields support for API responses
7. Jitter added to all retry logic
8. All existing tests pass
9. P50 latency reduced from 150ms to <50ms (cached)
10. Collection time reduced from 3s to <1.5s per package

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 7 for full performance analysis.
