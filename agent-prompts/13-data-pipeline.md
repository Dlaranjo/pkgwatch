# Agent Prompt: Data Pipeline Reliability Improvements

## Context

You are working on DepHealth, a dependency health intelligence platform. The data collection pipeline needs improvements for reliability, efficiency, and observability.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 13: Data Pipeline Review)

## Your Mission

Improve the data collection pipeline's reliability, fix race conditions, add input validation, and improve error handling.

## Current Pipeline Architecture

```
EventBridge Schedule → Refresh Dispatcher → SQS Queue → Package Collector
                                                              ↓
                                              deps.dev, npm, GitHub, Bundlephobia
                                                              ↓
                                                    DynamoDB + S3
                                                              ↓
                                              DynamoDB Streams → Score Calculator
```

### Key Files
- `functions/collectors/package_collector.py` - Main orchestrator
- `functions/collectors/refresh_dispatcher.py` - Schedule trigger
- `functions/collectors/dlq_processor.py` - Dead letter queue
- `functions/collectors/github_collector.py` - GitHub API
- `functions/collectors/npm_collector.py` - npm registry
- `functions/collectors/depsdev_collector.py` - deps.dev API
- `infrastructure/lib/pipeline-stack.ts` - SQS configuration

## Critical Improvements

### 1. Fix GitHub Rate Limit Race Condition (CRITICAL)

**Location:** `functions/collectors/package_collector.py`

**Problem:** Read-then-write pattern allows exceeding rate limit.

**Current (vulnerable):**
```python
def _check_and_increment_github_rate_limit() -> bool:
    total_calls = _get_total_github_calls(window_key)  # READ
    if total_calls >= GITHUB_HOURLY_LIMIT:
        return False
    # RACE WINDOW: Another Lambda could read same value
    table.update_item(...)  # WRITE
```

**Fix with atomic conditional update:**
```python
def _check_and_increment_github_rate_limit() -> bool:
    """
    Atomically check and increment GitHub rate limit.

    Uses conditional expression to prevent race conditions.
    Each shard has its own limit to distribute load.
    """
    table = dynamodb.Table(API_KEYS_TABLE)
    window_key = _get_rate_limit_window_key()
    shard_id = random.randint(0, RATE_LIMIT_SHARDS - 1)

    # Per-shard limit with buffer for edge cases
    per_shard_limit = (GITHUB_HOURLY_LIMIT // RATE_LIMIT_SHARDS) + 50

    now = datetime.now(timezone.utc)
    ttl = int(now.timestamp()) + 7200  # 2 hour TTL

    try:
        # Atomic increment with conditional check
        table.update_item(
            Key={
                "pk": f"github_rate_limit#{shard_id}",
                "sk": window_key,
            },
            UpdateExpression="SET calls = if_not_exists(calls, :zero) + :one, #ttl = :ttl",
            ConditionExpression="attribute_not_exists(calls) OR calls < :limit",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={
                ":zero": 0,
                ":one": 1,
                ":limit": per_shard_limit,
                ":ttl": ttl,
            },
        )
        return True

    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Rate limit exceeded for this shard
            logger.warning(
                f"GitHub rate limit exceeded",
                extra={
                    "shard_id": shard_id,
                    "window_key": window_key,
                    "per_shard_limit": per_shard_limit,
                }
            )
            return False

        logger.error(f"DynamoDB error in rate limit check: {e}")
        # Fail closed for safety
        return False
```

### 2. Add Input Validation for SQS Messages (HIGH PRIORITY)

**Location:** `functions/collectors/package_collector.py`

**Problem:** No validation of message format.

**Add validation function:**
```python
import re
from typing import Optional, Tuple

# Valid npm package name pattern
# Scoped: @scope/package-name
# Unscoped: package-name
NPM_PACKAGE_PATTERN = re.compile(
    r'^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$'
)

# Maximum package name length per npm
MAX_PACKAGE_NAME_LENGTH = 214


def validate_message(body: dict) -> Tuple[bool, Optional[str]]:
    """
    Validate SQS message body.

    Args:
        body: Parsed message body

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check required fields
    ecosystem = body.get("ecosystem")
    name = body.get("name")

    if not ecosystem:
        return False, "Missing 'ecosystem' field"

    if not name:
        return False, "Missing 'name' field"

    # Validate ecosystem
    if ecosystem not in ["npm"]:  # Add more as supported
        return False, f"Unsupported ecosystem: {ecosystem}"

    # Validate package name
    if len(name) > MAX_PACKAGE_NAME_LENGTH:
        return False, f"Package name too long: {len(name)} > {MAX_PACKAGE_NAME_LENGTH}"

    if not NPM_PACKAGE_PATTERN.match(name):
        return False, f"Invalid package name format: {name}"

    # Check for path traversal attempts
    if ".." in name or name.startswith("/"):
        return False, f"Invalid package name (path traversal): {name}"

    return True, None


# Update process_single_package to use validation:
async def process_single_package(message: dict) -> Tuple[bool, Optional[str]]:
    """Process a single package from SQS message."""
    body = message

    # Validate input
    is_valid, error = validate_message(body)
    if not is_valid:
        logger.warning(f"Invalid message: {error}", extra={"body": body})
        return False, error

    ecosystem = body["ecosystem"]
    name = body["name"]
    tier = body.get("tier", 3)

    # Continue with collection...
```

### 3. Add Error Classification in DLQ Processor (HIGH PRIORITY)

**Location:** `functions/collectors/dlq_processor.py`

See Error Handling prompt (09) for full implementation.

Key changes:
```python
TRANSIENT_ERRORS = ["timeout", "503", "502", "504", "rate limit", "connection"]
PERMANENT_ERRORS = ["404", "not found", "invalid package", "forbidden"]

def classify_error(error_message: str) -> str:
    """Classify error as transient or permanent."""
    error_lower = error_message.lower()

    for pattern in PERMANENT_ERRORS:
        if pattern in error_lower:
            return "permanent"

    for pattern in TRANSIENT_ERRORS:
        if pattern in error_lower:
            return "transient"

    return "unknown"
```

### 4. Add Jitter to Scheduled Refreshes (MEDIUM PRIORITY)

**Location:** `functions/collectors/refresh_dispatcher.py`

**Problem:** All packages dispatched simultaneously can overwhelm SQS.

**Add jitter to message delays:**
```python
import random

def dispatch_packages(tier: int, packages: list) -> dict:
    """Dispatch packages for collection with jitter."""
    batch_size = 10
    total_dispatched = 0

    for i in range(0, len(packages), batch_size):
        batch = packages[i:i + batch_size]
        entries = []

        for j, pkg in enumerate(batch):
            # Add random jitter (0-60 seconds) to spread load
            jitter = random.randint(0, 60)

            entries.append({
                "Id": str(i + j),
                "MessageBody": json.dumps({
                    "ecosystem": pkg["ecosystem"],
                    "name": pkg["name"],
                    "tier": tier,
                }),
                "DelaySeconds": jitter,
            })

        response = sqs.send_message_batch(
            QueueUrl=QUEUE_URL,
            Entries=entries,
        )

        successful = len(response.get("Successful", []))
        total_dispatched += successful

        if response.get("Failed"):
            logger.error(
                f"Failed to dispatch {len(response['Failed'])} messages",
                extra={"failed": response["Failed"]}
            )

    return {"dispatched": total_dispatched, "total": len(packages)}
```

### 5. Improve Graceful Degradation (MEDIUM PRIORITY)

**Location:** `functions/collectors/package_collector.py`

**Current:** All sources collected, errors logged but no fallback.

**Improved with stale data fallback:**
```python
async def collect_package_data(ecosystem: str, name: str) -> dict:
    """
    Collect package data with graceful degradation and stale fallback.
    """
    combined_data = {
        "ecosystem": ecosystem,
        "name": name,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "sources": [],
        "data_freshness": "fresh",
    }

    # Try primary source (deps.dev)
    try:
        depsdev_data = await get_depsdev_info(name, ecosystem)
        if depsdev_data:
            combined_data["sources"].append("deps.dev")
            _merge_depsdev_data(combined_data, depsdev_data)
    except Exception as e:
        logger.error(f"deps.dev failed for {ecosystem}/{name}: {e}")
        combined_data["depsdev_error"] = str(e)

        # Try to use stale data as fallback
        existing = await _get_existing_package_data(ecosystem, name)
        if existing and _is_data_acceptable(existing, max_age_days=7):
            logger.info(f"Using stale data for {ecosystem}/{name}")
            combined_data.update(_extract_cached_fields(existing))
            combined_data["data_freshness"] = "stale"
            combined_data["stale_reason"] = "deps.dev_unavailable"

    # Continue with secondary sources...
    # npm and bundlephobia run in parallel
    npm_task = get_npm_metadata(name)
    bundle_task = get_bundle_size(name)
    npm_result, bundle_result = await asyncio.gather(
        npm_task, bundle_task, return_exceptions=True
    )

    if not isinstance(npm_result, Exception) and npm_result:
        combined_data["sources"].append("npm")
        _merge_npm_data(combined_data, npm_result)
    else:
        combined_data["npm_error"] = str(npm_result)

    if not isinstance(bundle_result, Exception) and bundle_result:
        combined_data["sources"].append("bundlephobia")
        combined_data["bundle_size"] = bundle_result

    # GitHub is conditional on rate limit
    if GITHUB_CIRCUIT.can_execute() and _check_and_increment_github_rate_limit():
        try:
            github_data = await get_github_data(combined_data)
            if github_data:
                combined_data["sources"].append("github")
                _merge_github_data(combined_data, github_data)
                GITHUB_CIRCUIT.record_success()
        except Exception as e:
            logger.error(f"GitHub failed for {ecosystem}/{name}: {e}")
            combined_data["github_error"] = str(e)
            GITHUB_CIRCUIT.record_failure(e)

    return combined_data


async def _get_existing_package_data(ecosystem: str, name: str) -> Optional[dict]:
    """Get existing package data from DynamoDB."""
    table = dynamodb.Table(PACKAGES_TABLE)
    try:
        response = table.get_item(Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"})
        return response.get("Item")
    except Exception as e:
        logger.error(f"Failed to get existing data: {e}")
        return None


def _is_data_acceptable(data: dict, max_age_days: int) -> bool:
    """Check if existing data is fresh enough to use as fallback."""
    if not data:
        return False

    last_updated = data.get("last_updated")
    if not last_updated:
        return False

    try:
        updated_dt = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
        age = datetime.now(timezone.utc) - updated_dt
        return age.days <= max_age_days
    except Exception:
        return False
```

### 6. Add Pipeline Metrics (MEDIUM PRIORITY)

**Location:** `functions/collectors/package_collector.py`

```python
from shared.metrics import emit_metric

async def process_batch(records: list) -> Tuple[int, int]:
    """Process a batch of SQS records with metrics."""
    start_time = time.time()
    successes = 0
    failures = 0

    for record in records:
        try:
            body = json.loads(record["body"])
            result = await process_single_package(body)
            if result[0]:
                successes += 1
                emit_metric(
                    "PackagesCollected",
                    dimensions={"Ecosystem": body.get("ecosystem", "unknown")}
                )
            else:
                failures += 1
                emit_metric(
                    "CollectionFailures",
                    dimensions={
                        "Ecosystem": body.get("ecosystem", "unknown"),
                        "Reason": result[1][:50] if result[1] else "unknown",
                    }
                )
        except Exception as e:
            failures += 1
            logger.error(f"Failed to process record: {e}")

    # Emit batch metrics
    batch_duration = time.time() - start_time
    emit_metric("BatchProcessingTime", batch_duration, unit="Seconds")
    emit_metric("BatchSize", len(records))

    return successes, failures
```

### 7. Add Message Deduplication (LOW PRIORITY)

**Problem:** Same package could be processed multiple times if dispatcher runs twice.

**Solution 1: Use SQS FIFO Queue**
```typescript
// In pipeline-stack.ts
const packageQueue = new sqs.Queue(this, "PackageQueue", {
  queueName: "dephealth-package-queue.fifo",
  fifo: true,
  contentBasedDeduplication: true,  // Dedupe by message content hash
  visibilityTimeout: cdk.Duration.minutes(6),
});
```

**Solution 2: Check last_updated before processing**
```python
async def process_single_package(body: dict) -> Tuple[bool, Optional[str]]:
    """Process package with deduplication check."""
    ecosystem = body["ecosystem"]
    name = body["name"]

    # Check if recently collected
    existing = await _get_existing_package_data(ecosystem, name)
    if existing:
        last_updated = existing.get("last_updated")
        if last_updated:
            updated_dt = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
            age_minutes = (datetime.now(timezone.utc) - updated_dt).total_seconds() / 60

            if age_minutes < 30:  # Skip if updated in last 30 minutes
                logger.info(f"Skipping {ecosystem}/{name} - recently updated ({age_minutes:.0f}m ago)")
                return True, None  # Success - no action needed

    # Continue with collection...
```

### 8. Add Health Check Endpoint for Pipeline (LOW PRIORITY)

**Create:** `functions/collectors/pipeline_health.py`

```python
"""
Pipeline health check endpoint.

Checks:
- SQS queue depth
- DLQ message count
- Recent collection success rate
- GitHub rate limit status
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3

logger = logging.getLogger(__name__)

sqs = boto3.client("sqs")
cloudwatch = boto3.client("cloudwatch")

QUEUE_URL = os.environ.get("PACKAGE_QUEUE_URL")
DLQ_URL = os.environ.get("DLQ_URL")


def handler(event, context):
    """Return pipeline health status."""
    health = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {},
    }

    # Check main queue depth
    try:
        attrs = sqs.get_queue_attributes(
            QueueUrl=QUEUE_URL,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"]
        )
        queue_depth = int(attrs["Attributes"].get("ApproximateNumberOfMessages", 0))
        in_flight = int(attrs["Attributes"].get("ApproximateNumberOfMessagesNotVisible", 0))

        health["checks"]["main_queue"] = {
            "status": "healthy" if queue_depth < 1000 else "degraded",
            "depth": queue_depth,
            "in_flight": in_flight,
        }

        if queue_depth >= 1000:
            health["status"] = "degraded"
    except Exception as e:
        health["checks"]["main_queue"] = {"status": "error", "error": str(e)}
        health["status"] = "unhealthy"

    # Check DLQ
    try:
        attrs = sqs.get_queue_attributes(
            QueueUrl=DLQ_URL,
            AttributeNames=["ApproximateNumberOfMessages"]
        )
        dlq_depth = int(attrs["Attributes"].get("ApproximateNumberOfMessages", 0))

        health["checks"]["dlq"] = {
            "status": "healthy" if dlq_depth < 10 else "degraded" if dlq_depth < 100 else "unhealthy",
            "depth": dlq_depth,
        }

        if dlq_depth >= 100:
            health["status"] = "unhealthy"
        elif dlq_depth >= 10:
            health["status"] = "degraded"
    except Exception as e:
        health["checks"]["dlq"] = {"status": "error", "error": str(e)}

    # Check GitHub rate limit
    try:
        # Get current hour's usage across all shards
        # Implementation depends on how you expose this
        health["checks"]["github_rate_limit"] = {
            "status": "healthy",
            "note": "Check CloudWatch for details",
        }
    except Exception as e:
        health["checks"]["github_rate_limit"] = {"status": "error", "error": str(e)}

    return {
        "statusCode": 200 if health["status"] == "healthy" else 503,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(health),
    }
```

## Files to Modify

| File | Changes |
|------|---------|
| `functions/collectors/package_collector.py` | Fix race condition, add validation, improve degradation |
| `functions/collectors/refresh_dispatcher.py` | Add jitter |
| `functions/collectors/dlq_processor.py` | Add error classification |
| `infrastructure/lib/pipeline-stack.ts` | Consider FIFO queue |

## Files to Create

| File | Purpose |
|------|---------|
| `functions/collectors/pipeline_health.py` | Health check endpoint |

## Success Criteria

1. GitHub rate limit race condition fixed
2. Input validation for all SQS messages
3. Error classification in DLQ processor
4. Jitter added to scheduled refreshes
5. Stale data fallback implemented
6. Pipeline metrics being emitted
7. All existing tests pass
8. New tests for validation and race conditions

## Testing Requirements

```bash
cd /home/iebt/projects/startup-experiment/work/dephealth
pytest tests/test_collectors.py -v
```

Add tests for:
- Message validation
- Rate limit atomic operation
- Error classification
- Stale data fallback

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 13 for full data pipeline analysis.
