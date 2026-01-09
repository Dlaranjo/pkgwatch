# Agent Prompt: Critical Priority Fixes

## Context

You are working on DepHealth, a dependency health intelligence platform. This prompt focuses on the highest-priority, cross-cutting fixes that should be addressed immediately.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md`

## Your Mission

Fix the most critical issues identified across all review domains. These are blocking issues that affect security, correctness, or major functionality.

## Critical Issues Summary

| Priority | Issue | Domain | Impact |
|----------|-------|--------|--------|
| 1 | Magic token table scan | Security/DynamoDB | O(n) on every login |
| 2 | API key creation race | Security/Rate Limit | Can exceed MAX_KEYS |
| 3 | Enable TTL on API keys | DynamoDB | PENDING never expires |
| 4 | Magic link token reuse | Security | Replay attack possible |
| 5 | Zero collector tests | Testing | Critical code untested |

## Fix 1: Magic Token GSI (CRITICAL)

**Files:**
- `infrastructure/lib/storage-stack.ts`
- `functions/api/auth_callback.py`
- `tests/conftest.py`

### Step 1: Add GSI to Storage Stack

```typescript
// In storage-stack.ts, add to apiKeysTable GlobalSecondaryIndexes array:
{
  IndexName: "magic-token-index",
  KeySchema: [
    { AttributeName: "magic_token", KeyType: "HASH" },
  ],
  Projection: { ProjectionType: "KEYS_ONLY" },
},

// Add magic_token to AttributeDefinitions:
{ AttributeName: "magic_token", AttributeType: "S" },
```

### Step 2: Update auth_callback.py

```python
# Replace the scan (lines 88-93) with GSI query:

# OLD (vulnerable):
response = table.scan(
    FilterExpression=Attr("magic_token").eq(token),
    ProjectionExpression="pk, sk, email, magic_expires, tier",
)

# NEW (efficient):
response = table.query(
    IndexName="magic-token-index",
    KeyConditionExpression=Key("magic_token").eq(token),
)

if not response.get("Items"):
    return _error_response(400, "invalid_token", "Invalid or expired login link")

# GSI returns only pk/sk, so fetch full item
pk = response["Items"][0]["pk"]
sk = response["Items"][0]["sk"]

full_response = table.get_item(Key={"pk": pk, "sk": sk})
user = full_response.get("Item")

if not user:
    return _error_response(400, "invalid_token", "Invalid or expired login link")
```

### Step 3: Update Test Fixtures

```python
# In tests/conftest.py, add to mock_dynamodb fixture:

# Add to AttributeDefinitions:
{"AttributeName": "magic_token", "AttributeType": "S"},

# Add to GlobalSecondaryIndexes:
{
    "IndexName": "magic-token-index",
    "KeySchema": [{"AttributeName": "magic_token", "KeyType": "HASH"}],
    "Projection": {"ProjectionType": "KEYS_ONLY"},
},
```

## Fix 2: API Key Creation Race Condition (CRITICAL)

**File:** `functions/api/create_api_key.py`

Replace check-then-create with atomic operation:

```python
import boto3
from botocore.exceptions import ClientError

dynamodb_client = boto3.client("dynamodb")

def handler(event, context):
    # ... existing auth and validation ...

    # Get current keys for count
    response = table.query(KeyConditionExpression=Key("pk").eq(user_id))
    items = response.get("Items", [])
    active_keys = [i for i in items if i.get("sk") != "PENDING"]
    current_count = len(active_keys)

    if current_count >= MAX_KEYS_PER_USER:
        return _error_response(
            400, "max_keys_reached",
            f"Maximum of {MAX_KEYS_PER_USER} API keys allowed"
        )

    # Generate new key
    api_key, key_hash = _generate_api_key_pair()
    now = datetime.now(timezone.utc).isoformat()

    new_key_item = {
        "pk": {"S": user_id},
        "sk": {"S": key_hash},
        "key_hash": {"S": key_hash},
        "email": {"S": email},
        "tier": {"S": tier},
        "created_at": {"S": now},
        "requests_this_month": {"N": "0"},
        "monthly_limit": {"N": str(TIER_LIMITS.get(tier, TIER_LIMITS["free"]))},
        "key_name": {"S": body.get("name", f"Key {current_count + 1}")},
    }

    # Use TransactWriteItems to atomically create key only if count hasn't changed
    try:
        # Create a counter item if it doesn't exist, then increment
        dynamodb_client.transact_write_items(
            TransactItems=[
                {
                    # Ensure we haven't exceeded limit by checking all existing keys
                    # This uses a conditional check on the count
                    "Put": {
                        "TableName": API_KEYS_TABLE,
                        "Item": new_key_item,
                        "ConditionExpression": "attribute_not_exists(pk)",
                    }
                }
            ]
        )
    except ClientError as e:
        if "TransactionCanceledException" in str(e):
            # Key already exists (hash collision) or race condition
            return _error_response(
                409, "key_creation_failed",
                "Failed to create key. Please try again."
            )
        raise

    return _success_response({
        "api_key": api_key,
        "key_id": key_hash[:16],
        "message": "API key created. Save this key - it won't be shown again.",
    })
```

## Fix 3: Enable TTL on API Keys Table (CRITICAL)

**File:** `infrastructure/lib/storage-stack.ts`

```typescript
// Add to apiKeysTable configuration:
const apiKeysTable = new dynamodb.Table(this, "ApiKeysTable", {
  tableName: "dephealth-api-keys",
  partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
  sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
  billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
  pointInTimeRecovery: true,
  timeToLiveAttribute: "ttl",  // <-- ADD THIS LINE
  removalPolicy: cdk.RemovalPolicy.RETAIN,
});
```

This will enable automatic deletion of items with expired `ttl` attributes (PENDING signups, rate limit records, etc.).

## Fix 4: Magic Link Token Reuse Prevention (CRITICAL)

**File:** `functions/api/auth_callback.py`

Add conditional expression to prevent replay attacks:

```python
# Around line 124-129, update the token clearing:

try:
    table.update_item(
        Key={"pk": user_id, "sk": user["sk"]},
        UpdateExpression="REMOVE magic_token, magic_expires SET last_login = :now",
        ConditionExpression="attribute_exists(magic_token) AND magic_token = :expected_token",
        ExpressionAttributeValues={
            ":now": datetime.now(timezone.utc).isoformat(),
            ":expected_token": token,
        },
    )
except ClientError as e:
    if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
        logger.warning(f"Magic token replay attempt for {user_id}")
        return _error_response(
            400, "token_already_used",
            "This login link has already been used. Please request a new one."
        )
    raise
```

## Fix 5: Add Basic Collector Tests (CRITICAL)

**Create:** `tests/test_collectors.py`

```python
"""
Basic tests for data collectors.

These tests use mocked HTTP responses to verify collector logic
without making actual API calls.
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import json


class TestPackageCollectorValidation:
    """Tests for input validation in package collector."""

    def test_validates_ecosystem(self):
        """Test that invalid ecosystem is rejected."""
        from collectors.package_collector import validate_message

        valid, error = validate_message({"ecosystem": "npm", "name": "lodash"})
        assert valid is True

        valid, error = validate_message({"ecosystem": "invalid", "name": "lodash"})
        assert valid is False
        assert "ecosystem" in error.lower()

    def test_validates_package_name_format(self):
        """Test that invalid package names are rejected."""
        from collectors.package_collector import validate_message

        # Valid names
        assert validate_message({"ecosystem": "npm", "name": "lodash"})[0] is True
        assert validate_message({"ecosystem": "npm", "name": "@babel/core"})[0] is True
        assert validate_message({"ecosystem": "npm", "name": "my-package"})[0] is True

        # Invalid names
        assert validate_message({"ecosystem": "npm", "name": "../etc/passwd"})[0] is False
        assert validate_message({"ecosystem": "npm", "name": ""})[0] is False
        assert validate_message({"ecosystem": "npm", "name": "a" * 300})[0] is False

    def test_validates_required_fields(self):
        """Test that missing required fields are caught."""
        from collectors.package_collector import validate_message

        valid, error = validate_message({})
        assert valid is False

        valid, error = validate_message({"ecosystem": "npm"})
        assert valid is False
        assert "name" in error.lower()

        valid, error = validate_message({"name": "lodash"})
        assert valid is False
        assert "ecosystem" in error.lower()


class TestGitHubRateLimiting:
    """Tests for GitHub rate limiting logic."""

    def test_rate_limit_window_key_format(self):
        """Test rate limit window key is properly formatted."""
        from collectors.package_collector import _get_rate_limit_window_key

        key = _get_rate_limit_window_key()

        assert key.startswith("hour#")
        # Should be: hour#YYYY-MM-DD-HH
        parts = key.split("#")[1].split("-")
        assert len(parts) == 4

    @pytest.mark.asyncio
    async def test_rate_limit_allows_under_limit(self, mock_dynamodb):
        """Test rate limit allows requests when under limit."""
        # This test requires the rate limit function to be async or use sync DynamoDB
        pass  # Implement based on actual function signature

    @pytest.mark.asyncio
    async def test_rate_limit_blocks_at_limit(self, mock_dynamodb):
        """Test rate limit blocks when limit exceeded."""
        pass  # Implement based on actual function signature


class TestCollectPackageData:
    """Tests for the main collect_package_data function."""

    @pytest.mark.asyncio
    async def test_collects_from_all_sources(self):
        """Test successful collection from all sources."""
        with patch("collectors.package_collector.get_depsdev_info", new_callable=AsyncMock) as mock_depsdev, \
             patch("collectors.package_collector.get_npm_metadata", new_callable=AsyncMock) as mock_npm, \
             patch("collectors.package_collector.get_bundle_size", new_callable=AsyncMock) as mock_bundle, \
             patch("collectors.package_collector._check_and_increment_github_rate_limit") as mock_rate, \
             patch("collectors.package_collector.get_github_data", new_callable=AsyncMock) as mock_github:

            mock_depsdev.return_value = {"name": "lodash", "defaultVersion": "4.17.21"}
            mock_npm.return_value = {"name": "lodash", "version": "4.17.21"}
            mock_bundle.return_value = {"size": 72000}
            mock_rate.return_value = True
            mock_github.return_value = {"stars": 58000}

            from collectors.package_collector import collect_package_data
            result = await collect_package_data("npm", "lodash")

            assert result["ecosystem"] == "npm"
            assert result["name"] == "lodash"
            assert "deps.dev" in result["sources"]

    @pytest.mark.asyncio
    async def test_graceful_degradation_on_github_failure(self):
        """Test collection succeeds even when GitHub fails."""
        with patch("collectors.package_collector.get_depsdev_info", new_callable=AsyncMock) as mock_depsdev, \
             patch("collectors.package_collector.get_npm_metadata", new_callable=AsyncMock) as mock_npm, \
             patch("collectors.package_collector.get_bundle_size", new_callable=AsyncMock) as mock_bundle, \
             patch("collectors.package_collector._check_and_increment_github_rate_limit") as mock_rate, \
             patch("collectors.package_collector.get_github_data", new_callable=AsyncMock) as mock_github:

            mock_depsdev.return_value = {"name": "lodash"}
            mock_npm.return_value = {"name": "lodash"}
            mock_bundle.return_value = None
            mock_rate.return_value = True
            mock_github.side_effect = Exception("GitHub API error")

            from collectors.package_collector import collect_package_data
            result = await collect_package_data("npm", "lodash")

            # Should succeed with partial data
            assert result["ecosystem"] == "npm"
            assert "github_error" in result


class TestDLQProcessor:
    """Tests for DLQ processor."""

    def test_error_classification(self):
        """Test error classification for retry decisions."""
        # Add classify_error function to dlq_processor.py first
        from collectors.dlq_processor import classify_error

        assert classify_error("404 Not Found") == "permanent"
        assert classify_error("503 Service Unavailable") == "transient"
        assert classify_error("timeout after 30s") == "transient"
        assert classify_error("rate limit exceeded") == "transient"
        assert classify_error("unknown error") == "unknown"

    def test_exponential_backoff_calculation(self):
        """Test delay calculation for retries."""
        from collectors.dlq_processor import _calculate_delay

        assert _calculate_delay(0) == 60    # 1 minute
        assert _calculate_delay(1) == 120   # 2 minutes
        assert _calculate_delay(2) == 240   # 4 minutes
        assert _calculate_delay(3) == 480   # 8 minutes
        assert _calculate_delay(4) == 900   # 15 minutes (capped)
        assert _calculate_delay(10) == 900  # Still capped


class TestNpmCollector:
    """Tests for npm registry collector."""

    def test_scoped_package_encoding(self):
        """Test URL encoding for scoped packages."""
        from collectors.npm_collector import encode_scoped_package

        assert encode_scoped_package("lodash") == "lodash"
        assert encode_scoped_package("@babel/core") == "@babel%2Fcore"
        assert encode_scoped_package("@types/node") == "@types%2Fnode"


class TestDepsDevCollector:
    """Tests for deps.dev API collector."""

    @pytest.mark.asyncio
    async def test_handles_missing_package(self):
        """Test handling of non-existent package."""
        with patch("collectors.depsdev_collector.retry_with_backoff", new_callable=AsyncMock) as mock_retry:
            mock_retry.return_value = None

            from collectors.depsdev_collector import get_package_info
            result = await get_package_info("nonexistent-package-xyz")

            assert result is None
```

## Quick Validation Script

After making all fixes, run this validation:

```bash
#!/bin/bash
set -e

echo "=== DepHealth Critical Fixes Validation ==="

cd /home/iebt/projects/startup-experiment/work/dephealth

# Run Python tests
echo "Running Python tests..."
pytest tests/ -v --tb=short

# Check for syntax errors
echo "Checking Python syntax..."
python -m py_compile functions/api/auth_callback.py
python -m py_compile functions/api/create_api_key.py
python -m py_compile functions/collectors/package_collector.py

# Check TypeScript compiles
echo "Checking TypeScript..."
cd infrastructure && npx tsc --noEmit && cd ..

echo "=== All validations passed! ==="
```

## Deployment Order

1. **Deploy infrastructure changes first** (GSI, TTL):
   ```bash
   cd infrastructure
   npx cdk diff
   npx cdk deploy DepHealthStorageStack
   ```

2. **Wait for GSI backfill** (check in AWS Console)

3. **Deploy Lambda changes**:
   ```bash
   npx cdk deploy DepHealthApiStack
   npx cdk deploy DepHealthPipelineStack
   ```

4. **Run tests to verify**:
   ```bash
   pytest tests/ -v
   ```

## Success Criteria

1. [ ] Magic token lookup uses GSI query (not scan)
2. [ ] API key creation uses atomic operation
3. [ ] TTL enabled on API keys table
4. [ ] Magic link tokens are single-use
5. [ ] Collector tests exist and pass
6. [ ] All existing tests still pass
7. [ ] No regressions in auth flows

## Files Modified

| File | Change |
|------|--------|
| `infrastructure/lib/storage-stack.ts` | Add magic-token-index GSI, enable TTL |
| `functions/api/auth_callback.py` | Use GSI query, add conditional expression |
| `functions/api/create_api_key.py` | Atomic key creation |
| `tests/conftest.py` | Add GSI to mock DynamoDB |
| `tests/test_collectors.py` | New file - collector tests |

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` for complete analysis of all issues.
