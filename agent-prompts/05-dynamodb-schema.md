# Agent Prompt: DynamoDB Schema Improvements

## Context

You are working on DepHealth, a dependency health intelligence platform. The DynamoDB schema needs improvements for efficiency, correctness, and scalability.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 5: DynamoDB Schema Review)

## Your Mission

Fix schema issues, add missing GSIs, enable TTL, and improve query efficiency across the DynamoDB tables.

## Current Schema

### Packages Table (`dephealth-packages`)
| PK Pattern | SK | Purpose |
|------------|----|---------|
| `{ecosystem}#{name}` | `LATEST` | Current package data |

**GSIs:**
- `risk-level-index` (risk_level → last_updated) - ALL projection
- `tier-index` (tier → last_updated) - KEYS_ONLY projection

### API Keys Table (`dephealth-api-keys`)
| PK Pattern | SK | Purpose |
|------------|----|---------|
| `user_{email_hash}` | `{key_hash}` | API key record |
| `user_{email_hash}` | `PENDING` | Unverified signup |
| `demo#{ip}` | `hour#{hour}` | Demo rate limiting |
| `github_rate_limit#{shard}` | `{window}` | GitHub rate limiting |
| `SYSTEM#RESET_STATE` | `monthly_reset` | Reset checkpoint |
| `FAILED#{name}` | `{timestamp}` | Permanent DLQ failures |

**GSIs:**
- `key-hash-index` (key_hash) - ALL projection
- `email-index` (email) - ALL projection
- `verification-token-index` (verification_token) - KEYS_ONLY projection
- `stripe-customer-index` (stripe_customer_id) - ALL projection

## Critical Fixes

### 1. Add magic-token-index GSI (CRITICAL)

**Location:** `infrastructure/lib/storage-stack.ts`

**Problem:** `auth_callback.py:88-93` uses table scan to find users by magic token.

**Solution:** Add GSI on `magic_token` field:

```typescript
// In apiKeysTable definition
globalSecondaryIndexes: [
  // ... existing GSIs ...
  {
    indexName: "magic-token-index",
    partitionKey: {
      name: "magic_token",
      type: dynamodb.AttributeType.STRING,
    },
    projectionType: dynamodb.ProjectionType.KEYS_ONLY,
  },
],
```

**Also update attribute definitions:**
```typescript
const apiKeysTable = new dynamodb.Table(this, "ApiKeysTable", {
  // ... existing config ...
});

// Add attribute for GSI
apiKeysTable.addGlobalSecondaryIndex({
  indexName: "magic-token-index",
  partitionKey: {
    name: "magic_token",
    type: dynamodb.AttributeType.STRING,
  },
  projectionType: dynamodb.ProjectionType.KEYS_ONLY,
});
```

**Then update `auth_callback.py`:**
```python
# Replace scan with GSI query
response = table.query(
    IndexName="magic-token-index",
    KeyConditionExpression=Key("magic_token").eq(token),
)

if not response.get("Items"):
    return _error_response(...)

# Get pk/sk from GSI result, then fetch full item
pk = response["Items"][0]["pk"]
sk = response["Items"][0]["sk"]
full_item = table.get_item(Key={"pk": pk, "sk": sk})
user = full_item.get("Item")
```

### 2. Enable TTL on API Keys Table (CRITICAL)

**Location:** `infrastructure/lib/storage-stack.ts`

**Problem:** TTL attribute is set in code but NOT enabled on table.

**Solution:**
```typescript
const apiKeysTable = new dynamodb.Table(this, "ApiKeysTable", {
  // ... existing config ...
  timeToLiveAttribute: "ttl",  // Add this line
});
```

**Verification:** After deployment, PENDING records with `ttl` attribute will auto-expire.

### 3. Handle UnprocessedKeys in Batch Operations (HIGH)

**Location:** `functions/shared/dynamo.py`

**Problem:** `batch_get_packages()` doesn't handle `UnprocessedKeys`.

**Current code (incomplete):**
```python
def batch_get_packages(ecosystem: str, names: list[str]) -> dict[str, dict]:
    for i in range(0, len(names), batch_size):
        batch_names = names[i : i + batch_size]
        keys = [{"pk": f"{ecosystem}#{name}", "sk": "LATEST"} for name in batch_names]
        response = dynamodb.batch_get_item(RequestItems={PACKAGES_TABLE: {"Keys": keys}})
        # BUG: UnprocessedKeys not handled!
```

**Fixed code:**
```python
def batch_get_packages(ecosystem: str, names: list[str]) -> dict[str, dict]:
    """
    Batch get packages with proper UnprocessedKeys handling.
    """
    results = {}
    batch_size = 100  # DynamoDB limit

    for i in range(0, len(names), batch_size):
        batch_names = names[i : i + batch_size]
        keys = [{"pk": f"{ecosystem}#{name}", "sk": "LATEST"} for name in batch_names]

        request_items = {PACKAGES_TABLE: {"Keys": keys}}

        while request_items:
            response = dynamodb.batch_get_item(RequestItems=request_items)

            # Process returned items
            for item in response.get("Responses", {}).get(PACKAGES_TABLE, []):
                name = item["pk"].split("#", 1)[1]
                results[name] = item

            # Handle UnprocessedKeys with exponential backoff
            unprocessed = response.get("UnprocessedKeys", {})
            if unprocessed:
                logger.warning(f"Retrying {len(unprocessed.get(PACKAGES_TABLE, {}).get('Keys', []))} unprocessed keys")
                time.sleep(0.1)  # Brief backoff
                request_items = unprocessed
            else:
                request_items = None

    return results
```

### 4. Add Conditional Magic Token Consumption (HIGH)

**Location:** `functions/api/auth_callback.py`

**Problem:** Magic token clear is not atomic (see Security prompt for details).

**Solution:**
```python
# Line 124-129 - Add ConditionExpression
try:
    table.update_item(
        Key={"pk": user_id, "sk": user["sk"]},
        UpdateExpression="REMOVE magic_token, magic_expires SET last_login = :now",
        ConditionExpression="attribute_exists(magic_token) AND magic_token = :expected",
        ExpressionAttributeValues={
            ":now": datetime.now(timezone.utc).isoformat(),
            ":expected": token,  # The token we just validated
        },
    )
except ClientError as e:
    if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
        # Token was already consumed (replay attack or race condition)
        logger.warning(f"Magic token already consumed for {user_id}")
        return _error_response(400, "token_already_used", "This login link has already been used")
    raise
```

### 5. Add TTL to Permanent DLQ Failures (MEDIUM)

**Location:** `functions/collectors/dlq_processor.py`

**Problem:** `FAILED#` records never expire.

**Solution in `_store_permanent_failure()`:**
```python
def _store_permanent_failure(body: dict, message_id: str, last_error: str) -> None:
    """Store permanently failed message for manual review."""
    table = dynamodb.Table(API_KEYS_TABLE)

    now = datetime.now(timezone.utc)
    ttl_90_days = int((now + timedelta(days=90)).timestamp())

    table.put_item(Item={
        "pk": f"FAILED#{body.get('name', 'unknown')}",
        "sk": now.isoformat(),
        "ecosystem": body.get("ecosystem"),
        "name": body.get("name"),
        "message_id": message_id,
        "last_error": last_error,
        "retry_count": body.get("_retry_count", 0),
        "original_message": json.dumps(body),
        "failed_at": now.isoformat(),
        "ttl": ttl_90_days,  # Auto-cleanup after 90 days
    })
```

### 6. Reduce GSI Projection Size (LOW - Optimization)

**Location:** `infrastructure/lib/storage-stack.ts`

**Problem:** `risk-level-index` uses ALL projection, duplicating entire items.

**Solution:** Change to KEYS_ONLY and fetch full items when needed:
```typescript
{
  indexName: "risk-level-index",
  partitionKey: { name: "risk_level", type: dynamodb.AttributeType.STRING },
  sortKey: { name: "last_updated", type: dynamodb.AttributeType.STRING },
  projectionType: dynamodb.ProjectionType.KEYS_ONLY,  // Changed from ALL
},
```

**Note:** This requires updating any code that queries this GSI to then fetch full items.

## Files to Modify

| File | Changes |
|------|---------|
| `infrastructure/lib/storage-stack.ts` | Add magic-token-index GSI, enable TTL |
| `functions/api/auth_callback.py` | Use GSI query, add conditional expression |
| `functions/shared/dynamo.py` | Handle UnprocessedKeys |
| `functions/collectors/dlq_processor.py` | Add TTL to permanent failures |
| `tests/conftest.py` | Add magic-token-index to mock DynamoDB |
| `tests/test_integration_flows.py` | Update integration test fixtures |

## Test Fixture Updates

**Location:** `tests/conftest.py`

Add the new GSI to mock DynamoDB fixture:
```python
@pytest.fixture
def mock_dynamodb():
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

        # API Keys table with all GSIs
        dynamodb.create_table(
            TableName="dephealth-api-keys",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "key_hash", "AttributeType": "S"},
                {"AttributeName": "email", "AttributeType": "S"},
                {"AttributeName": "verification_token", "AttributeType": "S"},
                {"AttributeName": "stripe_customer_id", "AttributeType": "S"},
                {"AttributeName": "magic_token", "AttributeType": "S"},  # NEW
            ],
            GlobalSecondaryIndexes=[
                # ... existing GSIs ...
                {
                    "IndexName": "magic-token-index",
                    "KeySchema": [{"AttributeName": "magic_token", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "KEYS_ONLY"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        yield dynamodb
```

## Deployment Considerations

### Adding GSI to Existing Table
- GSI addition is a safe operation
- Backfill happens automatically
- No downtime required
- May take time for large tables

### Enabling TTL
- Safe operation, no downtime
- Items with past TTL values will start expiring within 48 hours
- DynamoDB deletes items eventually (not immediately at TTL time)

## Success Criteria

1. magic-token-index GSI created and deployed
2. auth_callback.py uses GSI query instead of scan
3. TTL enabled on API keys table
4. UnprocessedKeys properly handled in batch operations
5. Conditional expression on magic token consumption
6. TTL added to permanent DLQ failures
7. All existing tests pass
8. Test fixtures updated with new GSI

## Testing Requirements

```bash
cd /home/iebt/projects/startup-experiment/work/dephealth
pytest tests/ -v
```

Specifically test auth flows:
```bash
pytest tests/test_auth_handlers.py tests/test_integration_flows.py -v
```

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 5 for full DynamoDB analysis.
