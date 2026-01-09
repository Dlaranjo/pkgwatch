# Agent Prompt: Rate Limiting and Billing Improvements

## Context

You are working on DepHealth, a dependency health intelligence platform. The rate limiting and billing system needs fixes for race conditions, usage alerts, and improved user experience.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 10: Rate Limiting/Billing Review)

## Your Mission

Fix race conditions in API key management, add usage alerts, and improve the billing user experience.

## Current Tier System

| Tier | Monthly Limit | Price |
|------|--------------|-------|
| Free | 5,000 | $0 |
| Starter | 25,000 | TBD |
| Pro | 100,000 | TBD |
| Business | 500,000 | TBD |

## Critical Fixes

### 1. Fix API Key Creation Race Condition (CRITICAL)

**Location:** `functions/api/create_api_key.py`

**Problem:** Check-then-create pattern allows exceeding MAX_KEYS_PER_USER.

**Current code (vulnerable):**
```python
response = table.query(KeyConditionExpression=Key("pk").eq(user_id))
active_keys = [i for i in items if i.get("sk") != "PENDING"]
if len(active_keys) >= MAX_KEYS_PER_USER:
    return _error_response(400, "max_keys_reached", ...)
# RACE WINDOW HERE
api_key = generate_api_key(...)
```

**Fix using DynamoDB Transaction:**
```python
from boto3.dynamodb.conditions import Attr

def handler(event, context):
    # ... auth and validation ...

    # Use a transaction to atomically check count and create key
    try:
        # First, get current count
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
        api_key, key_hash = generate_api_key_pair()

        # Create key item
        now = datetime.now(timezone.utc).isoformat()
        new_key_item = {
            "pk": user_id,
            "sk": key_hash,
            "key_hash": key_hash,
            "email": email,
            "tier": tier,
            "created_at": now,
            "requests_this_month": 0,
            "monthly_limit": TIER_LIMITS.get(tier, TIER_LIMITS["free"]),
            "key_name": body.get("name", f"Key {current_count + 1}"),
        }

        # Use conditional put to prevent race condition
        # This will fail if another key was created in the meantime
        table.put_item(
            Item=new_key_item,
            ConditionExpression=(
                "attribute_not_exists(pk) OR "
                f"size(attribute_not_exists(sk)) = :zero"
            ),
            # Alternative: Use a counter attribute on user record
        )

        return success_response({
            "api_key": api_key,
            "key_id": key_hash[:16],
            "message": "API key created successfully. Save this key - it won't be shown again.",
        })

    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Race condition detected - another key was created
            return _error_response(
                409, "concurrent_modification",
                "Another key was created. Please try again."
            )
        raise
```

**Alternative Fix using Counter Attribute:**
```python
def handler(event, context):
    # ... auth and validation ...

    try:
        # Atomically increment key count and check limit in one operation
        response = table.update_item(
            Key={"pk": user_id, "sk": "META"},  # User metadata record
            UpdateExpression="SET key_count = if_not_exists(key_count, :zero) + :one",
            ConditionExpression="attribute_not_exists(key_count) OR key_count < :max",
            ExpressionAttributeValues={
                ":zero": 0,
                ":one": 1,
                ":max": MAX_KEYS_PER_USER,
            },
            ReturnValues="UPDATED_NEW",
        )

        # Count check passed - create the key
        api_key, key_hash = generate_api_key_pair()
        # ... create key item ...

    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return _error_response(
                400, "max_keys_reached",
                f"Maximum of {MAX_KEYS_PER_USER} API keys allowed"
            )
        raise
```

### 2. Fix API Key Revocation Race Condition (CRITICAL)

**Location:** `functions/api/revoke_api_key.py`

**Problem:** Check-then-delete pattern allows deleting last key.

**Fix:**
```python
def handler(event, context):
    # ... auth and validation ...

    try:
        # Use conditional delete to prevent deleting last key
        # First check if this is the target key and user has more than 1
        response = table.query(KeyConditionExpression=Key("pk").eq(user_id))
        items = response.get("Items", [])
        active_keys = [i for i in items if i.get("sk") != "PENDING"]

        if len(active_keys) <= 1:
            return _error_response(
                400, "cannot_revoke_last_key",
                "Cannot revoke your only API key. Create a new one first."
            )

        # Find target key
        target_key = None
        for key in active_keys:
            if key.get("sk", "")[:16] == key_id or key.get("sk") == key_id:
                target_key = key
                break

        if not target_key:
            return _error_response(404, "key_not_found", "API key not found")

        # Delete with condition that ensures we still have other keys
        # This uses a transaction to atomically verify count and delete
        dynamodb_client = boto3.client("dynamodb")
        dynamodb_client.transact_write_items(
            TransactItems=[
                {
                    "ConditionCheck": {
                        "TableName": API_KEYS_TABLE,
                        "Key": {
                            "pk": {"S": user_id},
                            "sk": {"S": "META"},
                        },
                        "ConditionExpression": "key_count > :one",
                        "ExpressionAttributeValues": {
                            ":one": {"N": "1"},
                        },
                    }
                },
                {
                    "Delete": {
                        "TableName": API_KEYS_TABLE,
                        "Key": {
                            "pk": {"S": user_id},
                            "sk": {"S": target_key["sk"]},
                        },
                    }
                },
                {
                    "Update": {
                        "TableName": API_KEYS_TABLE,
                        "Key": {
                            "pk": {"S": user_id},
                            "sk": {"S": "META"},
                        },
                        "UpdateExpression": "SET key_count = key_count - :one",
                        "ExpressionAttributeValues": {
                            ":one": {"N": "1"},
                        },
                    }
                },
            ]
        )

        return success_response({"message": "API key revoked successfully"})

    except ClientError as e:
        if e.response["Error"]["Code"] == "TransactionCanceledException":
            # Check which condition failed
            return _error_response(
                400, "cannot_revoke_last_key",
                "Cannot revoke your only API key"
            )
        raise
```

### 3. Add Usage Alerts (HIGH PRIORITY)

**Location:** `functions/api/get_package.py` and `functions/api/post_scan.py`

**Implementation:**
```python
def check_usage_alerts(user: dict, current_usage: int) -> Optional[dict]:
    """
    Check if user is approaching rate limit and return alert info.

    Returns dict with alert level and message if applicable, None otherwise.
    """
    limit = user.get("monthly_limit", 5000)
    usage_percent = (current_usage / limit) * 100

    if usage_percent >= 100:
        return {
            "level": "exceeded",
            "percent": 100,
            "message": f"Monthly limit exceeded. Upgrade at https://dephealth.laranjo.dev/pricing",
        }
    elif usage_percent >= 95:
        return {
            "level": "critical",
            "percent": round(usage_percent, 1),
            "message": f"Only {limit - current_usage} requests remaining this month",
        }
    elif usage_percent >= 80:
        return {
            "level": "warning",
            "percent": round(usage_percent, 1),
            "message": f"{round(100 - usage_percent, 1)}% of monthly quota remaining",
        }

    return None


# In handler, add alert headers to response:
def handler(event, context):
    # ... existing logic ...

    # Check for usage alerts
    alert = check_usage_alerts(user, authenticated_usage_count)
    if alert:
        response_headers["X-Usage-Alert"] = alert["level"]
        response_headers["X-Usage-Percent"] = str(alert["percent"])

        # Also include in response body for API consumers
        response_data["usage_alert"] = alert

    return success_response(response_data, headers=response_headers)
```

### 4. Add Usage Reset on Tier Upgrade (HIGH PRIORITY)

**Location:** `functions/api/stripe_webhook.py`

**Current behavior:** Usage is NOT reset when tier upgrades, which is confusing.

**Fix in `_update_user_tier()`:**
```python
def _update_user_tier(
    email: str,
    tier: str,
    customer_id: str = None,
    subscription_id: str = None,
    reset_usage: bool = False,
) -> None:
    """
    Update user tier across all their API keys.

    Args:
        email: User email
        tier: New tier name
        customer_id: Stripe customer ID
        subscription_id: Stripe subscription ID
        reset_usage: If True, reset requests_this_month to 0
    """
    table = dynamodb.Table(API_KEYS_TABLE)

    # Query all items for this user by email
    response = table.query(
        IndexName="email-index",
        KeyConditionExpression=Key("email").eq(email),
    )
    items = response.get("Items", [])

    new_limit = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

    for item in items:
        if item.get("sk") == "PENDING":
            continue

        update_expression = "SET tier = :tier, monthly_limit = :limit"
        expression_values = {
            ":tier": tier,
            ":limit": new_limit,
        }

        if customer_id:
            update_expression += ", stripe_customer_id = :customer"
            expression_values[":customer"] = customer_id

        if subscription_id:
            update_expression += ", subscription_id = :sub"
            expression_values[":sub"] = subscription_id

        if reset_usage:
            update_expression += ", requests_this_month = :zero"
            expression_values[":zero"] = 0
            logger.info(f"Resetting usage for {item['pk']} on tier upgrade to {tier}")

        table.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values,
        )

    logger.info(f"Updated {len(items)} keys for {email} to tier {tier}")


# In _handle_checkout_completed(), call with reset_usage=True for upgrades:
def _handle_checkout_completed(event_data: dict) -> dict:
    # ... existing logic ...

    # Check if this is an upgrade (existing customer) vs new signup
    is_upgrade = customer_id and _customer_exists(customer_id)

    _update_user_tier(
        email=email,
        tier=tier,
        customer_id=customer_id,
        subscription_id=subscription_id,
        reset_usage=is_upgrade,  # Reset usage on upgrade
    )

    return {"statusCode": 200, "body": json.dumps({"status": "success"})}
```

### 5. Add X-RateLimit-Reset Header (MEDIUM PRIORITY)

**Location:** `functions/api/get_package.py` and `functions/api/post_scan.py`

**Implementation:**
```python
from datetime import datetime, timezone
import calendar

def get_reset_timestamp() -> int:
    """Get Unix timestamp for start of next month (when usage resets)."""
    now = datetime.now(timezone.utc)

    # First day of next month
    if now.month == 12:
        next_month = datetime(now.year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        next_month = datetime(now.year, now.month + 1, 1, tzinfo=timezone.utc)

    return int(next_month.timestamp())


# In handler, add to response headers:
response_headers["X-RateLimit-Reset"] = str(get_reset_timestamp())
```

### 6. Fix GitHub Rate Limit Race Condition (MEDIUM PRIORITY)

**Location:** `functions/collectors/package_collector.py`

**Problem:** Read-then-write pattern for rate limit check.

**Fix using atomic conditional update:**
```python
def _check_and_increment_github_rate_limit_atomic() -> bool:
    """
    Atomically check and increment GitHub rate limit using conditional expression.

    Returns True if request is allowed, False if rate limit exceeded.
    """
    table = dynamodb.Table(API_KEYS_TABLE)
    window_key = _get_rate_limit_window_key()
    shard_id = random.randint(0, RATE_LIMIT_SHARDS - 1)

    # Per-shard limit with some buffer
    per_shard_limit = (GITHUB_HOURLY_LIMIT // RATE_LIMIT_SHARDS) + 50

    try:
        # Atomic increment with limit check
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
                ":ttl": int(datetime.now(timezone.utc).timestamp()) + 7200,
            },
        )
        return True

    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.warning(f"GitHub rate limit exceeded on shard {shard_id}")
            return False
        logger.error(f"DynamoDB error in rate limit check: {e}")
        # Fail closed for safety
        return False
```

## Files to Modify

| File | Changes |
|------|---------|
| `functions/api/create_api_key.py` | Fix race condition with transactions |
| `functions/api/revoke_api_key.py` | Fix race condition with transactions |
| `functions/api/get_package.py` | Add usage alerts, X-RateLimit-Reset |
| `functions/api/post_scan.py` | Add usage alerts, X-RateLimit-Reset |
| `functions/api/stripe_webhook.py` | Add usage reset on upgrade |
| `functions/collectors/package_collector.py` | Fix GitHub rate limit race |

## Success Criteria

1. API key creation race condition fixed
2. API key revocation race condition fixed
3. Usage alerts at 80%, 95%, 100% thresholds
4. Usage reset on tier upgrade
5. X-RateLimit-Reset header added
6. GitHub rate limit race condition fixed
7. All existing tests pass
8. New tests for race condition prevention

## Testing Requirements

```bash
cd /home/iebt/projects/startup-experiment/work/dephealth
pytest tests/test_auth.py tests/test_concurrency.py -v
```

Add concurrent tests:
```python
def test_concurrent_key_creation_respects_limit():
    """Test that concurrent key creation doesn't exceed limit."""
    # Use threading to simulate concurrent requests
    import threading

    results = []

    def create_key():
        result = handler(create_key_event, None)
        results.append(result["statusCode"])

    threads = [threading.Thread(target=create_key) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Should have MAX_KEYS_PER_USER successes and rest failures
    successes = sum(1 for r in results if r == 200)
    assert successes <= MAX_KEYS_PER_USER
```

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 10 for full rate limiting analysis.
