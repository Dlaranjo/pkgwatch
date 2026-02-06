"""
Rate Limiting Utilities

Shared functions for rate limit calculations, usage alerts, and reset timestamps.
Used by API endpoints (get_package, post_scan) to provide consistent rate limit
information to users.
"""

import os
import random
from datetime import datetime, timezone
from typing import Optional

from botocore.exceptions import ClientError

from shared.aws_clients import get_dynamodb


def get_reset_timestamp() -> int:
    """Get Unix timestamp for start of next month (when usage resets).

    Returns:
        Unix timestamp (seconds since epoch) for 00:00:00 UTC on the first day
        of next month.
    """
    now = datetime.now(timezone.utc)

    # First day of next month
    if now.month == 12:
        next_month = datetime(now.year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        next_month = datetime(now.year, now.month + 1, 1, tzinfo=timezone.utc)

    return int(next_month.timestamp())


def check_usage_alerts(user: dict, current_usage: int) -> Optional[dict]:
    """Check if user is approaching rate limit and return alert info.

    Provides tiered alerts at 80%, 95%, and 100% thresholds to help users
    monitor their API usage.

    Args:
        user: User dict with monthly_limit key
        current_usage: Current number of requests this month

    Returns:
        Alert dict with level, percent, and message if alert needed, None otherwise.

    Example:
        >>> user = {"monthly_limit": 5000}
        >>> check_usage_alerts(user, 4800)
        {
            "level": "critical",
            "percent": 96.0,
            "message": "Only 200 requests remaining this month"
        }
    """
    limit = user.get("monthly_limit", 5000)
    usage_percent = (current_usage / limit) * 100 if limit > 0 else 100

    if usage_percent >= 100:
        return {
            "level": "exceeded",
            "percent": 100,
            "message": "Monthly limit exceeded. Upgrade at https://pkgwatch.dev/pricing",
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


# External service rate limiting with sharded counters
RATE_LIMIT_SHARDS = 10


def check_and_increment_external_rate_limit(
    service: str, hourly_limit: int, table_name: str = None
) -> bool:
    """
    Check rate limit for external service using atomic sharded counters.
    Uses per-shard limits with atomic conditional updates to prevent TOCTOU race.

    Args:
        service: Service name (e.g., "npm", "bundlephobia")
        hourly_limit: Maximum requests per hour
        table_name: DynamoDB table name (defaults to API_KEYS_TABLE env var)

    Returns:
        True if request is allowed, False if rate limited
    """
    table = get_dynamodb().Table(table_name or os.environ.get("API_KEYS_TABLE"))
    now = datetime.now(timezone.utc)
    window_key = now.strftime("%Y-%m-%d-%H")
    shard_id = random.randint(0, RATE_LIMIT_SHARDS - 1)

    # Per-shard limit (distribute evenly, no buffer to avoid exceeding limit)
    # For hourly_limit=100 with 10 shards: 10 per shard = 100 total (exact)
    shard_limit = hourly_limit // RATE_LIMIT_SHARDS

    try:
        # ATOMIC check-and-increment using conditional expression
        table.update_item(
            Key={"pk": f"{service}_rate_limit#{shard_id}", "sk": window_key},
            UpdateExpression="SET calls = if_not_exists(calls, :zero) + :inc, #ttl = :ttl",
            ConditionExpression="attribute_not_exists(calls) OR calls < :limit",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={
                ":zero": 0,
                ":inc": 1,
                ":limit": shard_limit,
                ":ttl": int(now.timestamp()) + 7200,
            },
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # This shard is full, check other shards
            return _check_any_shard_available(table, service, window_key, shard_limit)
        raise


def _check_any_shard_available(table, service: str, window_key: str, shard_limit: int) -> bool:
    """Check if any shard has capacity (fallback when random shard is full)."""
    now = datetime.now(timezone.utc)
    for shard_id in range(RATE_LIMIT_SHARDS):
        try:
            table.update_item(
                Key={"pk": f"{service}_rate_limit#{shard_id}", "sk": window_key},
                UpdateExpression="SET calls = if_not_exists(calls, :zero) + :inc, #ttl = :ttl",
                ConditionExpression="attribute_not_exists(calls) OR calls < :limit",
                ExpressionAttributeNames={"#ttl": "ttl"},
                ExpressionAttributeValues={
                    ":zero": 0,
                    ":inc": 1,
                    ":limit": shard_limit,
                    ":ttl": int(now.timestamp()) + 7200,
                },
            )
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                continue
            raise
    return False  # All shards at limit
