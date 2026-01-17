"""
Authentication and API Key Management.

Handles:
- API key generation
- API key validation (using GSI for O(1) lookup)
- Usage tracking
- Tier limits
"""

import hashlib
import logging
import os
import random
import secrets
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

# DynamoDB throttling error codes that should trigger retry
THROTTLING_ERRORS = (
    "ProvisionedThroughputExceededException",
    "RequestLimitExceeded",
    "ThrottlingException",
    "InternalServerError",
)

# Lazy initialization to avoid boto3 resource creation at import time
# This prevents "NoRegionError" during test collection when AWS isn't configured
_dynamodb = None
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")


def _get_dynamodb():
    """Get DynamoDB resource, creating it lazily on first use."""
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb

# Import tier limits from constants (single source of truth)
from .constants import TIER_LIMITS


def generate_api_key(user_id: str, tier: str = "free", email: str = None) -> str:
    """
    Generate a new API key for a user.

    Args:
        user_id: Unique user identifier
        tier: Subscription tier (free, starter, pro, business)
        email: Optional user email for reference

    Returns:
        The generated API key (only returned once, store securely!)
    """
    # Generate secure random key with prefix
    api_key = f"pw_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    # Store last 8 chars of actual key for display (hash suffix is different)
    key_suffix = api_key[-8:]

    table = _get_dynamodb().Table(API_KEYS_TABLE)

    # Build item - only include GSI key attributes if they have values
    # DynamoDB GSIs require non-null values for key attributes
    item = {
        "pk": user_id,
        "sk": key_hash,
        "key_hash": key_hash,  # Duplicated for GSI
        "key_suffix": key_suffix,  # Last 8 chars of actual key for display
        "tier": tier,
        "payment_failures": 0,  # Track failed payment attempts
        "requests_this_month": 0,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "email_verified": False,  # For signup email verification
    }

    # Only include GSI key attributes if they have values
    if email:
        item["email"] = email

    table.put_item(Item=item)

    return api_key


def validate_api_key(api_key: str, max_retries: int = 3) -> Optional[dict]:
    """
    Validate API key and return user info.

    Uses key-hash-index GSI for O(1) lookup.
    Includes retry with exponential backoff for DynamoDB throttling.

    Args:
        api_key: The API key to validate (e.g., "pw_abc123...")
        max_retries: Maximum retry attempts for throttling errors

    Returns:
        User info dict or None if invalid
    """
    if not api_key:
        return None

    # Check prefix
    if not api_key.startswith("pw_"):
        return None

    # Hash the key for lookup
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    table = _get_dynamodb().Table(API_KEYS_TABLE)

    for attempt in range(max_retries):
        try:
            # Query using GSI for O(1) lookup by key hash
            response = table.query(
                IndexName="key-hash-index",
                KeyConditionExpression=Key("key_hash").eq(key_hash),
            )

            items = response.get("Items", [])
            if not items:
                return None

            item = items[0]
            tier = item.get("tier", "free")

            return {
                "user_id": item["pk"],
                "key_hash": item["sk"],  # Return for use in increment_usage
                "tier": tier,
                "monthly_limit": TIER_LIMITS.get(tier, TIER_LIMITS["free"]),
                "requests_this_month": item.get("requests_this_month", 0),
                "created_at": item.get("created_at"),
                "email": item.get("email"),
            }

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in THROTTLING_ERRORS and attempt < max_retries - 1:
                # Exponential backoff with jitter to prevent thundering herd
                base_delay = min(0.1 * (2 ** attempt), 2.0)
                jitter = random.uniform(0, base_delay * 0.5)
                delay = base_delay + jitter
                logger.warning(
                    f"DynamoDB throttled during auth, retry {attempt + 1}/{max_retries} in {delay:.2f}s"
                )
                time.sleep(delay)
                continue
            # Non-throttling error or max retries exceeded
            logger.error(f"Error validating API key: {e}")
            return None

        except Exception as e:
            # Log error but don't expose details
            logger.error(f"Error validating API key: {e}")
            return None

    # Max retries exceeded
    logger.error("Max retries exceeded validating API key")
    return None


def increment_usage(user_id: str, key_hash: str, count: int = 1) -> int:
    """
    Increment monthly usage counter.

    Uses atomic counter in DynamoDB for concurrency safety.

    Args:
        user_id: User's partition key (pk)
        key_hash: Key hash (sort key / sk)
        count: Number to increment by (default 1, use higher for batch operations)

    Returns:
        New usage count
    """
    table = _get_dynamodb().Table(API_KEYS_TABLE)

    response = table.update_item(
        Key={"pk": user_id, "sk": key_hash},
        UpdateExpression="ADD requests_this_month :inc",
        ExpressionAttributeValues={":inc": count},
        ReturnValues="UPDATED_NEW",
    )

    return response.get("Attributes", {}).get("requests_this_month", 0)


def check_and_increment_usage(user_id: str, key_hash: str, limit: int) -> tuple[bool, int]:
    """
    Atomically check limit and increment usage counter at USER_META level.

    Rate limiting is enforced at the user level (USER_META.requests_this_month)
    to prevent gaming via key deletion. Per-key counters are maintained for
    analytics purposes (best-effort, non-blocking).

    Args:
        user_id: User's partition key (pk)
        key_hash: Key hash (sort key / sk) - used for per-key analytics
        limit: Maximum allowed requests

    Returns:
        Tuple of (allowed: bool, new_count: int)
        - allowed: True if request was within limit and counter was incremented
        - new_count: The new usage count after increment (or current if denied)
    """
    table = _get_dynamodb().Table(API_KEYS_TABLE)

    try:
        # Atomically check and increment USER_META.requests_this_month
        response = table.update_item(
            Key={"pk": user_id, "sk": "USER_META"},
            UpdateExpression="SET requests_this_month = if_not_exists(requests_this_month, :zero) + :inc",
            ConditionExpression="attribute_not_exists(requests_this_month) OR requests_this_month < :limit",
            ExpressionAttributeValues={
                ":inc": 1,
                ":limit": limit,
                ":zero": 0,
            },
            ReturnValues="UPDATED_NEW",
        )
        new_count = response.get("Attributes", {}).get("requests_this_month", 1)

        # Also increment per-key counter for analytics (best-effort, non-blocking)
        try:
            table.update_item(
                Key={"pk": user_id, "sk": key_hash},
                UpdateExpression="ADD requests_this_month :inc",
                ExpressionAttributeValues={":inc": 1},
            )
        except Exception:
            logger.warning(f"Failed to increment per-key counter for {user_id}/{key_hash[:8]}...")

        return True, new_count
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Rate limit exceeded - get current count for accurate remaining calculation
            try:
                get_response = table.get_item(
                    Key={"pk": user_id, "sk": "USER_META"},
                    ProjectionExpression="requests_this_month",
                )
                current_count = get_response.get("Item", {}).get("requests_this_month", limit)
                return False, current_count
            except Exception:
                return False, limit
        raise


def check_and_increment_usage_batch(
    user_id: str, key_hash: str, limit: int, count: int
) -> tuple[bool, int]:
    """
    Atomically check limit and increment usage counter by a batch count at USER_META level.

    Rate limiting is enforced at the user level (USER_META.requests_this_month)
    to prevent gaming via key deletion. Per-key counters are maintained for
    analytics purposes (best-effort, non-blocking).

    Args:
        user_id: User's partition key (pk)
        key_hash: Key hash (sort key / sk) - used for per-key analytics
        limit: Maximum allowed requests
        count: Number of requests to increment by (for batch operations)

    Returns:
        Tuple of (allowed: bool, new_count: int)
        - allowed: True if request was within limit and counter was incremented
        - new_count: The new usage count after increment (or current if denied)
    """
    table = _get_dynamodb().Table(API_KEYS_TABLE)

    # Calculate threshold: if current count is at or above this, we'd exceed limit
    # This avoids arithmetic in condition expression (Moto compatibility)
    threshold = limit - count + 1  # Current must be < threshold for increment to be allowed

    try:
        # Atomically check and increment USER_META.requests_this_month
        response = table.update_item(
            Key={"pk": user_id, "sk": "USER_META"},
            UpdateExpression="SET requests_this_month = if_not_exists(requests_this_month, :zero) + :inc",
            ConditionExpression="attribute_not_exists(requests_this_month) OR requests_this_month < :threshold",
            ExpressionAttributeValues={
                ":inc": count,
                ":threshold": threshold,
                ":zero": 0,
            },
            ReturnValues="UPDATED_NEW",
        )
        new_count = response.get("Attributes", {}).get("requests_this_month", count)

        # Also increment per-key counter for analytics (best-effort, non-blocking)
        try:
            table.update_item(
                Key={"pk": user_id, "sk": key_hash},
                UpdateExpression="ADD requests_this_month :inc",
                ExpressionAttributeValues={":inc": count},
            )
        except Exception:
            logger.warning(f"Failed to increment per-key counter for {user_id}/{key_hash[:8]}...")

        return True, new_count
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Rate limit would be exceeded - get current count for accurate remaining
            try:
                get_response = table.get_item(
                    Key={"pk": user_id, "sk": "USER_META"},
                    ProjectionExpression="requests_this_month",
                )
                current_count = get_response.get("Item", {}).get(
                    "requests_this_month", limit
                )
                return False, current_count
            except Exception:
                return False, limit
        raise


def reset_monthly_usage(user_id: str, key_hash: str) -> None:
    """
    Reset monthly usage counter (called at start of each month).

    Args:
        user_id: User's partition key
        key_hash: Key hash (sort key)
    """
    table = _get_dynamodb().Table(API_KEYS_TABLE)

    table.update_item(
        Key={"pk": user_id, "sk": key_hash},
        UpdateExpression="SET requests_this_month = :zero, last_reset = :now",
        ExpressionAttributeValues={
            ":zero": 0,
            ":now": datetime.now(timezone.utc).isoformat(),
        },
    )


def update_tier(user_id: str, key_hash: str, new_tier: str) -> None:
    """
    Update user's subscription tier.

    Args:
        user_id: User's partition key
        key_hash: Key hash (sort key)
        new_tier: New tier (free, starter, pro, business)
    """
    if new_tier not in TIER_LIMITS:
        raise ValueError(f"Invalid tier: {new_tier}")

    table = _get_dynamodb().Table(API_KEYS_TABLE)

    table.update_item(
        Key={"pk": user_id, "sk": key_hash},
        UpdateExpression="SET tier = :tier, tier_updated_at = :now",
        ExpressionAttributeValues={
            ":tier": new_tier,
            ":now": datetime.now(timezone.utc).isoformat(),
        },
    )


def revoke_api_key(user_id: str, key_hash: str) -> None:
    """
    Revoke (delete) an API key.

    Args:
        user_id: User's partition key
        key_hash: Key hash (sort key)
    """
    table = _get_dynamodb().Table(API_KEYS_TABLE)
    table.delete_item(Key={"pk": user_id, "sk": key_hash})


def get_user_keys(user_id: str) -> list[dict]:
    """
    Get all API keys for a user.

    Args:
        user_id: User's partition key

    Returns:
        List of key metadata (not the actual keys!)
    """
    table = _get_dynamodb().Table(API_KEYS_TABLE)

    response = table.query(
        KeyConditionExpression=Key("pk").eq(user_id),
    )

    return [
        {
            "key_hash_prefix": item["sk"][:8] + "...",
            "tier": item.get("tier"),
            "created_at": item.get("created_at"),
            "requests_this_month": item.get("requests_this_month", 0),
        }
        for item in response.get("Items", [])
    ]
