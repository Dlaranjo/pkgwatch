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

from .circuit_breaker import DYNAMODB_CIRCUIT

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
    Protected by circuit breaker to prevent cascade failures.

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

    # Check circuit breaker before entering retry loop
    if not DYNAMODB_CIRCUIT.can_execute():
        logger.warning("DynamoDB circuit open, auth unavailable")
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

            # Record success even if no items found - DynamoDB call succeeded
            DYNAMODB_CIRCUIT.record_success()

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
            if error_code in THROTTLING_ERRORS:
                DYNAMODB_CIRCUIT.record_failure(e)
                if attempt < max_retries - 1:
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
            # Record failure for network errors, timeouts, etc.
            DYNAMODB_CIRCUIT.record_failure(e)
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

    Protected by circuit breaker with fail-open strategy: allows requests
    when circuit is open (DynamoDB stress) to prevent total service outage.

    Args:
        user_id: User's partition key (pk)
        key_hash: Key hash (sort key / sk) - used for per-key analytics
        limit: Maximum allowed requests

    Returns:
        Tuple of (allowed: bool, new_count: int)
        - allowed: True if request was within limit and counter was incremented
        - new_count: The new usage count after increment (or current if denied)
                     Returns -1 in degraded mode when circuit is open
    """
    # Fail-open: allow requests when circuit is open (DynamoDB stress)
    # This prevents total service outage during brief DynamoDB issues
    if not DYNAMODB_CIRCUIT.can_execute():
        logger.warning("DynamoDB circuit open, allowing request (degraded mode)")
        return True, -1  # -1 signals degraded mode to caller

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
        DYNAMODB_CIRCUIT.record_success()
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
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "ConditionalCheckFailedException":
            # Rate limit exceeded - this is expected behavior, record success
            DYNAMODB_CIRCUIT.record_success()
            # Get current count for accurate remaining calculation
            try:
                get_response = table.get_item(
                    Key={"pk": user_id, "sk": "USER_META"},
                    ProjectionExpression="requests_this_month",
                )
                current_count = get_response.get("Item", {}).get("requests_this_month", limit)
                return False, current_count
            except Exception:
                return False, limit
        if error_code in THROTTLING_ERRORS:
            DYNAMODB_CIRCUIT.record_failure(e)
        raise


def check_and_increment_usage_batch(
    user_id: str, key_hash: str, limit: int, count: int
) -> tuple[bool, int]:
    """
    Atomically check limit and increment usage counter by a batch count at USER_META level.

    Rate limiting is enforced at the user level (USER_META.requests_this_month)
    to prevent gaming via key deletion. Per-key counters are maintained for
    analytics purposes (best-effort, non-blocking).

    Protected by circuit breaker with fail-open strategy: allows requests
    when circuit is open (DynamoDB stress) to prevent total service outage.

    Args:
        user_id: User's partition key (pk)
        key_hash: Key hash (sort key / sk) - used for per-key analytics
        limit: Maximum allowed requests
        count: Number of requests to increment by (for batch operations)

    Returns:
        Tuple of (allowed: bool, new_count: int)
        - allowed: True if request was within limit and counter was incremented
        - new_count: The new usage count after increment (or current if denied)
                     Returns -1 in degraded mode when circuit is open
    """
    # Fail-open: allow requests when circuit is open (DynamoDB stress)
    # This prevents total service outage during brief DynamoDB issues
    if not DYNAMODB_CIRCUIT.can_execute():
        logger.warning("DynamoDB circuit open, allowing batch request (degraded mode)")
        return True, -1  # -1 signals degraded mode to caller

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
        DYNAMODB_CIRCUIT.record_success()
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
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "ConditionalCheckFailedException":
            # Rate limit would be exceeded - this is expected behavior, record success
            DYNAMODB_CIRCUIT.record_success()
            # Get current count for accurate remaining
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
        if error_code in THROTTLING_ERRORS:
            DYNAMODB_CIRCUIT.record_failure(e)
        raise


def check_and_increment_usage_with_bonus(
    user_id: str, key_hash: str, limit: int, count: int = 1
) -> tuple[bool, int, int]:
    """
    Check limit and increment usage, with bonus credit support and activity gate.

    Consumption priority:
    1. Monthly tier limit (requests_this_month)
    2. Bonus credits (bonus_requests) - used only after monthly exhausted

    Activity gate: If user has referral_pending=True and crosses ACTIVITY_THRESHOLD
    packages scanned, triggers referrer credit.

    Args:
        user_id: User's partition key
        key_hash: Key hash for per-key analytics
        limit: Monthly tier limit
        count: Number of requests to increment (default 1)

    Returns:
        Tuple of (allowed: bool, new_usage_count: int, remaining_bonus: int)
        - remaining_bonus is -1 if no bonus credits exist
    """
    # Import here to avoid circular import
    from shared.referral_utils import ACTIVITY_THRESHOLD

    if not DYNAMODB_CIRCUIT.can_execute():
        logger.warning("DynamoDB circuit open, allowing request (degraded mode)")
        return True, -1, -1

    table = _get_dynamodb().Table(API_KEYS_TABLE)

    try:
        # Get current USER_META state
        response = table.get_item(
            Key={"pk": user_id, "sk": "USER_META"},
            ProjectionExpression=(
                "requests_this_month, bonus_requests, referral_pending, "
                "referred_by, referral_pending_expires, total_packages_scanned"
            ),
        )

        meta = response.get("Item", {})
        current_usage = int(meta.get("requests_this_month", 0))
        bonus_available = int(meta.get("bonus_requests", 0))
        referral_pending = meta.get("referral_pending", False)
        total_scanned = int(meta.get("total_packages_scanned", 0))

        # Calculate effective limit (monthly + bonus)
        effective_limit = limit + bonus_available

        # Check if request fits within effective limit
        if current_usage + count > effective_limit:
            DYNAMODB_CIRCUIT.record_success()
            return False, current_usage, bonus_available

        # Determine how much goes to monthly vs bonus
        new_usage = current_usage + count
        bonus_consumed = 0

        if new_usage > limit:
            # Part or all consumed from bonus
            bonus_consumed = min(new_usage - limit, count)
            # Clamp usage at monthly limit
            usage_increment = count - bonus_consumed

            # Atomic update with both monthly and bonus.
            # GUARD: Condition ensures bonus_requests >= bonus_dec to prevent negative balance.
            # If another concurrent request consumed bonus first, this will fail and we reject.
            try:
                table.update_item(
                    Key={"pk": user_id, "sk": "USER_META"},
                    UpdateExpression=(
                        "SET requests_this_month = if_not_exists(requests_this_month, :zero) + :usage_inc, "
                        "bonus_requests = bonus_requests - :bonus_dec, "
                        "total_packages_scanned = if_not_exists(total_packages_scanned, :zero) + :count"
                    ),
                    ConditionExpression="bonus_requests >= :bonus_dec",
                    ExpressionAttributeValues={
                        ":usage_inc": usage_increment,
                        ":bonus_dec": bonus_consumed,
                        ":count": count,
                        ":zero": 0,
                    },
                )
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                    # Bonus was consumed by concurrent request - reject this request
                    logger.warning(f"Bonus race condition for {user_id}, rejecting request")
                    DYNAMODB_CIRCUIT.record_success()
                    return False, current_usage, 0
                raise
            new_bonus = bonus_available - bonus_consumed
        else:
            # All within monthly limit
            table.update_item(
                Key={"pk": user_id, "sk": "USER_META"},
                UpdateExpression=(
                    "SET requests_this_month = if_not_exists(requests_this_month, :zero) + :inc, "
                    "total_packages_scanned = if_not_exists(total_packages_scanned, :zero) + :count"
                ),
                ExpressionAttributeValues={
                    ":inc": count,
                    ":count": count,
                    ":zero": 0,
                },
            )
            new_bonus = bonus_available

        DYNAMODB_CIRCUIT.record_success()

        # Update per-key counter (best-effort)
        try:
            table.update_item(
                Key={"pk": user_id, "sk": key_hash},
                UpdateExpression="ADD requests_this_month :inc",
                ExpressionAttributeValues={":inc": count},
            )
        except Exception:
            pass

        # Check activity gate for referral credit
        new_total_scanned = total_scanned + count
        if referral_pending and new_total_scanned >= ACTIVITY_THRESHOLD and total_scanned < ACTIVITY_THRESHOLD:
            # User just crossed the activity threshold - trigger referrer credit
            _trigger_referral_activity_gate(user_id, meta)

        return True, new_usage, new_bonus

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in THROTTLING_ERRORS:
            DYNAMODB_CIRCUIT.record_failure(e)
        raise


def _trigger_referral_activity_gate(user_id: str, user_meta: dict):
    """
    Credit referrer when referred user hits activity threshold.

    Called when user crosses ACTIVITY_THRESHOLD packages scanned
    and has referral_pending=True.

    Uses atomic conditional update to prevent double-crediting from
    concurrent requests.

    Args:
        user_id: The referred user's ID
        user_meta: USER_META record for the referred user
    """
    from datetime import datetime, timezone
    from shared.referral_utils import (
        add_bonus_with_cap,
        update_referrer_stats,
        update_referral_event_to_credited,
        REFERRAL_REWARDS,
    )

    referrer_id = user_meta.get("referred_by")
    if not referrer_id:
        logger.warning(f"Activity gate triggered but no referrer for {user_id}")
        return

    # Check if pending has expired
    expires = user_meta.get("referral_pending_expires")
    if expires:
        try:
            expires_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expires_dt:
                logger.info(f"Referral pending expired for {user_id}, not crediting referrer")
                # Clear the pending flag
                table = _get_dynamodb().Table(API_KEYS_TABLE)
                table.update_item(
                    Key={"pk": user_id, "sk": "USER_META"},
                    UpdateExpression="REMOVE referral_pending, referral_pending_expires",
                )
                return
        except (ValueError, TypeError):
            pass

    table = _get_dynamodb().Table(API_KEYS_TABLE)

    try:
        # IDEMPOTENCY: Atomically clear pending flag and set credited marker.
        # This prevents double-crediting if concurrent requests both trigger the gate.
        # The condition ensures only one request succeeds.
        table.update_item(
            Key={"pk": user_id, "sk": "USER_META"},
            UpdateExpression=(
                "SET referral_activity_credited = :true "
                "REMOVE referral_pending, referral_pending_expires"
            ),
            ConditionExpression=(
                "referral_pending = :pending AND "
                "attribute_not_exists(referral_activity_credited)"
            ),
            ExpressionAttributeValues={
                ":true": True,
                ":pending": True,
            },
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Another concurrent request already processed this - that's OK
            logger.info(f"Activity gate already processed for {user_id} (concurrent request)")
            return
        raise

    # If we get here, we won the race - proceed with crediting
    try:
        # Credit referrer with signup bonus (respecting cap)
        reward_amount = REFERRAL_REWARDS["signup"]
        actual_reward = add_bonus_with_cap(referrer_id, reward_amount)

        # Update referral event from pending to credited
        update_referral_event_to_credited(referrer_id, user_id, actual_reward)

        # Update referrer stats
        update_referrer_stats(
            referrer_id,
            pending_delta=-1,  # Decrease pending count
            rewards_delta=actual_reward,
        )

        logger.info(
            f"Activity gate: credited referrer {referrer_id} with {actual_reward} "
            f"for referred user {user_id}"
        )

    except Exception as e:
        logger.error(f"Error processing activity gate for {user_id}: {e}")
        # Don't re-raise - the user's request should still succeed


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
