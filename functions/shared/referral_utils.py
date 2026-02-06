"""
Referral Program Utilities.

Handles:
- Referral code generation and validation
- Email canonicalization for self-referral prevention
- Disposable email detection
- Bonus credit management with lifetime cap
- Referral reward processing
"""

import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from .aws_clients import get_dynamodb

logger = logging.getLogger(__name__)


# Table names from environment
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
REFERRAL_EVENTS_TABLE = os.environ.get("REFERRAL_EVENTS_TABLE", "pkgwatch-referral-events")

# ===========================================
# Referral Constants
# ===========================================

# Reward amounts (requests)
REFERRAL_REWARDS = {
    "signup": 5000,  # Referrer gets when referred user scans 100+ packages
    "paid": 25000,  # Referrer gets when referred user upgrades to paid
    "retained": 25000,  # Referrer gets when referred user stays 2 months
}
REFERRED_USER_BONUS = 10000  # What the referred user gets immediately

# Activity threshold (packages scanned before referrer gets credit)
ACTIVITY_THRESHOLD = 100

# Bonus credit limits
BONUS_CAP = 500000  # Lifetime cap for bonus credits

# Time limits
LATE_ENTRY_DAYS = 14  # Days after signup to add referral code
PENDING_TIMEOUT_DAYS = 90  # Days before pending referral expires
RETENTION_MONTHS = 2  # Months before retention bonus triggers

# Referral code format (allows alphanumeric plus _ and - for backwards compatibility)
REFERRAL_CODE_REGEX = re.compile(r"^[a-zA-Z0-9_-]{6,12}$")

# ===========================================
# Email Canonicalization
# ===========================================


def canonicalize_email(email: str) -> str:
    """
    Canonicalize email for comparison (strip Gmail dots/plus-aliases).

    This prevents self-referral via email aliases like:
    - john.doe@gmail.com vs johndoe@gmail.com
    - john+referral@gmail.com vs john@gmail.com

    Args:
        email: Email address to canonicalize

    Returns:
        Canonicalized email address
    """
    if not email or "@" not in email:
        return email.lower() if email else ""

    local, domain = email.lower().split("@", 1)

    # Gmail and Google-hosted domains use the same backend
    if domain in ("gmail.com", "googlemail.com"):
        # Remove dots (Gmail ignores them)
        local = local.replace(".", "")
        # Remove plus-alias (everything after +)
        if "+" in local:
            local = local.split("+")[0]
        # Normalize googlemail.com to gmail.com
        domain = "gmail.com"

    return f"{local}@{domain}"


# ===========================================
# Disposable Email Detection
# ===========================================

# Top disposable email domains (subset - can be expanded)
DISPOSABLE_DOMAINS = frozenset(
    [
        "10minutemail.com",
        "10minutemail.net",
        "guerrillamail.com",
        "guerrillamail.org",
        "mailinator.com",
        "tempmail.com",
        "temp-mail.org",
        "throwaway.email",
        "throwawaymail.com",
        "trashmail.com",
        "fakeinbox.com",
        "yopmail.com",
        "sharklasers.com",
        "maildrop.cc",
        "dispostable.com",
        "mailnesia.com",
        "tempr.email",
        "discard.email",
        "tmpmail.org",
        "tmpmail.net",
        "emailondeck.com",
        "mohmal.com",
        "getnada.com",
        "minuteinbox.com",
        "tempail.com",
        "emailfake.com",
        "crazymailing.com",
        "inboxkitten.com",
        "burnermail.io",
        "mailsac.com",
        "moakt.com",
        "tempinbox.com",
        "mytrashmail.com",
        "spam4.me",
        "jetable.org",
        "getairmail.com",
        "mailcatch.com",
        "tempmailaddress.com",
        "spambox.us",
        "bobmail.info",
        "mintemail.com",
        "mailforspam.com",
        "spamdecoy.net",
        "trash-mail.com",
        "harakirimail.com",
        "spamfree24.org",
        "anonymbox.net",
        "tempemailco.com",
        "mailnull.com",
        "disposableemailaddresses.com",
    ]
)


def is_disposable_email(email: str) -> bool:
    """
    Check if email is from a known disposable email domain.

    Args:
        email: Email address to check

    Returns:
        True if email is from a disposable domain
    """
    if not email or "@" not in email:
        return False

    domain = email.lower().split("@")[1]
    return domain in DISPOSABLE_DOMAINS


# ===========================================
# Referral Code Generation
# ===========================================


def generate_referral_code() -> str:
    """
    Generate a unique 8-character alphanumeric referral code.

    Uses only alphanumeric characters (A-Z, a-z, 0-9) to match
    the validation regex and avoid URL encoding issues.

    Returns:
        8-character referral code like "AbC12DeF"
    """
    # Use only alphanumeric characters to match validation regex
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(8))


def is_valid_referral_code(code: str) -> bool:
    """
    Validate referral code format.

    Args:
        code: Referral code to validate

    Returns:
        True if code matches expected format
    """
    if not code:
        return False
    return bool(REFERRAL_CODE_REGEX.match(code))


# ===========================================
# Referral Code Lookup
# ===========================================


def lookup_referrer_by_code(code: str) -> Optional[dict]:
    """
    Look up referrer user by their referral code.

    Uses referral-code-index GSI for O(1) lookup.

    Args:
        code: Referral code to look up

    Returns:
        Dict with user_id and email, or None if not found
    """
    if not is_valid_referral_code(code):
        return None

    table = get_dynamodb().Table(API_KEYS_TABLE)

    try:
        response = table.query(
            IndexName="referral-code-index",
            KeyConditionExpression=Key("referral_code").eq(code),
            Limit=1,
        )

        items = response.get("Items", [])
        if not items:
            return None

        item = items[0]
        return {
            "user_id": item.get("pk"),
            "email": item.get("email"),
        }

    except ClientError as e:
        logger.error(f"Error looking up referral code: {e}")
        return None


def code_exists(code: str) -> bool:
    """
    Check if a referral code already exists.

    Args:
        code: Code to check

    Returns:
        True if code exists
    """
    return lookup_referrer_by_code(code) is not None


def generate_unique_referral_code(max_attempts: int = 5) -> str:
    """
    Generate a unique referral code that doesn't exist yet.

    Args:
        max_attempts: Maximum attempts to generate unique code

    Returns:
        Unique referral code

    Raises:
        RuntimeError: If unable to generate unique code
    """
    for _ in range(max_attempts):
        code = generate_referral_code()
        if not code_exists(code):
            return code

    # Extremely unlikely to hit this
    raise RuntimeError("Failed to generate unique referral code")


# ===========================================
# Bonus Credit Management
# ===========================================


def add_bonus_with_cap(user_id: str, amount: int) -> int:
    """
    Add bonus credits to user, respecting lifetime cap.

    Uses atomic conditional update to prevent race conditions.
    If adding the full amount would exceed cap, retries with partial amount.

    Args:
        user_id: User ID to credit
        amount: Amount of bonus credits to add

    Returns:
        Amount actually added (may be less than requested if at cap)
    """
    if amount <= 0:
        return 0

    table = get_dynamodb().Table(API_KEYS_TABLE)

    try:
        # First attempt: try to add full amount with cap condition
        # This is atomic - condition is checked at write time
        table.update_item(
            Key={"pk": user_id, "sk": "USER_META"},
            UpdateExpression="""
                SET bonus_requests = if_not_exists(bonus_requests, :zero) + :add_amount,
                    bonus_requests_lifetime = if_not_exists(bonus_requests_lifetime, :zero) + :add_amount
            """,
            ConditionExpression=(
                "(attribute_not_exists(bonus_requests_lifetime) OR bonus_requests_lifetime < :cap_threshold)"
            ),
            ExpressionAttributeValues={
                ":add_amount": amount,
                ":zero": 0,
                ":cap_threshold": BONUS_CAP - amount + 1,  # Allow if result would be <= cap
            },
        )
        logger.info(f"User {user_id} received {amount} bonus credits")
        return amount

    except ClientError as e:
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            logger.error(f"Error adding bonus credits for {user_id}: {e}")
            raise

        # Condition failed - user is at or near cap. Get current state and calculate partial.
        try:
            response = table.get_item(
                Key={"pk": user_id, "sk": "USER_META"},
                ProjectionExpression="bonus_requests_lifetime",
                ConsistentRead=True,  # Use consistent read to get accurate cap check
            )

            current_lifetime = 0
            if "Item" in response:
                current_lifetime = int(response["Item"].get("bonus_requests_lifetime", 0))

            if current_lifetime >= BONUS_CAP:
                logger.info(f"User {user_id} at bonus cap ({current_lifetime}/{BONUS_CAP}), no credit added")
                return 0

            # Calculate partial amount
            remaining_cap = BONUS_CAP - current_lifetime
            partial_amount = min(amount, remaining_cap)

            if partial_amount <= 0:
                return 0

            # Try partial update with strict cap condition
            table.update_item(
                Key={"pk": user_id, "sk": "USER_META"},
                UpdateExpression="""
                    SET bonus_requests = if_not_exists(bonus_requests, :zero) + :add_amount,
                        bonus_requests_lifetime = if_not_exists(bonus_requests_lifetime, :zero) + :add_amount
                """,
                ConditionExpression="bonus_requests_lifetime <= :max_before",
                ExpressionAttributeValues={
                    ":add_amount": partial_amount,
                    ":zero": 0,
                    ":max_before": BONUS_CAP - partial_amount,
                },
            )

            logger.info(
                f"User {user_id} received partial credit: {partial_amount}/{amount} "
                f"(cap reached at {current_lifetime + partial_amount})"
            )
            return partial_amount

        except ClientError as retry_error:
            if retry_error.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # Another concurrent request filled the cap
                logger.info(f"User {user_id} cap filled by concurrent request, no credit added")
                return 0
            raise


def consume_bonus_credits(user_id: str, amount: int) -> bool:
    """
    Consume bonus credits from user's balance.

    Only consumes if user has sufficient bonus credits.
    This is used when monthly limit is exceeded.

    Args:
        user_id: User ID
        amount: Amount to consume

    Returns:
        True if credits were consumed, False if insufficient
    """
    if amount <= 0:
        return True

    table = get_dynamodb().Table(API_KEYS_TABLE)

    try:
        table.update_item(
            Key={"pk": user_id, "sk": "USER_META"},
            UpdateExpression="SET bonus_requests = bonus_requests - :amount",
            ConditionExpression="attribute_exists(bonus_requests) AND bonus_requests >= :amount",
            ExpressionAttributeValues={":amount": amount},
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise


def get_bonus_balance(user_id: str) -> dict:
    """
    Get user's bonus credit balance and stats.

    Args:
        user_id: User ID

    Returns:
        Dict with bonus_requests, bonus_requests_lifetime, at_cap
    """
    table = get_dynamodb().Table(API_KEYS_TABLE)

    response = table.get_item(
        Key={"pk": user_id, "sk": "USER_META"},
        ProjectionExpression="bonus_requests, bonus_requests_lifetime",
    )

    item = response.get("Item", {})
    current = int(item.get("bonus_requests", 0))
    lifetime = int(item.get("bonus_requests_lifetime", 0))

    return {
        "bonus_requests": current,
        "bonus_requests_lifetime": lifetime,
        "bonus_cap": BONUS_CAP,
        "at_cap": lifetime >= BONUS_CAP,
    }


# ===========================================
# Referral Event Recording
# ===========================================


def record_referral_event(
    referrer_id: str,
    referred_id: str,
    event_type: str,
    referred_email: str = None,
    reward_amount: int = 0,
    ttl_days: int = None,
    retention_check_date: str = None,
) -> bool:
    """
    Record a referral event in the referral-events table.

    Event types: "pending", "signup", "paid", "retained"

    Args:
        referrer_id: User ID of referrer
        referred_id: User ID of referred user
        event_type: Type of event
        referred_email: Email of referred user (for display, masked)
        reward_amount: Amount of bonus credited
        ttl_days: Days until record expires (for pending events)
        retention_check_date: ISO date for retention check (for paid events)

    Returns:
        True if recorded successfully
    """
    table = get_dynamodb().Table(REFERRAL_EVENTS_TABLE)
    now = datetime.now(timezone.utc)

    item = {
        "pk": referrer_id,
        "sk": f"{referred_id}#{event_type}",
        "referred_id": referred_id,
        "event_type": event_type,
        "created_at": now.isoformat(),
        "reward_amount": reward_amount,
    }

    # Mask email for privacy (jo**@example.com)
    if referred_email:
        item["referred_email_masked"] = mask_email(referred_email)

    # Set TTL for pending events
    if ttl_days:
        ttl_timestamp = int((now + timedelta(days=ttl_days)).timestamp())
        item["ttl"] = ttl_timestamp

    # Set retention check fields for paid events
    if retention_check_date:
        item["needs_retention_check"] = "true"
        item["retention_check_date"] = retention_check_date

    try:
        table.put_item(Item=item)
        return True
    except ClientError as e:
        logger.error(f"Error recording referral event: {e}")
        return False


def update_referral_event_to_credited(
    referrer_id: str,
    referred_id: str,
    reward_amount: int,
) -> bool:
    """
    Update a pending referral event to credited status.

    Removes TTL since credited events should persist.

    Args:
        referrer_id: Referrer user ID
        referred_id: Referred user ID
        reward_amount: Amount of bonus credited

    Returns:
        True if updated successfully
    """
    table = get_dynamodb().Table(REFERRAL_EVENTS_TABLE)
    now = datetime.now(timezone.utc)

    try:
        # Delete the pending event
        table.delete_item(Key={"pk": referrer_id, "sk": f"{referred_id}#pending"})

        # Create the signup event (no TTL)
        table.put_item(
            Item={
                "pk": referrer_id,
                "sk": f"{referred_id}#signup",
                "referred_id": referred_id,
                "event_type": "signup",
                "created_at": now.isoformat(),
                "reward_amount": reward_amount,
            }
        )

        return True
    except ClientError as e:
        logger.error(f"Error updating referral event: {e}")
        return False


def mark_retention_checked(referrer_id: str, referred_id: str) -> bool:
    """
    Remove retention check flag after processing.

    Args:
        referrer_id: Referrer user ID
        referred_id: Referred user ID

    Returns:
        True if updated successfully
    """
    table = get_dynamodb().Table(REFERRAL_EVENTS_TABLE)

    try:
        table.update_item(
            Key={"pk": referrer_id, "sk": f"{referred_id}#paid"},
            UpdateExpression="REMOVE needs_retention_check, retention_check_date",
        )
        return True
    except ClientError as e:
        logger.error(f"Error marking retention checked: {e}")
        return False


# ===========================================
# Referrer Stats Management
# ===========================================


def update_referrer_stats(
    user_id: str,
    total_delta: int = 0,
    pending_delta: int = 0,
    paid_delta: int = 0,
    retained_delta: int = 0,
    rewards_delta: int = 0,
) -> bool:
    """
    Update referrer statistics atomically.

    Uses ADD operations for atomic increments.

    Args:
        user_id: Referrer user ID
        total_delta: Change to referral_total
        pending_delta: Change to referral_pending_count
        paid_delta: Change to referral_paid
        retained_delta: Change to referral_retained
        rewards_delta: Change to referral_rewards_earned

    Returns:
        True if updated successfully
    """
    table = get_dynamodb().Table(API_KEYS_TABLE)

    update_parts = []
    expr_values = {}

    if total_delta:
        update_parts.append("referral_total = if_not_exists(referral_total, :zero) + :total")
        expr_values[":total"] = total_delta

    if pending_delta:
        update_parts.append("referral_pending_count = if_not_exists(referral_pending_count, :zero) + :pending")
        expr_values[":pending"] = pending_delta

    if paid_delta:
        update_parts.append("referral_paid = if_not_exists(referral_paid, :zero) + :paid")
        expr_values[":paid"] = paid_delta

    if retained_delta:
        update_parts.append("referral_retained = if_not_exists(referral_retained, :zero) + :retained")
        expr_values[":retained"] = retained_delta

    if rewards_delta:
        update_parts.append("referral_rewards_earned = if_not_exists(referral_rewards_earned, :zero) + :rewards")
        expr_values[":rewards"] = rewards_delta

    if not update_parts:
        return True

    expr_values[":zero"] = 0

    try:
        table.update_item(
            Key={"pk": user_id, "sk": "USER_META"},
            UpdateExpression="SET " + ", ".join(update_parts),
            ExpressionAttributeValues=expr_values,
        )
        return True
    except ClientError as e:
        logger.error(f"Error updating referrer stats for {user_id}: {e}")
        return False


def get_referrer_stats(user_id: str) -> dict:
    """
    Get referrer statistics.

    Args:
        user_id: User ID

    Returns:
        Dict with referral stats
    """
    table = get_dynamodb().Table(API_KEYS_TABLE)

    response = table.get_item(
        Key={"pk": user_id, "sk": "USER_META"},
        ProjectionExpression=(
            "referral_total, referral_pending_count, referral_paid, referral_retained, referral_rewards_earned"
        ),
    )

    item = response.get("Item", {})

    return {
        "total_referrals": int(item.get("referral_total", 0)),
        "pending_referrals": int(item.get("referral_pending_count", 0)),
        "paid_conversions": int(item.get("referral_paid", 0)),
        "retained_conversions": int(item.get("referral_retained", 0)),
        "total_rewards_earned": int(item.get("referral_rewards_earned", 0)),
    }


# ===========================================
# Self-Referral Prevention
# ===========================================


def is_self_referral(referrer_email: str, referred_email: str) -> bool:
    """
    Check if this would be a self-referral.

    Compares canonicalized emails to catch alias-based self-referral.

    Args:
        referrer_email: Email of the referrer
        referred_email: Email of the referred user

    Returns:
        True if emails canonicalize to the same address
    """
    canon_referrer = canonicalize_email(referrer_email)
    canon_referred = canonicalize_email(referred_email)

    return canon_referrer == canon_referred


# ===========================================
# Helper Functions
# ===========================================


def mask_email(email: str) -> str:
    """
    Mask email for privacy display.

    Example: john.doe@example.com -> jo**@example.com

    Args:
        email: Full email address

    Returns:
        Masked email
    """
    if not email or "@" not in email:
        return "**@**.***"

    local, domain = email.split("@", 1)

    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[:2] + "**"

    return f"{masked_local}@{domain}"


def can_add_late_referral(user_id: str) -> tuple[bool, Optional[str]]:
    """
    Check if user can still add a referral code (within 14-day window).

    Args:
        user_id: User ID

    Returns:
        Tuple of (can_add, deadline_iso) - deadline is None if can't add
    """
    table = get_dynamodb().Table(API_KEYS_TABLE)

    response = table.get_item(
        Key={"pk": user_id, "sk": "USER_META"},
        ProjectionExpression="created_at, referred_by",
    )

    item = response.get("Item", {})

    # Already has a referrer
    if item.get("referred_by"):
        return False, None

    # Check account age
    created_at = item.get("created_at")
    if not created_at:
        return False, None

    try:
        created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        deadline = created_dt + timedelta(days=LATE_ENTRY_DAYS)
        now = datetime.now(timezone.utc)

        if now > deadline:
            return False, None

        return True, deadline.isoformat()

    except (ValueError, TypeError):
        return False, None


def get_referral_events(referrer_id: str, limit: int = 50) -> list[dict]:
    """
    Get referral events for a user.

    Args:
        referrer_id: User ID of referrer
        limit: Maximum events to return

    Returns:
        List of referral event records
    """
    table = get_dynamodb().Table(REFERRAL_EVENTS_TABLE)

    try:
        response = table.query(
            KeyConditionExpression=Key("pk").eq(referrer_id),
            Limit=limit,
            ScanIndexForward=False,  # Most recent first
        )

        return response.get("Items", [])

    except ClientError as e:
        logger.error(f"Error getting referral events: {e}")
        return []
