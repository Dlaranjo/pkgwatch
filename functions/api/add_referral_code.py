"""
Add Referral Code Endpoint - POST /referral/add-code

Allows users to add a referral code within 14 days of account creation.
This is for users who forgot to use a referral code during signup.
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie

import boto3
from boto3.dynamodb.conditions import Key

from shared.response_utils import error_response, success_response
from shared.referral_utils import (
    is_valid_referral_code,
    lookup_referrer_by_code,
    is_self_referral,
    add_bonus_with_cap,
    record_referral_event,
    update_referrer_stats,
    REFERRED_USER_BONUS,
    PENDING_TIMEOUT_DAYS,
    LATE_ENTRY_DAYS,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import session verification
from api.auth_callback import verify_session_token

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")


def _get_origin(event: dict) -> str | None:
    """Extract Origin header from request."""
    headers = event.get("headers", {}) or {}
    return headers.get("origin") or headers.get("Origin")


def handler(event, context):
    """
    Lambda handler for POST /referral/add-code.

    Request body:
    {
        "code": "abc12345"
    }

    Allows users to add a referral code within 14 days of signup.
    """
    origin = _get_origin(event)

    # Extract and verify session
    headers = event.get("headers", {}) or {}
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    session_token = None

    if cookie_header:
        cookies = SimpleCookie()
        cookies.load(cookie_header)
        if "session" in cookies:
            session_token = cookies["session"].value

    if not session_token:
        return error_response(401, "unauthorized", "Not authenticated", origin=origin)

    session_data = verify_session_token(session_token)
    if not session_data:
        return error_response(401, "session_expired", "Session expired. Please log in again.", origin=origin)

    user_id = session_data.get("user_id")
    user_email = session_data.get("email", "")

    # Defense-in-depth: validate user_id format
    if not user_id or not isinstance(user_id, str) or not user_id.startswith("user_"):
        logger.warning(f"Invalid user_id format in session: {user_id}")
        return error_response(401, "invalid_session", "Invalid session data", origin=origin)

    # Parse request body
    raw_body = event.get("body") or ""
    if len(raw_body) > 1000:  # Prevent large payload abuse
        return error_response(400, "payload_too_large", "Request body too large", origin=origin)

    try:
        body = json.loads(raw_body or "{}")
    except json.JSONDecodeError:
        return error_response(400, "invalid_json", "Request body must be valid JSON", origin=origin)

    code = body.get("code", "").strip()

    # Validate code format
    if not code or not is_valid_referral_code(code):
        return error_response(400, "invalid_code", "Invalid referral code format", origin=origin)

    table = dynamodb.Table(API_KEYS_TABLE)

    try:
        # Get user's current state
        response = table.get_item(
            Key={"pk": user_id, "sk": "USER_META"},
            ProjectionExpression="created_at, referred_by, email",
        )

        meta = response.get("Item")
        if not meta:
            return error_response(404, "user_not_found", "User account not found", origin=origin)

        # Check if user already has a referrer
        if meta.get("referred_by"):
            return error_response(
                409,
                "already_referred",
                "You've already used a referral code",
                origin=origin
            )

        # Check account age (14-day window)
        created_at = meta.get("created_at")
        if not created_at:
            return error_response(
                400,
                "invalid_account",
                "Unable to verify account creation date",
                origin=origin
            )

        try:
            created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            deadline = created_dt + timedelta(days=LATE_ENTRY_DAYS)
            now = datetime.now(timezone.utc)

            if now > deadline:
                return error_response(
                    400,
                    "window_expired",
                    f"Referral codes can only be added within {LATE_ENTRY_DAYS} days of signup",
                    origin=origin
                )
        except (ValueError, TypeError):
            return error_response(
                400,
                "invalid_account",
                "Unable to verify account creation date",
                origin=origin
            )

        # Look up the referrer
        referrer = lookup_referrer_by_code(code)
        if not referrer:
            return error_response(400, "code_not_found", "Referral code not found", origin=origin)

        referrer_id = referrer["user_id"]
        referrer_email = referrer.get("email", "")

        # Get user's email if not in session
        if not user_email:
            user_email = meta.get("email", "")

        # Check for self-referral
        if is_self_referral(referrer_email, user_email):
            return error_response(
                400,
                "self_referral",
                "You cannot use your own referral code",
                origin=origin
            )

        # All checks passed - process the late referral
        referral_pending_expires = (now + timedelta(days=PENDING_TIMEOUT_DAYS)).isoformat()

        # Update user with referral info and credit bonus
        table.update_item(
            Key={"pk": user_id, "sk": "USER_META"},
            UpdateExpression="""
                SET referred_by = :referrer,
                    referred_at = :now,
                    referral_pending = :pending,
                    referral_pending_expires = :expires,
                    bonus_requests = if_not_exists(bonus_requests, :zero) + :bonus,
                    bonus_requests_lifetime = if_not_exists(bonus_requests_lifetime, :zero) + :bonus
            """,
            ExpressionAttributeValues={
                ":referrer": referrer_id,
                ":now": now.isoformat(),
                ":pending": True,
                ":expires": referral_pending_expires,
                ":bonus": REFERRED_USER_BONUS,
                ":zero": 0,
            },
        )

        # Record pending referral event
        record_referral_event(
            referrer_id=referrer_id,
            referred_id=user_id,
            event_type="pending",
            referred_email=user_email,
            reward_amount=0,
            ttl_days=PENDING_TIMEOUT_DAYS,
        )

        # Update referrer stats
        update_referrer_stats(
            referrer_id,
            total_delta=1,
            pending_delta=1,
        )

        logger.info(f"Late referral: user {user_id} added code {code}, credited {REFERRED_USER_BONUS}")

        return success_response(
            {
                "message": f"Referral code applied! You've received {REFERRED_USER_BONUS:,} bonus requests.",
                "bonus_added": REFERRED_USER_BONUS,
            },
            origin=origin
        )

    except Exception as e:
        logger.error(f"Error in add_referral_code handler: {e}")
        return error_response(500, "internal_error", "An error occurred", origin=origin)
