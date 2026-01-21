"""
Referral Status Endpoint - GET /referral/status

Returns the current user's referral program status including:
- Their referral code and URL
- Bonus credit balance
- Referral statistics
- List of referrals with status
"""

import json
import logging
import os
from decimal import Decimal
from http.cookies import SimpleCookie

import boto3
from boto3.dynamodb.conditions import Key

from shared.response_utils import decimal_default, error_response, get_cors_headers
from shared.referral_utils import (
    get_bonus_balance,
    get_referrer_stats,
    get_referral_events,
    mask_email,
    BONUS_CAP,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import session verification
from api.auth_callback import verify_session_token

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
BASE_URL = os.environ.get("BASE_URL", "https://pkgwatch.dev")


def handler(event, context):
    """
    Lambda handler for GET /referral/status.

    Returns the user's referral program information.
    Requires session authentication.
    """
    headers = event.get("headers", {}) or {}
    origin = headers.get("origin") or headers.get("Origin")

    # Extract and verify session
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

    # Defense-in-depth: validate user_id format
    if not user_id or not isinstance(user_id, str) or not user_id.startswith("user_"):
        logger.warning(f"Invalid user_id format in session: {user_id}")
        return error_response(401, "invalid_session", "Invalid session data", origin=origin)

    try:
        table = dynamodb.Table(API_KEYS_TABLE)

        # Get USER_META for referral code and basic info
        response = table.get_item(
            Key={"pk": user_id, "sk": "USER_META"},
            ProjectionExpression=(
                "referral_code, bonus_requests, bonus_requests_lifetime, "
                "referral_total, referral_pending_count, referral_paid, "
                "referral_retained, referral_rewards_earned"
            ),
        )

        meta = response.get("Item", {})

        referral_code = meta.get("referral_code")
        if not referral_code:
            # User doesn't have a referral code yet (legacy account)
            # Generate one for them
            from shared.referral_utils import generate_unique_referral_code

            referral_code = generate_unique_referral_code()
            table.update_item(
                Key={"pk": user_id, "sk": "USER_META"},
                UpdateExpression="SET referral_code = :code",
                ExpressionAttributeValues={":code": referral_code},
            )
            logger.info(f"Generated referral code for legacy user {user_id}")

        # Build response
        bonus_balance = int(meta.get("bonus_requests", 0))
        bonus_lifetime = int(meta.get("bonus_requests_lifetime", 0))

        stats = {
            "total_referrals": int(meta.get("referral_total", 0)),
            "pending_referrals": int(meta.get("referral_pending_count", 0)),
            "paid_conversions": int(meta.get("referral_paid", 0)),
            "retained_conversions": int(meta.get("referral_retained", 0)),
            "total_rewards_earned": int(meta.get("referral_rewards_earned", 0)),
        }

        # Get recent referral events
        events = get_referral_events(user_id, limit=20)
        referrals = []
        seen_users = set()

        for event_item in events:
            referred_id = event_item.get("referred_id")
            if referred_id in seen_users:
                continue
            seen_users.add(referred_id)

            event_type = event_item.get("event_type", "")
            status = "credited" if event_type in ("signup", "paid", "retained") else "pending"

            referral = {
                "email": event_item.get("referred_email_masked", "**@**.***"),
                "status": status,
                "date": event_item.get("created_at", "")[:10],  # Just the date part
                "reward": int(event_item.get("reward_amount", 0)),
            }

            # Add expiry for pending referrals
            if status == "pending" and event_item.get("ttl"):
                from datetime import datetime, timezone

                ttl_timestamp = int(event_item.get("ttl"))
                expires = datetime.fromtimestamp(ttl_timestamp, tz=timezone.utc)
                referral["expires"] = expires.strftime("%Y-%m-%d")

            referrals.append(referral)

        response_headers = {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
        }
        response_headers.update(get_cors_headers(origin))

        return {
            "statusCode": 200,
            "headers": response_headers,
            "body": json.dumps({
                "referral_code": referral_code,
                "referral_url": f"{BASE_URL}/r/{referral_code}",
                "bonus_requests": bonus_balance,
                "bonus_cap": BONUS_CAP,
                "bonus_lifetime": bonus_lifetime,
                "at_cap": bonus_lifetime >= BONUS_CAP,
                "stats": stats,
                "referrals": referrals,
            }, default=decimal_default),
        }

    except Exception as e:
        logger.error(f"Error in referral_status handler: {e}")
        return error_response(500, "internal_error", "An error occurred", origin=origin)
