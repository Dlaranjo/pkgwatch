"""
Auth Me Endpoint - GET /auth/me

Returns current authenticated user info from session cookie.
"""

import json
import logging
import os
from decimal import Decimal
from http.cookies import SimpleCookie

import boto3
from boto3.dynamodb.conditions import Key

from shared.response_utils import decimal_default, error_response, get_cors_headers
from shared.constants import TIER_LIMITS

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import session verification
from api.auth_callback import verify_session_token

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")


def handler(event, context):
    """
    Lambda handler for GET /auth/me.

    Returns the current authenticated user's info.
    """
    # Extract origin for CORS (outside try block so exception handler can use it)
    headers = event.get("headers", {}) or {}
    origin = headers.get("origin") or headers.get("Origin")

    try:

        # Extract session cookie
        cookie_header = headers.get("cookie") or headers.get("Cookie") or ""

        session_token = None
        if cookie_header:
            cookies = SimpleCookie()
            cookies.load(cookie_header)
            if "session" in cookies:
                session_token = cookies["session"].value

        if not session_token:
            return error_response(401, "unauthorized", "Not authenticated", origin=origin)

        # Verify session token
        session_data = verify_session_token(session_token)
        if not session_data:
            return error_response(401, "session_expired", "Session expired. Please log in again.", origin=origin)

        user_id = session_data.get("user_id")
        email = session_data.get("email")

        # Get fresh user data from DynamoDB
        table = dynamodb.Table(API_KEYS_TABLE)
        response = table.query(
            KeyConditionExpression=Key("pk").eq(user_id),
        )
        items = response.get("Items", [])

        # Separate API keys from metadata records
        api_keys = []
        user_meta = None
        for item in items:
            sk = item.get("sk", "")
            if sk == "PENDING":
                continue
            elif sk == "USER_META":
                user_meta = item
            else:
                api_keys.append(item)

        if not api_keys:
            return error_response(404, "user_not_found", "User account not found", origin=origin)

        # Get authoritative usage from USER_META (if exists)
        # Fall back to aggregating per-key counters for backward compatibility
        if user_meta and "requests_this_month" in user_meta:
            total_requests = int(user_meta.get("requests_this_month", 0))
        else:
            # Backward compatibility: sum per-key counters
            total_requests = sum(
                int(key.get("requests_this_month", 0))
                for key in api_keys
            )

        # Use the first key for metadata (tier, created_at, etc.)
        # All keys should have the same tier
        primary_key = api_keys[0]

        # Return user info with CORS headers and no-cache to prevent stale data
        response_headers = {
            "Content-Type": "application/json",
            "Cache-Control": "no-store, no-cache, must-revalidate",
        }
        response_headers.update(get_cors_headers(origin))

        return {
            "statusCode": 200,
            "headers": response_headers,
            "body": json.dumps({
                "user_id": user_id,
                "email": email,
                "tier": primary_key.get("tier", "free"),
                "requests_this_month": total_requests,
                "monthly_limit": TIER_LIMITS.get(primary_key.get("tier", "free"), TIER_LIMITS["free"]),
                "created_at": primary_key.get("created_at"),
                "last_login": primary_key.get("last_login"),
            }, default=decimal_default),
        }
    except Exception as e:
        logger.error(f"Error in auth_me handler: {e}")
        return error_response(500, "internal_error", "An error occurred processing your request", origin=origin)




