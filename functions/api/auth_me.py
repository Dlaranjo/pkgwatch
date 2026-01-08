"""
Auth Me Endpoint - GET /auth/me

Returns current authenticated user info from session cookie.
"""

import json
import logging
import os
from http.cookies import SimpleCookie

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import session verification
from api.auth_callback import verify_session_token

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "dephealth-api-keys")


def handler(event, context):
    """
    Lambda handler for GET /auth/me.

    Returns the current authenticated user's info.
    """
    # Extract session cookie
    headers = event.get("headers", {})
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""

    session_token = None
    if cookie_header:
        cookies = SimpleCookie()
        cookies.load(cookie_header)
        if "session" in cookies:
            session_token = cookies["session"].value

    if not session_token:
        return _error_response(401, "unauthorized", "Not authenticated")

    # Verify session token
    session_data = verify_session_token(session_token)
    if not session_data:
        return _error_response(401, "session_expired", "Session expired. Please log in again.")

    user_id = session_data.get("user_id")
    email = session_data.get("email")

    # Get fresh user data from DynamoDB
    table = dynamodb.Table(API_KEYS_TABLE)
    try:
        response = table.query(
            KeyConditionExpression=Key("pk").eq(user_id),
        )
        items = response.get("Items", [])

        # Find the primary API key (not PENDING)
        user_record = None
        for item in items:
            if item.get("sk") != "PENDING":
                user_record = item
                break

        if not user_record:
            return _error_response(404, "user_not_found", "User account not found")

    except Exception as e:
        logger.error(f"Error fetching user data: {e}")
        return _error_response(500, "internal_error", "Failed to fetch user data")

    # Return user info
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "user_id": user_id,
            "email": email,
            "tier": user_record.get("tier", "free"),
            "requests_this_month": user_record.get("requests_this_month", 0),
            "monthly_limit": _get_tier_limit(user_record.get("tier", "free")),
            "created_at": user_record.get("created_at"),
            "last_login": user_record.get("last_login"),
        }),
    }


def _get_tier_limit(tier: str) -> int:
    """Get monthly limit for tier."""
    limits = {
        "free": 5000,
        "starter": 25000,
        "pro": 100000,
        "business": 500000,
    }
    return limits.get(tier, 5000)


def _error_response(status_code: int, code: str, message: str) -> dict:
    """Generate error response."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": {"code": code, "message": message}}),
    }
