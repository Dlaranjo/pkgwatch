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
    try:
        # Extract origin for CORS
        headers = event.get("headers", {})
        origin = headers.get("origin") or headers.get("Origin")

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

        # Find the primary API key (not PENDING)
        user_record = None
        for item in items:
            if item.get("sk") != "PENDING":
                user_record = item
                break

        if not user_record:
            return error_response(404, "user_not_found", "User account not found", origin=origin)

        # Return user info with CORS headers
        response_headers = {"Content-Type": "application/json"}
        response_headers.update(get_cors_headers(origin))

        return {
            "statusCode": 200,
            "headers": response_headers,
            "body": json.dumps({
                "user_id": user_id,
                "email": email,
                "tier": user_record.get("tier", "free"),
                "requests_this_month": user_record.get("requests_this_month", 0),
                "monthly_limit": TIER_LIMITS.get(user_record.get("tier", "free"), TIER_LIMITS["free"]),
                "created_at": user_record.get("created_at"),
                "last_login": user_record.get("last_login"),
            }, default=decimal_default),
        }
    except Exception as e:
        logger.error(f"Error in auth_me handler: {e}")
        return error_response(500, "internal_error", "An error occurred processing your request")




