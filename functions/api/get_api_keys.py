"""
Get API Keys Endpoint - GET /api-keys

Lists all API keys for the authenticated user.
"""

import json
import logging
import os
from decimal import Decimal
from http.cookies import SimpleCookie

import boto3


from boto3.dynamodb.conditions import Key


def _decimal_default(obj):
    """JSON encoder for Decimal types from DynamoDB."""
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import session verification
from api.auth_callback import verify_session_token

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "dephealth-api-keys")


def handler(event, context):
    """
    Lambda handler for GET /api-keys.

    Returns all API keys for the authenticated user.
    Note: Only returns key metadata (prefix, creation date, usage) - not the actual keys.
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

    # Get all API keys for user
    table = dynamodb.Table(API_KEYS_TABLE)
    try:
        response = table.query(
            KeyConditionExpression=Key("pk").eq(user_id),
        )
        items = response.get("Items", [])

        # Filter out pending signups, user metadata, and format response
        api_keys = []
        for item in items:
            sk = item.get("sk")
            if sk == "PENDING" or sk == "USER_META":
                continue

            key_hash = sk or ""
            api_keys.append({
                "key_id": key_hash[:16],  # First 16 chars of hash as identifier
                "key_prefix": f"dh_...{key_hash[-8:]}",  # Show suffix only
                "tier": item.get("tier", "free"),
                "requests_this_month": item.get("requests_this_month", 0),
                "created_at": item.get("created_at"),
                "last_used": item.get("last_used"),
            })

    except Exception as e:
        logger.error(f"Error fetching API keys: {e}")
        return _error_response(500, "internal_error", "Failed to fetch API keys")

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"api_keys": api_keys}, default=_decimal_default),
    }


def _error_response(status_code: int, code: str, message: str) -> dict:
    """Generate error response."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": {"code": code, "message": message}}),
    }
