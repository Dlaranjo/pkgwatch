"""
Create API Key Endpoint - POST /api-keys

Creates a new API key for the authenticated user.
"""

import json
import logging
import os
from http.cookies import SimpleCookie

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import session verification and key generation
from api.auth_callback import verify_session_token
from shared.auth import generate_api_key

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "dephealth-api-keys")

# Max keys per user
MAX_KEYS_PER_USER = 5


def handler(event, context):
    """
    Lambda handler for POST /api-keys.

    Creates a new API key for the authenticated user.
    Returns the full API key (shown only once).
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
    tier = session_data.get("tier", "free")

    # Check existing key count
    table = dynamodb.Table(API_KEYS_TABLE)
    try:
        response = table.query(
            KeyConditionExpression=Key("pk").eq(user_id),
        )
        items = response.get("Items", [])

        # Count active keys (excluding PENDING)
        active_keys = [i for i in items if i.get("sk") != "PENDING"]
        if len(active_keys) >= MAX_KEYS_PER_USER:
            return _error_response(
                400,
                "max_keys_reached",
                f"Maximum {MAX_KEYS_PER_USER} API keys allowed. Revoke an existing key to create a new one."
            )

    except Exception as e:
        logger.error(f"Error checking key count: {e}")
        return _error_response(500, "internal_error", "Failed to create API key")

    # Generate new API key
    try:
        api_key = generate_api_key(user_id=user_id, tier=tier, email=email)
    except Exception as e:
        logger.error(f"Error generating API key: {e}")
        return _error_response(500, "internal_error", "Failed to create API key")

    logger.info(f"New API key created for user {user_id}")

    return {
        "statusCode": 201,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "api_key": api_key,
            "message": "API key created. This key will only be shown once - save it securely!",
        }),
    }


def _error_response(status_code: int, code: str, message: str) -> dict:
    """Generate error response."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": {"code": code, "message": message}}),
    }
