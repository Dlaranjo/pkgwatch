"""
Get API Keys Endpoint - GET /api-keys

Lists all API keys for the authenticated user.
"""

import json
import logging
import os
from http.cookies import SimpleCookie

import boto3
from boto3.dynamodb.conditions import Key

from shared.auth import is_api_key_record
from shared.response_utils import decimal_default, error_response, get_cors_headers

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import session verification
from api.auth_callback import verify_session_token

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")


def handler(event, context):
    """
    Lambda handler for GET /api-keys.

    Returns all API keys for the authenticated user.
    Note: Only returns key metadata (prefix, creation date, usage) - not the actual keys.
    """
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

    # Get all API keys for user
    table = dynamodb.Table(API_KEYS_TABLE)
    try:
        response = table.query(
            KeyConditionExpression=Key("pk").eq(user_id),
        )
        items = response.get("Items", [])

        # Filter out pending signups, user metadata, pending display records,
        # recovery codes, and recovery sessions - only keep actual API key records
        api_keys = []
        for item in items:
            sk = item.get("sk", "")
            if not is_api_key_record(sk):
                continue

            key_hash = sk or ""
            # Use stored key_suffix if available, fall back to hash suffix for old keys
            key_suffix = item.get("key_suffix") or key_hash[-8:]
            api_keys.append(
                {
                    "key_id": key_hash[:16],  # First 16 chars of hash as identifier
                    "key_prefix": f"pw_....{key_suffix}",  # Show actual key suffix
                    "tier": item.get("tier", "free"),
                    "requests_this_month": item.get("requests_this_month", 0),
                    "created_at": item.get("created_at"),
                    "last_used": item.get("last_used"),
                }
            )

    except Exception as e:
        logger.error(f"Error fetching API keys: {e}")
        return error_response(500, "internal_error", "Failed to fetch API keys", origin=origin)

    # Return with CORS headers and no-cache to prevent stale data
    response_headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }
    response_headers.update(get_cors_headers(origin))

    return {
        "statusCode": 200,
        "headers": response_headers,
        "body": json.dumps({"api_keys": api_keys}, default=decimal_default),
    }
