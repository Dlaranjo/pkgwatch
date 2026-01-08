"""
Revoke API Key Endpoint - DELETE /api-keys/{key_id}

Revokes (deletes) an API key for the authenticated user.
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
    Lambda handler for DELETE /api-keys/{key_id}.

    Revokes the specified API key if it belongs to the authenticated user.
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

    # Get key_id from path parameters
    path_params = event.get("pathParameters") or {}
    key_id = path_params.get("key_id")

    if not key_id:
        return _error_response(400, "missing_key_id", "API key ID is required")

    # Get all API keys for user to find matching one
    table = dynamodb.Table(API_KEYS_TABLE)
    try:
        response = table.query(
            KeyConditionExpression=Key("pk").eq(user_id),
        )
        items = response.get("Items", [])

        # Find the key with matching key_id (first 16 chars of hash)
        target_key = None
        for item in items:
            if item.get("sk") == "PENDING":
                continue
            key_hash = item.get("sk", "")
            if key_hash.startswith(key_id):
                target_key = item
                break

        if not target_key:
            return _error_response(404, "key_not_found", "API key not found")

        # Count remaining keys (excluding PENDING)
        active_keys = [i for i in items if i.get("sk") != "PENDING"]
        if len(active_keys) <= 1:
            return _error_response(
                400,
                "cannot_revoke_last_key",
                "Cannot revoke your only API key. Create a new one first."
            )

        # Delete the key
        table.delete_item(
            Key={"pk": user_id, "sk": target_key["sk"]},
        )

        logger.info(f"API key revoked for user {user_id}")

    except Exception as e:
        logger.error(f"Error revoking API key: {e}")
        return _error_response(500, "internal_error", "Failed to revoke API key")

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"message": "API key revoked successfully"}),
    }


def _error_response(status_code: int, code: str, message: str) -> dict:
    """Generate error response."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": {"code": code, "message": message}}),
    }
