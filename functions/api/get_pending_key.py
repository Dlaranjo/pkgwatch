"""
Get Pending Key Endpoint - GET /auth/pending-key

Retrieves a newly created API key for one-time display.
Used after email verification to show the API key in the dashboard.
"""

import json
import logging
import os
from http.cookies import SimpleCookie

import boto3

from shared.response_utils import error_response, get_cors_headers

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import session verification
from api.auth_callback import verify_session_token

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")


def handler(event, context):
    """
    Lambda handler for GET /auth/pending-key.

    Returns the pending API key for one-time display and deletes it.
    Requires valid session authentication.

    Returns:
    - 200: {api_key: "pw_xxx..."}
    - 401: Not authenticated
    - 404: No pending key found (already retrieved or expired)
    """
    # Extract origin for CORS
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

        # Get pending key display record
        table = dynamodb.Table(API_KEYS_TABLE)
        response = table.get_item(Key={"pk": user_id, "sk": "PENDING_DISPLAY"})

        pending_item = response.get("Item")
        if not pending_item:
            return error_response(
                404,
                "no_pending_key",
                "No pending key found. It may have already been retrieved or expired.",
                origin=origin,
            )

        api_key = pending_item.get("api_key")

        # Delete the pending record (one-time use)
        try:
            table.delete_item(Key={"pk": user_id, "sk": "PENDING_DISPLAY"})
        except Exception as e:
            logger.warning(f"Failed to delete pending key record: {e}")
            # Continue anyway - TTL will clean it up

        # Log without revealing key
        logger.info(f"Pending key retrieved for user {user_id[:12]}...")

        # Return the API key
        response_headers = {"Content-Type": "application/json"}
        response_headers.update(get_cors_headers(origin))

        return {
            "statusCode": 200,
            "headers": response_headers,
            "body": json.dumps(
                {
                    "api_key": api_key,
                    "message": "This key will only be shown once. Please copy it now.",
                }
            ),
        }

    except Exception as e:
        logger.error(f"Error in get_pending_key handler: {e}")
        return error_response(500, "internal_error", "An error occurred", origin=origin)
