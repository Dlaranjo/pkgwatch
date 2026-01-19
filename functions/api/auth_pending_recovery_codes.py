"""
Get Pending Recovery Codes Endpoint - GET /auth/pending-recovery-codes

Retrieves newly generated recovery codes for one-time display.
Used after email verification to show recovery codes in the dashboard.
"""

import json
import logging
import os
from http.cookies import SimpleCookie

import boto3
from botocore.exceptions import ClientError

from shared.response_utils import error_response, get_cors_headers

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import session verification
from api.auth_callback import verify_session_token

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")


def handler(event, context):
    """
    Lambda handler for GET /auth/pending-recovery-codes.

    Returns the pending recovery codes for one-time display and deletes them atomically.
    Also marks recovery_codes_shown=true in USER_META.
    Requires valid session authentication.

    Returns:
    - 200: {codes: ["XXXX-XXXX-XXXX-XXXX", ...]}
    - 401: Not authenticated
    - 404: No pending codes found (already retrieved or expired)
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
        table = dynamodb.Table(API_KEYS_TABLE)

        # Atomically delete and retrieve pending recovery codes
        # This prevents race conditions and ensures single-use
        try:
            response = table.delete_item(
                Key={"pk": user_id, "sk": "PENDING_RECOVERY_CODES"},
                ConditionExpression="attribute_exists(codes)",
                ReturnValues="ALL_OLD",
            )
            pending_item = response.get("Attributes")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # Record doesn't exist or was already consumed
                return error_response(
                    404,
                    "no_pending_codes",
                    "No pending recovery codes found. They may have already been retrieved or expired.",
                    origin=origin
                )
            raise

        if not pending_item:
            return error_response(
                404,
                "no_pending_codes",
                "No pending recovery codes found. They may have already been retrieved or expired.",
                origin=origin
            )

        codes = pending_item.get("codes", [])

        # Mark that recovery codes have been shown to the user
        # This helps detect if user closed browser before seeing codes
        try:
            table.update_item(
                Key={"pk": user_id, "sk": "USER_META"},
                UpdateExpression="SET recovery_codes_shown = :shown",
                ExpressionAttributeValues={":shown": True},
            )
        except Exception as e:
            logger.warning(f"Failed to update recovery_codes_shown: {e}")
            # Continue anyway - codes were retrieved successfully

        # Log without revealing codes
        logger.info(f"Pending recovery codes retrieved for user {user_id[:12]}...")

        # Return the recovery codes
        response_headers = {"Content-Type": "application/json"}
        response_headers.update(get_cors_headers(origin))

        return {
            "statusCode": 200,
            "headers": response_headers,
            "body": json.dumps({
                "codes": codes,
                "message": "These recovery codes will only be shown once. Save them in a secure location.",
            }),
        }

    except Exception as e:
        logger.error(f"Error in auth_pending_recovery_codes handler: {e}")
        return error_response(500, "internal_error", "An error occurred", origin=origin)
