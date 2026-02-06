"""
Account Recovery Codes Endpoints.

Authenticated endpoints for managing recovery codes:
- POST /account/recovery-codes - Generate new recovery codes
- DELETE /account/recovery-codes - Invalidate all recovery codes
- GET /account/recovery-codes/status - Check if codes exist
"""

import logging
import os
from datetime import datetime, timezone
from http.cookies import SimpleCookie

import boto3
from botocore.exceptions import ClientError

from api.auth_callback import verify_session_token
from shared.recovery_utils import generate_recovery_codes
from shared.response_utils import error_response, success_response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")

# Maximum number of recovery codes
MAX_RECOVERY_CODES = 4


def _get_origin(event: dict) -> str | None:
    """Extract Origin header from request (case-insensitive)."""
    headers = event.get("headers", {}) or {}
    return headers.get("origin") or headers.get("Origin")


def _get_session(event: dict) -> dict | None:
    """Extract and verify session from cookie.

    Returns:
        Session data dict with user_id, email, tier, exp or None if invalid
    """
    headers = event.get("headers", {}) or {}
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""

    if not cookie_header:
        return None

    cookies = SimpleCookie()
    cookies.load(cookie_header)

    if "session" not in cookies:
        return None

    session_token = cookies["session"].value
    return verify_session_token(session_token)


def handler(event, context):
    """
    Lambda handler for /account/recovery-codes endpoints.

    Routes based on HTTP method:
    - POST: Generate new recovery codes
    - DELETE: Invalidate all recovery codes
    - GET: Check recovery codes status
    """
    origin = _get_origin(event)
    method = event.get("httpMethod", "")

    # Verify authentication
    session = _get_session(event)
    if not session:
        return error_response(401, "unauthorized", "Not authenticated", origin=origin)

    user_id = session.get("user_id")
    if not user_id:
        return error_response(401, "unauthorized", "Invalid session", origin=origin)

    # Route to appropriate handler
    if method == "POST":
        return _handle_generate_codes(user_id, origin)
    elif method == "DELETE":
        return _handle_delete_codes(user_id, origin)
    elif method == "GET":
        return _handle_get_status(user_id, origin)
    else:
        return error_response(405, "method_not_allowed", f"Method {method} not allowed", origin=origin)


def _handle_generate_codes(user_id: str, origin: str | None) -> dict:
    """
    Generate new recovery codes.

    Generates 8 new codes, stores bcrypt hashes in USER_META record.
    Returns plaintext codes (shown to user once only).

    Previous codes are invalidated when new codes are generated.
    """
    table = dynamodb.Table(API_KEYS_TABLE)
    now = datetime.now(timezone.utc).isoformat()

    # Generate recovery codes
    plaintext_codes, hashed_codes = generate_recovery_codes(count=MAX_RECOVERY_CODES)

    try:
        # Store hashes in USER_META record
        # Create USER_META if it doesn't exist
        table.update_item(
            Key={"pk": user_id, "sk": "USER_META"},
            UpdateExpression=(
                "SET recovery_codes_hash = :hashes, "
                "recovery_codes_generated_at = :generated_at, "
                "recovery_codes_count = :count"
            ),
            ExpressionAttributeValues={
                ":hashes": hashed_codes,
                ":generated_at": now,
                ":count": len(hashed_codes),
            },
        )

        logger.info(f"Generated {len(plaintext_codes)} recovery codes for user {user_id}")

        return success_response(
            {
                "message": "Recovery codes generated successfully. Store these securely - they will not be shown again.",
                "codes": plaintext_codes,
                "codes_count": len(plaintext_codes),
                "generated_at": now,
            },
            origin=origin,
        )

    except ClientError as e:
        logger.error(f"Error generating recovery codes: {e}")
        return error_response(
            500, "internal_error", "Failed to generate recovery codes", origin=origin
        )


def _handle_delete_codes(user_id: str, origin: str | None) -> dict:
    """
    Invalidate all recovery codes.

    Removes recovery_codes_hash from USER_META record.
    """
    table = dynamodb.Table(API_KEYS_TABLE)

    try:
        # Remove recovery codes from USER_META
        table.update_item(
            Key={"pk": user_id, "sk": "USER_META"},
            UpdateExpression="REMOVE recovery_codes_hash, recovery_codes_generated_at, recovery_codes_count",
            ConditionExpression="attribute_exists(pk)",
        )

        logger.info(f"Invalidated recovery codes for user {user_id}")

        return success_response(
            {"message": "Recovery codes have been invalidated"},
            origin=origin,
        )

    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # USER_META doesn't exist - that's fine, nothing to delete
            return success_response(
                {"message": "No recovery codes to invalidate"},
                origin=origin,
            )
        logger.error(f"Error deleting recovery codes: {e}")
        return error_response(
            500, "internal_error", "Failed to invalidate recovery codes", origin=origin
        )


def _handle_get_status(user_id: str, origin: str | None) -> dict:
    """
    Get recovery codes status.

    Returns whether codes exist, when they were generated,
    and how many are remaining.
    """
    table = dynamodb.Table(API_KEYS_TABLE)

    try:
        response = table.get_item(
            Key={"pk": user_id, "sk": "USER_META"},
            ProjectionExpression="recovery_codes_hash, recovery_codes_generated_at, recovery_codes_count",
        )

        item = response.get("Item", {})
        hashes = item.get("recovery_codes_hash", [])
        generated_at = item.get("recovery_codes_generated_at")
        original_count = item.get("recovery_codes_count", 0)

        has_codes = len(hashes) > 0
        codes_remaining = len(hashes)

        return success_response(
            {
                "has_codes": has_codes,
                "codes_remaining": codes_remaining,
                "generated_at": generated_at,
                "original_count": original_count,
            },
            origin=origin,
        )

    except ClientError as e:
        logger.error(f"Error getting recovery codes status: {e}")
        return error_response(
            500, "internal_error", "Failed to get recovery codes status", origin=origin
        )
