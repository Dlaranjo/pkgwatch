"""
Recovery Verify Code Endpoint - POST /recovery/verify-code

Verifies account ownership via recovery code and generates
a recovery token that allows updating the email address.

Security:
- Recovery codes are stored offline by users (more secure than API keys)
- This method allows email change (true account recovery)
- Used codes are atomically consumed to prevent replay
- Uses timing normalization to prevent enumeration
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from shared.recovery_utils import (
    generate_recovery_token,
    verify_recovery_code,
    validate_recovery_code_format,
)
from shared.response_utils import error_response, success_response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")

# Minimum response time for timing normalization (1.5s)
MIN_RESPONSE_TIME_SECONDS = 1.5


def _get_origin(event: dict) -> str | None:
    """Extract Origin header from request (case-insensitive)."""
    headers = event.get("headers", {}) or {}
    return headers.get("origin") or headers.get("Origin")


def _timed_response(start_time: float, response: dict) -> dict:
    """Ensure response takes at least MIN_RESPONSE_TIME_SECONDS."""
    elapsed = time.time() - start_time
    if elapsed < MIN_RESPONSE_TIME_SECONDS:
        time.sleep(MIN_RESPONSE_TIME_SECONDS - elapsed)
    return response


def handler(event, context):
    """
    Lambda handler for POST /recovery/verify-code.

    Request body:
    {
        "recovery_session_id": "xxx",
        "recovery_code": "XXXX-XXXX-XXXX-XXXX"
    }

    Response (success):
    {
        "recovery_token": "xxx",
        "codes_remaining": 7,
        "message": "Recovery code verified. You can now update your email."
    }

    Security:
    - Code is atomically consumed after verification
    - Generates recovery_token for email update step
    - Timing normalized to prevent enumeration
    """
    start_time = time.time()
    origin = _get_origin(event)

    # Generic error message to prevent enumeration
    generic_error = "Invalid recovery session or code"

    # Parse request body
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return error_response(400, "invalid_json", "Request body must be valid JSON", origin=origin)

    recovery_session_id = body.get("recovery_session_id", "").strip()
    recovery_code = body.get("recovery_code", "").strip()

    # Validate inputs
    if not recovery_session_id:
        return error_response(400, "missing_session", "Recovery session ID is required", origin=origin)

    if not recovery_code:
        return error_response(400, "missing_code", "Recovery code is required", origin=origin)

    # Validate code format
    if not validate_recovery_code_format(recovery_code):
        return _timed_response(
            start_time,
            error_response(400, "invalid_code_format", "Invalid recovery code format", origin=origin),
        )

    table = dynamodb.Table(API_KEYS_TABLE)
    now = datetime.now(timezone.utc)

    # We need to find the recovery session first to get the user_id
    # Since we don't know the user_id yet, we need to scan for the session
    # This is acceptable because recovery sessions have a 1-hour TTL
    # and the recovery flow is not high-frequency

    # First, let's try to find any session with this ID by scanning
    # In production, you might want a GSI on recovery_session_id
    # For now, we'll use a scan with a filter (sessions are short-lived)

    try:
        # Scan for the recovery session
        # Note: This is acceptable for recovery flow which is low-frequency
        scan_response = table.scan(
            FilterExpression="recovery_session_id = :session_id",
            ExpressionAttributeValues={":session_id": recovery_session_id},
            ProjectionExpression="pk, sk, email, #ttl_attr, verified, recovery_method",
            ExpressionAttributeNames={"#ttl_attr": "ttl"},
        )
        sessions = scan_response.get("Items", [])
    except ClientError as e:
        logger.error(f"Error scanning for recovery session: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Failed to verify session", origin=origin),
        )

    if not sessions:
        logger.warning(f"Recovery session not found: {recovery_session_id[:8]}...")
        return _timed_response(
            start_time,
            error_response(400, "invalid_session", generic_error, origin=origin),
        )

    session_item = sessions[0]
    user_id = session_item["pk"]

    # Check session hasn't expired
    session_ttl = session_item.get("ttl", 0)
    if session_ttl < now.timestamp():
        logger.warning(f"Recovery session expired: {recovery_session_id[:8]}...")
        return _timed_response(
            start_time,
            error_response(400, "session_expired", "Recovery session has expired. Please start over.", origin=origin),
        )

    # Get USER_META to find recovery codes
    try:
        meta_response = table.get_item(
            Key={"pk": user_id, "sk": "USER_META"},
            ProjectionExpression="recovery_codes_hash",
        )
        user_meta = meta_response.get("Item", {})
    except ClientError as e:
        logger.error(f"Error fetching USER_META: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Failed to verify code", origin=origin),
        )

    recovery_codes_hash = user_meta.get("recovery_codes_hash", [])

    if not recovery_codes_hash:
        logger.warning(f"No recovery codes set for user {user_id}")
        return _timed_response(
            start_time,
            error_response(400, "no_recovery_codes", "No recovery codes set up for this account", origin=origin),
        )

    # Verify the recovery code
    is_valid, code_index = verify_recovery_code(recovery_code, recovery_codes_hash)

    if not is_valid:
        logger.warning(f"Invalid recovery code attempt for user {user_id}")
        return _timed_response(
            start_time,
            error_response(400, "invalid_code", generic_error, origin=origin),
        )

    # Code is valid - atomically remove it from the list
    # Generate recovery token for email update
    recovery_token = generate_recovery_token()

    try:
        # Remove the used code from the list
        # Using SET with list_remove doesn't exist, so we need to rebuild the list
        new_codes = [h for i, h in enumerate(recovery_codes_hash) if i != code_index]

        # Update USER_META to remove used code with optimistic locking
        # ConditionExpression ensures no concurrent modification (race condition prevention)
        table.update_item(
            Key={"pk": user_id, "sk": "USER_META"},
            UpdateExpression="SET recovery_codes_hash = :new_codes",
            ConditionExpression="size(recovery_codes_hash) = :expected_count",
            ExpressionAttributeValues={
                ":new_codes": new_codes,
                ":expected_count": len(recovery_codes_hash),
            },
        )

        # Update recovery session with verification info and token
        table.update_item(
            Key={"pk": user_id, "sk": f"RECOVERY_{recovery_session_id}"},
            UpdateExpression=(
                "SET verified = :verified, "
                "recovery_method = :method, "
                "recovery_token = :token, "
                "verified_at = :now"
            ),
            ExpressionAttributeValues={
                ":verified": True,
                ":method": "recovery_code",
                ":token": recovery_token,
                ":now": now.isoformat(),
            },
        )

    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Race condition: codes were modified by concurrent request
            logger.warning(f"Race condition detected consuming recovery code for user {user_id}")
            return _timed_response(
                start_time,
                error_response(409, "concurrent_modification", "Recovery code was already used. Please try again.", origin=origin),
            )
        logger.error(f"Error consuming recovery code: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Failed to process recovery code", origin=origin),
        )

    codes_remaining = len(new_codes)
    logger.info(f"Recovery code verified for user {user_id}, {codes_remaining} codes remaining")

    return _timed_response(
        start_time,
        success_response(
            {
                "recovery_token": recovery_token,
                "codes_remaining": codes_remaining,
                "message": "Recovery code verified. You can now update your email address.",
            },
            origin=origin,
        ),
    )
