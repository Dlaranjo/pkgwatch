"""
Recovery Initiate Endpoint - POST /recovery/initiate

Starts the account recovery flow. Creates a recovery session
that can be completed with either an API key (triggers magic link)
or a recovery code (allows email change).

Security:
- Uses timing normalization to prevent email enumeration
- Returns consistent responses whether email exists or not
- Rate limited per IP (handled by WAF) and per user
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from shared.recovery_utils import generate_recovery_session_id, mask_email
from shared.response_utils import error_response, success_response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")

# Minimum response time to prevent timing-based enumeration (1.5s)
MIN_RESPONSE_TIME_SECONDS = 1.5

# Recovery session TTL (4 hours)
RECOVERY_SESSION_TTL_SECONDS = 14400

# Rate limiting: max attempts per user per 24 hours
MAX_RECOVERY_ATTEMPTS_PER_DAY = 10


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
    Lambda handler for POST /recovery/initiate.

    Request body:
    {
        "email": "user@example.com"
    }

    Response (success):
    {
        "recovery_session_id": "xxx",
        "masked_email": "j***@example.com",
        "has_recovery_codes": true,
        "message": "Recovery session created"
    }

    Security: Returns consistent error messages and timing
    to prevent email enumeration attacks.
    """
    start_time = time.time()
    origin = _get_origin(event)

    # Parse request body
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        # Validation errors can return early - they don't reveal email existence
        return error_response(400, "invalid_json", "Request body must be valid JSON", origin=origin)

    email = body.get("email", "").strip().lower()

    # Validate email format
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        return error_response(400, "invalid_email", "Please provide a valid email address", origin=origin)

    table = dynamodb.Table(API_KEYS_TABLE)

    # Look up user by email using GSI
    try:
        response = table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(email),
        )
        items = response.get("Items", [])
    except ClientError as e:
        logger.error(f"Error querying for email: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Failed to process request", origin=origin),
        )

    # Find a user record (not PENDING record)
    # Note: We allow recovery for unverified users too - they have a legitimate
    # account and API key, even if they never clicked the email verification link.
    user_item = None
    user_meta = None
    for item in items:
        sk = item.get("sk", "")
        if sk == "PENDING":
            continue
        elif sk == "USER_META":
            user_meta = item
        else:
            # Accept both verified and unverified API key records
            user_item = item

    # If no user found, still create a fake session for timing normalization
    # but don't actually store anything - this prevents enumeration
    if not user_item:
        # Generate a fake session ID but don't store it
        fake_session_id = generate_recovery_session_id()
        logger.info("Recovery initiated for non-existent email (not revealing)")
        return _timed_response(
            start_time,
            success_response(
                {
                    "recovery_session_id": fake_session_id,
                    "masked_email": mask_email(email),
                    "has_recovery_codes": False,
                    "message": "Recovery session created. Choose a verification method.",
                },
                origin=origin,
            ),
        )

    user_id = user_item["pk"]

    # Fetch USER_META separately (not returned by email-index GSI since it lacks email field)
    if not user_meta:
        try:
            meta_response = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
            user_meta = meta_response.get("Item")
        except ClientError as e:
            logger.warning(f"Error fetching USER_META for {user_id}: {e}")
            # Continue without user_meta - recovery codes check will fail gracefully

    # Check per-user rate limiting
    now = datetime.now(timezone.utc)
    today_key = now.strftime("%Y-%m-%d")

    if user_meta:
        reset_date = user_meta.get("recovery_attempts_reset_at", "")
        attempts_today = user_meta.get("recovery_attempts_today", 0)

        if reset_date == today_key and attempts_today >= MAX_RECOVERY_ATTEMPTS_PER_DAY:
            logger.warning(f"Recovery rate limit exceeded for user {user_id}")
            return _timed_response(
                start_time,
                error_response(
                    429,
                    "rate_limited",
                    "Too many recovery attempts. Please try again tomorrow.",
                    origin=origin,
                    retry_after=3600,
                ),
            )

    # Check if user has recovery codes
    has_recovery_codes = False
    if user_meta:
        recovery_codes_hash = user_meta.get("recovery_codes_hash", [])
        has_recovery_codes = len(recovery_codes_hash) > 0

    # Create recovery session
    session_id = generate_recovery_session_id()
    session_expires = now + timedelta(seconds=RECOVERY_SESSION_TTL_SECONDS)
    ttl_timestamp = int(session_expires.timestamp())

    try:
        # Store recovery session record
        table.put_item(
            Item={
                "pk": user_id,
                "sk": f"RECOVERY_{session_id}",
                "email": email,
                "recovery_session_id": session_id,
                "verified": False,
                "recovery_method": None,  # Set when user chooses method
                "recovery_token": None,  # Generated after code verification
                "created_at": now.isoformat(),
                "ttl": ttl_timestamp,
            }
        )

        # Increment rate limit counter
        if user_meta and user_meta.get("recovery_attempts_reset_at") == today_key:
            # Same day, increment counter
            table.update_item(
                Key={"pk": user_id, "sk": "USER_META"},
                UpdateExpression="SET recovery_attempts_today = if_not_exists(recovery_attempts_today, :zero) + :one",
                ExpressionAttributeValues={":one": 1, ":zero": 0},
            )
        else:
            # New day, reset counter
            table.update_item(
                Key={"pk": user_id, "sk": "USER_META"},
                UpdateExpression="SET recovery_attempts_today = :one, recovery_attempts_reset_at = :today",
                ExpressionAttributeValues={":one": 1, ":today": today_key},
            )

    except ClientError as e:
        logger.error(f"Error creating recovery session: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Failed to create recovery session", origin=origin),
        )

    logger.info(f"Recovery session created for user {user_id}")

    return _timed_response(
        start_time,
        success_response(
            {
                "recovery_session_id": session_id,
                "masked_email": mask_email(email),
                "has_recovery_codes": has_recovery_codes,
                "message": "Recovery session created. Choose a verification method.",
            },
            origin=origin,
        ),
    )
