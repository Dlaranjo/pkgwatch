"""
Recovery Verify API Key Endpoint - POST /recovery/verify-api-key

Verifies account ownership via API key and sends a magic link
to the EXISTING email address. This helps users who are locked
out of their email client but still have the email account.

Security:
- API keys can be leaked (logs, commits), so this method only
  triggers a magic link to the existing email - it does NOT
  allow changing the email address.
- Uses timing normalization to prevent enumeration.
"""

import hashlib
import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from shared.response_utils import error_response, success_response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
ses = boto3.client("ses")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
API_URL = os.environ.get("API_URL", "https://api.pkgwatch.dev")
LOGIN_EMAIL_SENDER = os.environ.get("LOGIN_EMAIL_SENDER", "noreply@pkgwatch.dev")

# Minimum response time for timing normalization (1.5s)
MIN_RESPONSE_TIME_SECONDS = 1.5

# Magic link TTL (15 minutes) - same as login flow
MAGIC_LINK_TTL_MINUTES = 15


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
    Lambda handler for POST /recovery/verify-api-key.

    Request body:
    {
        "recovery_session_id": "xxx",
        "api_key": "pw_xxx..."
    }

    Response (success):
    {
        "message": "Magic link sent to your email address"
    }

    Security:
    - API key verification only sends magic link to existing email
    - Does NOT allow email change (use recovery codes for that)
    - Timing normalized to prevent enumeration
    """
    start_time = time.time()
    origin = _get_origin(event)

    # Generic error message to prevent enumeration
    generic_error = "Invalid recovery session or API key"

    # Parse request body
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return error_response(400, "invalid_json", "Request body must be valid JSON", origin=origin)

    recovery_session_id = body.get("recovery_session_id", "").strip()
    api_key = body.get("api_key", "").strip()

    # Validate inputs
    if not recovery_session_id:
        return error_response(400, "missing_session", "Recovery session ID is required", origin=origin)

    if not api_key:
        return error_response(400, "missing_api_key", "API key is required", origin=origin)

    # Validate API key format
    if not api_key.startswith("pw_"):
        return _timed_response(
            start_time,
            error_response(400, "invalid_api_key", generic_error, origin=origin),
        )

    table = dynamodb.Table(API_KEYS_TABLE)
    now = datetime.now(timezone.utc)

    # Hash the API key for lookup
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    # Look up the API key using GSI
    try:
        key_response = table.query(
            IndexName="key-hash-index",
            KeyConditionExpression=Key("key_hash").eq(key_hash),
        )
        key_items = key_response.get("Items", [])
    except ClientError as e:
        logger.error(f"Error querying API key: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Failed to verify API key", origin=origin),
        )

    if not key_items:
        logger.warning("Invalid API key used in recovery attempt")
        return _timed_response(
            start_time,
            error_response(400, "invalid_credentials", generic_error, origin=origin),
        )

    api_key_record = key_items[0]
    user_id = api_key_record["pk"]
    email = api_key_record.get("email")

    if not email:
        logger.error(f"API key record missing email for user {user_id}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Account configuration error", origin=origin),
        )

    # Look up the recovery session
    try:
        session_response = table.get_item(
            Key={"pk": user_id, "sk": f"RECOVERY_{recovery_session_id}"}
        )
        session_item = session_response.get("Item")
    except ClientError as e:
        logger.error(f"Error fetching recovery session: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Failed to verify session", origin=origin),
        )

    # Verify session exists and is valid
    if not session_item:
        logger.warning(f"Recovery session not found: {recovery_session_id[:8]}...")
        return _timed_response(
            start_time,
            error_response(400, "invalid_session", generic_error, origin=origin),
        )

    # Check session hasn't expired (TTL may not have cleaned it up yet)
    session_ttl = session_item.get("ttl", 0)
    if session_ttl < now.timestamp():
        logger.warning(f"Recovery session expired: {recovery_session_id[:8]}...")
        return _timed_response(
            start_time,
            error_response(400, "session_expired", "Recovery session has expired. Please start over.", origin=origin),
        )

    # Check session email matches API key email
    session_email = session_item.get("email", "").lower()
    if session_email != email.lower():
        logger.warning(f"Recovery session email mismatch for user {user_id}")
        return _timed_response(
            start_time,
            error_response(400, "invalid_credentials", generic_error, origin=origin),
        )

    # API key verification successful - send magic link to EXISTING email
    # Generate magic link token
    magic_token = secrets.token_urlsafe(32)
    magic_expires = (now + timedelta(minutes=MAGIC_LINK_TTL_MINUTES)).isoformat()

    try:
        # Store magic token on the API key record
        table.update_item(
            Key={"pk": user_id, "sk": api_key_record["sk"]},
            UpdateExpression="SET magic_token = :token, magic_expires = :expires",
            ExpressionAttributeValues={
                ":token": magic_token,
                ":expires": magic_expires,
            },
        )

        # Mark recovery session as verified via API key
        # Note: This method doesn't generate a recovery_token (can't change email)
        table.update_item(
            Key={"pk": user_id, "sk": f"RECOVERY_{recovery_session_id}"},
            UpdateExpression="SET verified = :verified, recovery_method = :method, verified_at = :now",
            ExpressionAttributeValues={
                ":verified": True,
                ":method": "api_key",
                ":now": now.isoformat(),
            },
        )

    except ClientError as e:
        logger.error(f"Error updating magic token: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Failed to generate login link", origin=origin),
        )

    # Send magic link email
    magic_url = f"{API_URL}/auth/callback?token={magic_token}"
    try:
        _send_recovery_magic_link_email(email, magic_url)
    except Exception as e:
        logger.error(f"Failed to send recovery magic link email: {e}")
        # Still return success to prevent enumeration

    logger.info(f"Recovery magic link sent for user {user_id} via API key verification")

    return _timed_response(
        start_time,
        success_response(
            {
                "message": "A sign-in link has been sent to your email address. Check your inbox and spam folder.",
                "method": "api_key",
            },
            origin=origin,
        ),
    )


def _send_recovery_magic_link_email(email: str, magic_url: str):
    """Send recovery magic link email via SES."""
    ses.send_email(
        Source=LOGIN_EMAIL_SENDER,
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Sign in to PkgWatch (Account Recovery)", "Charset": "UTF-8"},
            "Body": {
                "Html": {
                    "Data": f"""
                    <html>
                    <body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h1 style="color: #1e293b;">Account Recovery</h1>
                        <p style="color: #475569; font-size: 16px;">
                            You've verified your identity using your API key. Click the button below to sign in:
                        </p>
                        <a href="{magic_url}"
                           style="display: inline-block; background: #3b82f6; color: white; padding: 12px 24px;
                                  text-decoration: none; border-radius: 6px; margin: 20px 0;">
                            Sign In
                        </a>
                        <p style="color: #64748b; font-size: 14px;">
                            Or copy this link: <a href="{magic_url}">{magic_url}</a>
                        </p>
                        <p style="color: #dc2626; font-size: 14px; font-weight: 500;">
                            <strong>Important:</strong> This link expires in {MAGIC_LINK_TTL_MINUTES} minutes.
                        </p>
                        <p style="color: #94a3b8; font-size: 12px;">
                            If you didn't request account recovery, someone may have access to your API key.
                            Consider rotating your API keys after signing in.
                        </p>
                    </body>
                    </html>
                    """,
                    "Charset": "UTF-8",
                },
                "Text": {
                    "Data": f"""Account Recovery

You've verified your identity using your API key. Click the link below to sign in:

{magic_url}

Important: This link expires in {MAGIC_LINK_TTL_MINUTES} minutes.

If you didn't request account recovery, someone may have access to your API key.
Consider rotating your API keys after signing in.
""",
                    "Charset": "UTF-8",
                },
            },
        },
    )
