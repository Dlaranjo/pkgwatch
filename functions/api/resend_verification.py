"""
Resend Verification Email Endpoint - POST /auth/resend-verification

Resends verification email for pending signups with cooldown enforcement.
Security: Uses timing normalization and uniform responses to prevent email enumeration.
"""

import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

from shared.response_utils import error_response, success_response

# Minimum response time to normalize timing and prevent enumeration
MIN_RESPONSE_TIME_SECONDS = 1.5

# Cooldown between resend requests (60 seconds)
RESEND_COOLDOWN_SECONDS = 60

dynamodb = boto3.resource("dynamodb")
ses = boto3.client("ses")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
VERIFICATION_EMAIL_SENDER = os.environ.get(
    "VERIFICATION_EMAIL_SENDER", "noreply@pkgwatch.laranjo.dev"
)
BASE_URL = os.environ.get("BASE_URL", "https://pkgwatch.laranjo.dev")


def _get_origin(event: dict) -> str | None:
    """Extract Origin header from request (case-insensitive)."""
    headers = event.get("headers", {}) or {}
    return headers.get("origin") or headers.get("Origin")


def handler(event, context):
    """
    Lambda handler for POST /auth/resend-verification.

    Request body:
    {
        "email": "user@example.com"
    }

    Resends verification email for pending signups.
    Enforces 60-second cooldown between resends.

    Security: Returns the same response whether email exists or not
    to prevent email enumeration attacks.
    """
    start_time = time.time()
    origin = _get_origin(event)

    # Generic success message - same whether email exists or not
    success_message = (
        "If your email is pending verification, we've sent a new verification link. "
        "Check your email (including spam folder)."
    )

    # Parse request body (use `or "{}"` to handle explicit None)
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return error_response(400, "invalid_json", "Request body must be valid JSON", origin=origin)

    email = body.get("email", "").strip().lower()

    # Basic email validation
    if not email or "@" not in email:
        return error_response(400, "invalid_email", "Please provide a valid email address", origin=origin)

    table = dynamodb.Table(API_KEYS_TABLE)
    now = datetime.now(timezone.utc)

    try:
        # Query for pending signup with this email
        response = table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(email),
        )
        items = response.get("Items", [])

        # Find PENDING record
        pending_item = None
        for item in items:
            if item.get("sk") == "PENDING":
                pending_item = item
                break

        if not pending_item:
            # No pending signup - return same response for enumeration prevention
            logger.info("Resend requested for non-existent pending signup")
            return _timed_response(start_time, success_response({"message": success_message}, origin=origin))

        # Check cooldown
        last_sent = pending_item.get("last_verification_sent")
        if last_sent:
            try:
                last_sent_dt = datetime.fromisoformat(last_sent.replace("Z", "+00:00"))
                seconds_since_last = (now - last_sent_dt).total_seconds()
                if seconds_since_last < RESEND_COOLDOWN_SECONDS:
                    remaining = int(RESEND_COOLDOWN_SECONDS - seconds_since_last)
                    return _timed_response(
                        start_time,
                        error_response(
                            429,
                            "cooldown",
                            f"Please wait {remaining} seconds before requesting another email.",
                            origin=origin
                        )
                    )
            except (ValueError, TypeError):
                pass

        # Generate new verification token
        verification_token = secrets.token_urlsafe(32)
        verification_expires = (now + timedelta(hours=24)).isoformat()

        # Update PENDING record with new token and timestamp
        user_id = pending_item["pk"]
        table.update_item(
            Key={"pk": user_id, "sk": "PENDING"},
            UpdateExpression="SET verification_token = :token, verification_expires = :expires, last_verification_sent = :sent",
            ExpressionAttributeValues={
                ":token": verification_token,
                ":expires": verification_expires,
                ":sent": now.isoformat(),
            },
        )

        # Send verification email
        verification_url = f"{BASE_URL}/verify?token={verification_token}"
        try:
            _send_verification_email(email, verification_url)
        except Exception as e:
            logger.error(f"Failed to send verification email: {e}")
            # Don't fail - still return success for enumeration prevention

        # Log without full email for privacy
        email_prefix = email.split("@")[0][:3] if "@" in email else email[:3]
        email_domain = email.split("@")[1] if "@" in email else "unknown"
        logger.info(f"Verification email resent for {email_prefix}***@{email_domain}")

    except Exception as e:
        logger.error(f"Error in resend verification: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "An error occurred. Please try again.", origin=origin),
        )

    return _timed_response(start_time, success_response({"message": success_message}, origin=origin))


def _send_verification_email(email: str, verification_url: str):
    """Send verification email via SES."""
    ses.send_email(
        Source=VERIFICATION_EMAIL_SENDER,
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Verify your PkgWatch account", "Charset": "UTF-8"},
            "Body": {
                "Html": {
                    "Data": f"""
                    <html>
                    <body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h1 style="color: #1e293b;">Welcome to PkgWatch</h1>
                        <p style="color: #475569; font-size: 16px;">
                            Click the button below to verify your email and get your API key:
                        </p>
                        <a href="{verification_url}"
                           style="display: inline-block; background: #3b82f6; color: white; padding: 12px 24px;
                                  text-decoration: none; border-radius: 6px; margin: 20px 0;">
                            Verify Email
                        </a>
                        <p style="color: #64748b; font-size: 14px;">
                            Or copy this link: <a href="{verification_url}">{verification_url}</a>
                        </p>
                        <p style="color: #94a3b8; font-size: 12px;">
                            This link expires in 24 hours. If you didn't sign up for PkgWatch, you can ignore this email.
                        </p>
                    </body>
                    </html>
                    """,
                    "Charset": "UTF-8",
                },
                "Text": {
                    "Data": f"""Welcome to PkgWatch

Click the link below to verify your email and get your API key:

{verification_url}

This link expires in 24 hours. If you didn't sign up for PkgWatch, you can ignore this email.
""",
                    "Charset": "UTF-8",
                },
            },
        },
    )


def _timed_response(start_time: float, response: dict) -> dict:
    """
    Ensure response takes at least MIN_RESPONSE_TIME_SECONDS to prevent timing attacks.
    """
    elapsed = time.time() - start_time
    if elapsed < MIN_RESPONSE_TIME_SECONDS:
        time.sleep(MIN_RESPONSE_TIME_SECONDS - elapsed)
    return response
