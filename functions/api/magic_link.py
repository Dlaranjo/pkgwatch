"""
Magic Link Endpoint - POST /auth/magic-link

Sends a login link to the user's email for passwordless authentication.
"""

import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

from shared.response_utils import error_response, success_response

dynamodb = boto3.resource("dynamodb")
ses = boto3.client("ses")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
LOGIN_EMAIL_SENDER = os.environ.get(
    "LOGIN_EMAIL_SENDER", "noreply@pkgwatch.laranjo.dev"
)
BASE_URL = os.environ.get("BASE_URL", "https://pkgwatch.laranjo.dev")
API_URL = os.environ.get("API_URL", "https://api.pkgwatch.laranjo.dev")

# Email validation regex
EMAIL_REGEX = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

# Magic link TTL (15 minutes)
MAGIC_LINK_TTL_MINUTES = 15

# Minimum response time to normalize timing and prevent email enumeration
# Set to 1.5s to absorb SES latency variance and prevent timing attacks
MIN_RESPONSE_TIME_SECONDS = 1.5


def _get_origin(event: dict) -> str | None:
    """Extract Origin header from request (case-insensitive)."""
    headers = event.get("headers", {}) or {}
    return headers.get("origin") or headers.get("Origin")


def handler(event, context):
    """
    Lambda handler for POST /auth/magic-link.

    Request body:
    {
        "email": "user@example.com"
    }

    Sends a magic link to the user's email.

    Security: Returns the same response whether email exists or not
    to prevent email enumeration attacks. Uses timing normalization
    to prevent timing-based enumeration.
    """
    start_time = time.time()
    origin = _get_origin(event)

    # Generic success message - same whether email exists or not
    success_message = (
        "If an account exists with this email, a login link has been sent. "
        "Check your email (including spam folder)."
    )

    # Parse request body
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        # Validation errors can return early - they don't reveal email existence
        return error_response(400, "invalid_json", "Request body must be valid JSON", origin=origin)

    email = body.get("email", "").strip().lower()

    # Validate email format
    if not email or not EMAIL_REGEX.match(email):
        return error_response(400, "invalid_email", "Please provide a valid email address", origin=origin)

    # Check if user exists and is verified
    table = dynamodb.Table(API_KEYS_TABLE)
    try:
        response = table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(email),
        )
        items = response.get("Items", [])

        # Find a verified user (not PENDING)
        verified_user = None
        for item in items:
            if item.get("sk") != "PENDING" and item.get("email_verified", True):
                verified_user = item
                break

        if not verified_user:
            # Don't reveal whether email exists - same response as success
            # Log without full email for privacy (GDPR compliance)
            email_prefix = email.split("@")[0][:3] if "@" in email else email[:3]
            logger.info(f"Magic link requested for non-existent email: {email_prefix}***")
            return _timed_response(start_time, success_response({"message": success_message}, origin=origin))

    except Exception as e:
        logger.error(f"Error checking user: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Failed to process request", origin=origin),
        )

    user_id = verified_user["pk"]
    now = datetime.now(timezone.utc)

    # Generate magic link token
    magic_token = secrets.token_urlsafe(32)
    magic_expires = (now + timedelta(minutes=MAGIC_LINK_TTL_MINUTES)).isoformat()

    # Store magic token on the user record
    try:
        table.update_item(
            Key={"pk": user_id, "sk": verified_user["sk"]},
            UpdateExpression="SET magic_token = :token, magic_expires = :expires",
            ExpressionAttributeValues={
                ":token": magic_token,
                ":expires": magic_expires,
            },
        )
    except Exception as e:
        logger.error(f"Error storing magic token: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Failed to generate login link", origin=origin),
        )

    # Send magic link email
    # SECURITY: Return same success message even on SES failure to prevent email enumeration
    # (Returning an error would reveal that the email exists in our system)
    magic_url = f"{API_URL}/auth/callback?token={magic_token}"
    try:
        _send_magic_link_email(email, magic_url)
    except Exception as e:
        logger.error(f"Failed to send magic link email: {e}")
        # Don't reveal SES failure - return success to prevent enumeration

    # Log without full email for privacy (GDPR compliance)
    email_prefix = email.split("@")[0][:3] if "@" in email else email[:3]
    email_domain = email.split("@")[1] if "@" in email else "unknown"
    logger.info(f"Magic link sent to {email_prefix}***@{email_domain}")

    return _timed_response(start_time, success_response({"message": success_message}, origin=origin))


def _send_magic_link_email(email: str, magic_url: str):
    """Send magic link email via SES."""
    ses.send_email(
        Source=LOGIN_EMAIL_SENDER,
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Sign in to PkgWatch", "Charset": "UTF-8"},
            "Body": {
                "Html": {
                    "Data": f"""
                    <html>
                    <body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h1 style="color: #1e293b;">Sign in to PkgWatch</h1>
                        <p style="color: #475569; font-size: 16px;">
                            Click the button below to sign in to your account:
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
                            If you didn't request this, you can ignore this email.
                        </p>
                    </body>
                    </html>
                    """,
                    "Charset": "UTF-8",
                },
                "Text": {
                    "Data": f"""Sign in to PkgWatch

Click the link below to sign in to your account:

{magic_url}

IMPORTANT: This link expires in {MAGIC_LINK_TTL_MINUTES} minutes.

If you didn't request this, you can ignore this email.
""",
                    "Charset": "UTF-8",
                },
            },
        },
    )


def _timed_response(start_time: float, response: dict) -> dict:
    """
    Ensure response takes at least MIN_RESPONSE_TIME_SECONDS to prevent timing attacks.

    Attackers could measure response times to determine if an email exists
    (existing emails trigger additional operations). Normalizing timing eliminates this vector.
    """
    elapsed = time.time() - start_time
    if elapsed < MIN_RESPONSE_TIME_SECONDS:
        time.sleep(MIN_RESPONSE_TIME_SECONDS - elapsed)
    return response
