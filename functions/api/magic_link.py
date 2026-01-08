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

dynamodb = boto3.resource("dynamodb")
ses = boto3.client("ses")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "dephealth-api-keys")
LOGIN_EMAIL_SENDER = os.environ.get(
    "LOGIN_EMAIL_SENDER", "noreply@dephealth.laranjo.dev"
)
BASE_URL = os.environ.get("BASE_URL", "https://dephealth.laranjo.dev")

# Email validation regex
EMAIL_REGEX = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

# Magic link TTL (15 minutes)
MAGIC_LINK_TTL_MINUTES = 15

# Minimum response time to normalize timing and prevent email enumeration
# Set to 1.5s to absorb SES latency variance and prevent timing attacks
MIN_RESPONSE_TIME_SECONDS = 1.5


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

    # Generic success message - same whether email exists or not
    success_message = "If an account exists with this email, a login link has been sent."

    # Parse request body
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        # Validation errors can return early - they don't reveal email existence
        return _error_response(400, "invalid_json", "Request body must be valid JSON")

    email = body.get("email", "").strip().lower()

    # Validate email format
    if not email or not EMAIL_REGEX.match(email):
        return _error_response(400, "invalid_email", "Please provide a valid email address")

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
            logger.info(f"Magic link requested for non-existent email: {email}")
            return _timed_response(start_time, _success_response(success_message))

    except Exception as e:
        logger.error(f"Error checking user: {e}")
        return _timed_response(
            start_time,
            _error_response(500, "internal_error", "Failed to process request"),
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
            _error_response(500, "internal_error", "Failed to generate login link"),
        )

    # Send magic link email
    magic_url = f"{BASE_URL}/api/v1/auth/callback?token={magic_token}"
    try:
        _send_magic_link_email(email, magic_url)
    except Exception as e:
        logger.error(f"Failed to send magic link email: {e}")
        return _timed_response(
            start_time,
            _error_response(500, "internal_error", "Failed to send login email"),
        )

    logger.info(f"Magic link sent to {email}")

    return _timed_response(start_time, _success_response(success_message))


def _send_magic_link_email(email: str, magic_url: str):
    """Send magic link email via SES."""
    ses.send_email(
        Source=LOGIN_EMAIL_SENDER,
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Sign in to DepHealth", "Charset": "UTF-8"},
            "Body": {
                "Html": {
                    "Data": f"""
                    <html>
                    <body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h1 style="color: #1e293b;">Sign in to DepHealth</h1>
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
                        <p style="color: #94a3b8; font-size: 12px;">
                            This link expires in {MAGIC_LINK_TTL_MINUTES} minutes.
                            If you didn't request this, you can ignore this email.
                        </p>
                    </body>
                    </html>
                    """,
                    "Charset": "UTF-8",
                },
                "Text": {
                    "Data": f"""Sign in to DepHealth

Click the link below to sign in to your account:

{magic_url}

This link expires in {MAGIC_LINK_TTL_MINUTES} minutes. If you didn't request this, you can ignore this email.
""",
                    "Charset": "UTF-8",
                },
            },
        },
    )


def _error_response(status_code: int, code: str, message: str) -> dict:
    """Generate error response."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": {"code": code, "message": message}}),
    }


def _success_response(message: str) -> dict:
    """Generate generic success response that doesn't reveal email existence."""
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"message": message}),
    }


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
