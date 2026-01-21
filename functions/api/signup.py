"""
Signup Endpoint - POST /signup

Creates a pending user account and sends verification email.
Security: Uses timing normalization and uniform responses to prevent email enumeration.
"""

import hashlib
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
from shared.referral_utils import (
    is_disposable_email,
    is_valid_referral_code,
    lookup_referrer_by_code,
)

# Minimum response time to normalize timing and prevent enumeration
# Set to 1.5s to fully absorb worst-case SES latency variance (~200-500ms)
MIN_RESPONSE_TIME_SECONDS = 1.5

dynamodb = boto3.resource("dynamodb")
ses = boto3.client("ses")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
VERIFICATION_EMAIL_SENDER = os.environ.get(
    "VERIFICATION_EMAIL_SENDER", "noreply@pkgwatch.dev"
)
BASE_URL = os.environ.get("BASE_URL", "https://pkgwatch.dev")
API_URL = os.environ.get("API_URL", "https://api.pkgwatch.dev")

# Magic link TTL (same as login flow)
MAGIC_LINK_TTL_MINUTES = 15

# Resend cooldown for pending users (prevents email spam)
RESEND_COOLDOWN_SECONDS = 60

# Email validation regex
EMAIL_REGEX = re.compile(r"^[^@]+@[^@]+\.[^@]+$")


def _get_origin(event: dict) -> str | None:
    """Extract Origin header from request (case-insensitive)."""
    headers = event.get("headers", {}) or {}
    # API Gateway may lowercase headers
    return headers.get("origin") or headers.get("Origin")


def handler(event, context):
    """
    Lambda handler for POST /signup.

    Request body:
    {
        "email": "user@example.com"
    }

    Creates a pending user and sends verification email.

    Security: Returns the same response whether email exists or not
    to prevent email enumeration attacks. Uses timing normalization
    to prevent timing-based enumeration.
    """
    start_time = time.time()
    origin = _get_origin(event)

    # Generic success message - same whether email exists or not
    # Mentions spam folder to help users find the email
    success_message = (
        "Check your email (including spam folder) for a verification link. "
        "If you already have an account, we've sent you a sign-in link instead."
    )

    # Parse request body (use `or "{}"` to handle explicit None)
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        # Validation errors can return early - they don't reveal email existence
        return error_response(400, "invalid_json", "Request body must be valid JSON", origin=origin)

    email = body.get("email", "").strip().lower()
    referral_code = body.get("referral_code", "").strip() if body.get("referral_code") else None

    # Validate email format
    if not email or not EMAIL_REGEX.match(email):
        # Validation errors can return early - they don't reveal email existence
        return error_response(400, "invalid_email", "Please provide a valid email address", origin=origin)

    # Block disposable email domains (anti-fraud)
    if is_disposable_email(email):
        return error_response(
            400,
            "disposable_email",
            "Please use a permanent email address. Disposable email addresses are not allowed.",
            origin=origin
        )

    # Validate referral code format if provided
    if referral_code and not is_valid_referral_code(referral_code):
        # Don't block signup, just ignore invalid code
        logger.info(f"Invalid referral code format ignored: {referral_code[:20]}...")
        referral_code = None

    # Verify referral code exists (optional - silently ignore if not found)
    if referral_code:
        referrer = lookup_referrer_by_code(referral_code)
        if not referrer:
            logger.info(f"Referral code not found, ignoring: {referral_code}")
            referral_code = None

    # Check if email already exists using email-index GSI
    table = dynamodb.Table(API_KEYS_TABLE)
    try:
        response = table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(email),
        )
        existing_items = response.get("Items", [])

        # Check for verified users - send magic link instead of just returning
        for item in existing_items:
            if item.get("email_verified", False):
                logger.info(f"Signup attempted for existing verified email - sending magic link")
                # Send magic link to help user log in (same UX as login flow)
                try:
                    _send_magic_link_for_existing_user(table, item, email)
                except Exception as e:
                    logger.error(f"Failed to send magic link to existing user: {e}")
                    # Don't fail - still return same response for enumeration prevention
                # Same response as new signup - no enumeration possible
                return _timed_response(start_time, success_response({"message": success_message}, origin=origin))

        # Clean up any stale pending signups (expired verification tokens)
        now = datetime.now(timezone.utc)
        valid_pending_item = None
        for item in existing_items:
            if item.get("sk") == "PENDING":
                expires = item.get("verification_expires")
                if expires:
                    try:
                        expires_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                        if expires_dt < now:
                            # Delete expired pending signup
                            table.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
                        else:
                            # Valid non-expired PENDING record
                            valid_pending_item = item
                    except (ValueError, TypeError):
                        pass
                else:
                    # No expiry set, delete it
                    table.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})

        # Handle existing valid PENDING record - resend verification with cooldown
        if valid_pending_item:
            return _handle_pending_user_resend(
                table, valid_pending_item, email, now, start_time, origin, success_message
            )

    except Exception as e:
        logger.error(f"Error checking existing email: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "An error occurred. Please try again.", origin=origin),
        )

    # Generate user ID and verification token
    user_id = f"user_{hashlib.sha256(email.encode()).hexdigest()[:16]}"
    verification_token = secrets.token_urlsafe(32)
    verification_expires = (now + timedelta(hours=24)).isoformat()

    # Create pending user record
    # TTL is set to 25 hours after verification expires to allow for cleanup
    verification_expires_dt = now + timedelta(hours=24)
    ttl_timestamp = int((verification_expires_dt + timedelta(hours=1)).timestamp())

    # Build PENDING record
    pending_item = {
        "pk": user_id,
        "sk": "PENDING",
        "email": email,
        "verification_token": verification_token,
        "verification_expires": verification_expires,
        "created_at": now.isoformat(),
        "last_verification_sent": now.isoformat(),  # For resend cooldown tracking
        "email_verified": False,
        "ttl": ttl_timestamp,  # Auto-cleanup of expired PENDING records
    }

    # Store referral code if provided (will be processed during verification)
    if referral_code:
        pending_item["referral_code_used"] = referral_code
        logger.info(f"Signup with referral code: {referral_code}")

    try:
        table.put_item(
            Item=pending_item,
            ConditionExpression="attribute_not_exists(pk) OR attribute_not_exists(sk)",
        )
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        # Race condition - same response to prevent enumeration
        logger.info(f"Signup race condition for email (not revealing)")
        return _timed_response(start_time, success_response({"message": success_message}, origin=origin))
    except Exception as e:
        logger.error(f"Error creating pending user: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "An error occurred. Please try again.", origin=origin),
        )

    # Send verification email
    # Note: Uses API_URL because /verify is an API Gateway endpoint that handles
    # the token validation and redirects to the dashboard
    verification_url = f"{API_URL}/verify?token={verification_token}"
    try:
        _send_verification_email(email, verification_url)
    except Exception as e:
        logger.error(f"Failed to send verification email: {e}")
        # Don't fail the signup if email fails - user can request resend
        # but log it for monitoring

    # Log without full email for privacy (GDPR compliance)
    email_prefix = email.split("@")[0][:3] if "@" in email else email[:3]
    email_domain = email.split("@")[1] if "@" in email else "unknown"
    logger.info(f"Signup initiated for {email_prefix}***@{email_domain}")

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


def _send_magic_link_for_existing_user(table, user_item: dict, email: str):
    """
    Send magic link to existing user who tried to sign up.

    This helps users who forgot they already have an account by sending
    them a sign-in link instead of leaving them confused.
    """
    user_id = user_item["pk"]
    now = datetime.now(timezone.utc)

    # Generate magic link token (same TTL as login flow)
    magic_token = secrets.token_urlsafe(32)
    magic_expires = (now + timedelta(minutes=MAGIC_LINK_TTL_MINUTES)).isoformat()

    # Store magic token on the user record
    table.update_item(
        Key={"pk": user_id, "sk": user_item["sk"]},
        UpdateExpression="SET magic_token = :token, magic_expires = :expires",
        ExpressionAttributeValues={
            ":token": magic_token,
            ":expires": magic_expires,
        },
    )

    # Send email with "Welcome back!" messaging
    magic_url = f"{API_URL}/auth/callback?token={magic_token}"

    ses.send_email(
        Source=VERIFICATION_EMAIL_SENDER,
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Sign in to PkgWatch", "Charset": "UTF-8"},
            "Body": {
                "Html": {
                    "Data": f"""
                    <html>
                    <body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h1 style="color: #1e293b;">Welcome back to PkgWatch!</h1>
                        <p style="color: #475569; font-size: 16px;">
                            You already have an account. Click the button below to sign in:
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
                    "Data": f"""Welcome back to PkgWatch!

You already have an account. Click the link below to sign in:

{magic_url}

Important: This link expires in {MAGIC_LINK_TTL_MINUTES} minutes.

If you didn't request this, you can ignore this email.
""",
                    "Charset": "UTF-8",
                },
            },
        },
    )

    # Log without full email for privacy
    email_prefix = email.split("@")[0][:3] if "@" in email else email[:3]
    email_domain = email.split("@")[1] if "@" in email else "unknown"
    logger.info(f"Magic link sent to existing user {email_prefix}***@{email_domain}")


def _handle_pending_user_resend(
    table, pending_item: dict, email: str, now: datetime, start_time: float, origin: str | None, success_message: str
) -> dict:
    """
    Handle signup attempt for a user with existing PENDING record.

    Resends verification email if cooldown has passed (60 seconds).
    Returns same success message regardless of whether email was sent
    to prevent email enumeration attacks.
    """
    user_id = pending_item["pk"]
    last_sent = pending_item.get("last_verification_sent")

    # Check cooldown
    if last_sent:
        try:
            last_sent_dt = datetime.fromisoformat(last_sent.replace("Z", "+00:00"))
            seconds_since_last = (now - last_sent_dt).total_seconds()
            if seconds_since_last < RESEND_COOLDOWN_SECONDS:
                # Cooldown not passed - return success without sending email
                logger.info(f"Resend cooldown active ({int(seconds_since_last)}s since last send)")
                return _timed_response(start_time, success_response({"message": success_message}, origin=origin))
        except (ValueError, TypeError):
            pass  # If parsing fails, proceed with resend

    # Generate new verification token
    verification_token = secrets.token_urlsafe(32)
    verification_expires = (now + timedelta(hours=24)).isoformat()
    verification_expires_dt = now + timedelta(hours=24)
    ttl_timestamp = int((verification_expires_dt + timedelta(hours=1)).timestamp())

    # Update the PENDING record with new token
    try:
        table.update_item(
            Key={"pk": user_id, "sk": "PENDING"},
            UpdateExpression="SET verification_token = :token, verification_expires = :expires, last_verification_sent = :sent, #ttl_attr = :ttl",
            ExpressionAttributeNames={"#ttl_attr": "ttl"},
            ExpressionAttributeValues={
                ":token": verification_token,
                ":expires": verification_expires,
                ":sent": now.isoformat(),
                ":ttl": ttl_timestamp,
            },
        )
    except Exception as e:
        logger.error(f"Error updating PENDING record for resend: {e}")
        # Return success anyway to prevent enumeration
        return _timed_response(start_time, success_response({"message": success_message}, origin=origin))

    # Send verification email
    verification_url = f"{API_URL}/verify?token={verification_token}"
    try:
        _send_verification_email(email, verification_url)
    except Exception as e:
        logger.error(f"Failed to resend verification email: {e}")
        # Don't fail - user sees success message

    # Log without full email for privacy
    email_prefix = email.split("@")[0][:3] if "@" in email else email[:3]
    email_domain = email.split("@")[1] if "@" in email else "unknown"
    logger.info(f"Verification email resent to pending user {email_prefix}***@{email_domain}")

    return _timed_response(start_time, success_response({"message": success_message}, origin=origin))


def _timed_response(start_time: float, response: dict) -> dict:
    """
    Ensure response takes at least MIN_RESPONSE_TIME_SECONDS to prevent timing attacks.

    Attackers could measure response times to determine if an email exists
    (existing emails skip some operations). Normalizing timing eliminates this vector.
    """
    elapsed = time.time() - start_time
    if elapsed < MIN_RESPONSE_TIME_SECONDS:
        time.sleep(MIN_RESPONSE_TIME_SECONDS - elapsed)
    return response
