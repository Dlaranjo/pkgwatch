"""
Recovery Update Email Endpoint - POST /recovery/update-email

Completes the account recovery by updating the email address.
Only available after verifying with a recovery code (not API key).

Flow:
1. User provides recovery_token and new_email
2. We verify the token is valid and came from recovery code verification
3. Create an EMAIL_CHANGE_PENDING record with verification token
4. Send verification email to new address
5. On verification: update email on all user records, notify old email

Security:
- Only recovery code verification grants a recovery_token
- API key verification does NOT allow email change
- New email must be verified before update takes effect
- Old email receives notification of the change
"""

import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from shared.recovery_utils import mask_email
from shared.response_utils import error_response, success_response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
ses = boto3.client("ses")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
API_URL = os.environ.get("API_URL", "https://api.pkgwatch.dev")
BASE_URL = os.environ.get("BASE_URL", "https://pkgwatch.dev")
EMAIL_SENDER = os.environ.get("VERIFICATION_EMAIL_SENDER", "noreply@pkgwatch.dev")

# Email validation regex
EMAIL_REGEX = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

# Minimum response time for timing normalization (1.5s)
MIN_RESPONSE_TIME_SECONDS = 1.5

# Email change verification TTL (24 hours)
EMAIL_CHANGE_TTL_HOURS = 24


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
    Lambda handler for POST /recovery/update-email.

    Request body:
    {
        "recovery_token": "xxx",
        "new_email": "new@example.com"
    }

    Response (success):
    {
        "message": "Verification email sent to your new address"
    }

    Security:
    - recovery_token must come from recovery code verification
    - New email must be verified before taking effect
    - Old email is notified of the pending change
    """
    start_time = time.time()
    origin = _get_origin(event)

    # Parse request body
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return error_response(400, "invalid_json", "Request body must be valid JSON", origin=origin)

    recovery_token = body.get("recovery_token", "").strip()
    new_email = body.get("new_email", "").strip().lower()

    # Validate inputs
    if not recovery_token:
        return error_response(400, "missing_token", "Recovery token is required", origin=origin)

    if not new_email:
        return error_response(400, "missing_email", "New email address is required", origin=origin)

    if not EMAIL_REGEX.match(new_email):
        return error_response(400, "invalid_email", "Please provide a valid email address", origin=origin)

    table = dynamodb.Table(API_KEYS_TABLE)
    now = datetime.now(timezone.utc)

    # Find the recovery session with this token using GSI query
    try:
        try:
            scan_response = table.query(
                IndexName="recovery-token-index",
                KeyConditionExpression=Key("recovery_token").eq(recovery_token),
                FilterExpression=Attr("recovery_method").eq("recovery_code"),
            )
        except ClientError as e:
            if "ValidationException" in str(e):
                # GSI not deployed yet — fall back to scan
                scan_response = table.scan(
                    FilterExpression="recovery_token = :token AND recovery_method = :method",
                    ExpressionAttributeValues={
                        ":token": recovery_token,
                        ":method": "recovery_code",
                    },
                    ProjectionExpression="pk, sk, email, #ttl_attr, verified",
                    ExpressionAttributeNames={"#ttl_attr": "ttl"},
                )
            else:
                raise
        sessions = scan_response.get("Items", [])
    except ClientError as e:
        logger.error(f"Error querying for recovery token: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Failed to verify token", origin=origin),
        )

    if not sessions:
        logger.warning("Recovery token not found or not from code verification")
        return _timed_response(
            start_time,
            error_response(400, "invalid_token", "Invalid or expired recovery token", origin=origin),
        )

    session_item = sessions[0]
    user_id = session_item["pk"]
    old_email = session_item.get("email", "")

    # Check session hasn't expired
    session_ttl = session_item.get("ttl", 0)
    if session_ttl < now.timestamp():
        logger.warning(f"Recovery session expired for user {user_id}")
        return _timed_response(
            start_time,
            error_response(400, "session_expired", "Recovery session has expired. Please start over.", origin=origin),
        )

    # Check session was verified
    if not session_item.get("verified"):
        logger.warning(f"Recovery session not verified for user {user_id}")
        return _timed_response(
            start_time,
            error_response(400, "session_not_verified", "Recovery session not verified", origin=origin),
        )

    # Check new email isn't already in use by another user
    try:
        email_response = table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(new_email),
        )
        existing_users = email_response.get("Items", [])

        # Filter out PENDING records and check if it's a different user
        for item in existing_users:
            if item.get("sk") != "PENDING" and item.get("pk") != user_id:
                logger.warning(f"Email {new_email[:5]}*** already in use")
                return _timed_response(
                    start_time,
                    error_response(
                        400,
                        "email_in_use",
                        "This email address is already associated with another account",
                        origin=origin,
                    ),
                )
    except ClientError as e:
        logger.error(f"Error checking email availability: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Failed to verify email availability", origin=origin),
        )

    # Generate email change verification token
    change_token = secrets.token_urlsafe(32)
    change_expires = now + timedelta(hours=EMAIL_CHANGE_TTL_HOURS)
    ttl_timestamp = int(change_expires.timestamp())

    try:
        # Create EMAIL_CHANGE_PENDING record
        table.put_item(
            Item={
                "pk": user_id,
                "sk": f"EMAIL_CHANGE_{change_token}",
                "old_email": old_email,
                "new_email": new_email,
                "change_token": change_token,
                "created_at": now.isoformat(),
                "recovery_session_sk": session_item["sk"],
                "ttl": ttl_timestamp,
            }
        )

        # Mark the recovery session as having initiated email change
        table.update_item(
            Key={"pk": user_id, "sk": session_item["sk"]},
            UpdateExpression="SET email_change_initiated = :initiated, new_email = :new_email",
            ExpressionAttributeValues={
                ":initiated": now.isoformat(),
                ":new_email": new_email,
            },
        )

    except ClientError as e:
        logger.error(f"Error creating email change record: {e}")
        return _timed_response(
            start_time,
            error_response(500, "internal_error", "Failed to initiate email change", origin=origin),
        )

    # Send verification email to new address
    verify_url = f"{API_URL}/recovery/confirm-email?token={change_token}"
    try:
        _send_email_change_verification(new_email, verify_url, old_email)
    except Exception as e:
        logger.error(f"Failed to send email change verification: {e}")
        # Continue - record is created, user can retry

    # Notify old email about the pending change
    try:
        _send_email_change_notification(old_email, new_email)
    except Exception as e:
        logger.error(f"Failed to send email change notification: {e}")
        # Continue - not critical

    logger.info(f"Email change initiated for user {user_id}: {old_email[:5]}*** -> {new_email[:5]}***")

    return _timed_response(
        start_time,
        success_response(
            {
                "message": f"A verification link has been sent to {new_email}. Please check your inbox to complete the email change.",
                "masked_new_email": mask_email(new_email),
            },
            origin=origin,
        ),
    )


def _send_email_change_verification(new_email: str, verify_url: str, old_email: str):
    """Send verification email to new address."""
    ses.send_email(
        Source=EMAIL_SENDER,
        Destination={"ToAddresses": [new_email]},
        Message={
            "Subject": {"Data": "Verify your new PkgWatch email address", "Charset": "UTF-8"},
            "Body": {
                "Html": {
                    "Data": f"""
                    <html>
                    <body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h1 style="color: #1e293b;">Verify Your New Email</h1>
                        <p style="color: #475569; font-size: 16px;">
                            You've requested to change your PkgWatch account email from
                            <strong>{mask_email(old_email)}</strong> to this address.
                        </p>
                        <p style="color: #475569; font-size: 16px;">
                            Click the button below to confirm this change:
                        </p>
                        <a href="{verify_url}"
                           style="display: inline-block; background: #3b82f6; color: white; padding: 12px 24px;
                                  text-decoration: none; border-radius: 6px; margin: 20px 0;">
                            Verify Email
                        </a>
                        <p style="color: #64748b; font-size: 14px;">
                            Or copy this link: <a href="{verify_url}">{verify_url}</a>
                        </p>
                        <p style="color: #dc2626; font-size: 14px; font-weight: 500;">
                            <strong>Important:</strong> This link expires in {EMAIL_CHANGE_TTL_HOURS} hours.
                        </p>
                        <p style="color: #94a3b8; font-size: 12px;">
                            If you didn't request this change, you can safely ignore this email.
                        </p>
                    </body>
                    </html>
                    """,
                    "Charset": "UTF-8",
                },
                "Text": {
                    "Data": f"""Verify Your New Email

You've requested to change your PkgWatch account email from {mask_email(old_email)} to this address.

Click the link below to confirm this change:

{verify_url}

Important: This link expires in {EMAIL_CHANGE_TTL_HOURS} hours.

If you didn't request this change, you can safely ignore this email.
""",
                    "Charset": "UTF-8",
                },
            },
        },
    )


def _send_email_change_notification(old_email: str, new_email: str):
    """Notify old email about the pending email change."""
    ses.send_email(
        Source=EMAIL_SENDER,
        Destination={"ToAddresses": [old_email]},
        Message={
            "Subject": {"Data": "PkgWatch: Email Change Requested", "Charset": "UTF-8"},
            "Body": {
                "Html": {
                    "Data": f"""
                    <html>
                    <body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h1 style="color: #1e293b;">Email Change Requested</h1>
                        <p style="color: #475569; font-size: 16px;">
                            Someone has requested to change your PkgWatch account email to
                            <strong>{mask_email(new_email)}</strong>.
                        </p>
                        <p style="color: #475569; font-size: 16px;">
                            This change was initiated using an account recovery code. The change will only
                            complete if the new email address is verified.
                        </p>
                        <p style="color: #dc2626; font-size: 16px; font-weight: 500;">
                            If you did not request this change, your account may be compromised.
                            Please contact support immediately.
                        </p>
                        <p style="color: #94a3b8; font-size: 12px;">
                            You're receiving this because your email is associated with a PkgWatch account.
                        </p>
                    </body>
                    </html>
                    """,
                    "Charset": "UTF-8",
                },
                "Text": {
                    "Data": f"""Email Change Requested

Someone has requested to change your PkgWatch account email to {mask_email(new_email)}.

This change was initiated using an account recovery code. The change will only complete if the new email address is verified.

If you did not request this change, your account may be compromised. Please contact support immediately.

You're receiving this because your email is associated with a PkgWatch account.
""",
                    "Charset": "UTF-8",
                },
            },
        },
    )
