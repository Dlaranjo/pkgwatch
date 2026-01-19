"""
Recovery Confirm Email Endpoint - GET /recovery/confirm-email?token=xxx

Completes the email change by verifying the new email address.
Updates email on all user records and creates a session.

Security:
- Token is single-use
- Notifies old email that the change is complete
- Creates session so user is logged in to new email
"""

import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from api.auth_callback import _create_session_token, _get_session_secret
from shared.recovery_utils import mask_email

# Minimum response time for timing normalization (1.5s)
MIN_RESPONSE_TIME_SECONDS = 1.5

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
ses = boto3.client("ses")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
BASE_URL = os.environ.get("BASE_URL", "https://pkgwatch.laranjo.dev")
EMAIL_SENDER = os.environ.get("VERIFICATION_EMAIL_SENDER", "noreply@pkgwatch.laranjo.dev")

# Session TTL (7 days)
SESSION_TTL_DAYS = 7


def _timed_redirect(start_time: float, response: dict) -> dict:
    """Ensure response takes at least MIN_RESPONSE_TIME_SECONDS."""
    elapsed = time.time() - start_time
    if elapsed < MIN_RESPONSE_TIME_SECONDS:
        time.sleep(MIN_RESPONSE_TIME_SECONDS - elapsed)
    return response


def handler(event, context):
    """
    Lambda handler for GET /recovery/confirm-email?token=xxx.

    Validates the email change token and completes the email update.
    Redirects to dashboard with a session cookie on success.
    """
    start_time = time.time()
    params = event.get("queryStringParameters") or {}
    token = params.get("token", "")

    if not token:
        return _timed_redirect(start_time, _redirect_with_error("missing_token", "Verification token is required"))

    session_secret = _get_session_secret()
    if not session_secret:
        return _timed_redirect(start_time, _redirect_with_error("internal_error", "Authentication not configured"))

    table = dynamodb.Table(API_KEYS_TABLE)
    now = datetime.now(timezone.utc)

    # Find the EMAIL_CHANGE record with this token
    try:
        scan_response = table.scan(
            FilterExpression="change_token = :token",
            ExpressionAttributeValues={":token": token},
            ProjectionExpression="pk, sk, old_email, new_email, #ttl_attr, recovery_session_sk",
            ExpressionAttributeNames={"#ttl_attr": "ttl"},
        )
        records = scan_response.get("Items", [])
    except ClientError as e:
        logger.error(f"Error scanning for change token: {e}")
        return _timed_redirect(start_time, _redirect_with_error("internal_error", "Failed to verify token"))

    if not records:
        logger.warning(f"Email change token not found: {token[:8]}...")
        return _timed_redirect(start_time, _redirect_with_error("invalid_token", "Invalid or expired verification link"))

    change_record = records[0]
    user_id = change_record["pk"]
    change_sk = change_record["sk"]
    old_email = change_record.get("old_email", "")
    new_email = change_record.get("new_email", "")
    recovery_session_sk = change_record.get("recovery_session_sk")

    # Check token hasn't expired
    record_ttl = change_record.get("ttl", 0)
    if record_ttl < now.timestamp():
        logger.warning(f"Email change token expired for user {user_id}")
        return _timed_redirect(start_time, _redirect_with_error("token_expired", "This verification link has expired. Please start the recovery process again."))

    # Get all user records to update email
    try:
        user_response = table.query(
            KeyConditionExpression=Key("pk").eq(user_id),
        )
        user_items = user_response.get("Items", [])
    except ClientError as e:
        logger.error(f"Error fetching user records: {e}")
        return _timed_redirect(start_time, _redirect_with_error("internal_error", "Failed to update email"))

    # Find the primary API key record for session creation
    primary_key = None
    for item in user_items:
        sk = item.get("sk", "")
        if sk not in ["PENDING", "USER_META"] and not sk.startswith("RECOVERY_") and not sk.startswith("EMAIL_CHANGE_"):
            primary_key = item
            break

    if not primary_key:
        logger.error(f"No API key record found for user {user_id}")
        return _timed_redirect(start_time, _redirect_with_error("internal_error", "Account not found"))

    # CRITICAL: Delete the EMAIL_CHANGE record FIRST with conditional check
    # This prevents race conditions where the same token could be used twice
    try:
        table.delete_item(
            Key={"pk": user_id, "sk": change_sk},
            ConditionExpression="attribute_exists(pk)",  # Ensure it exists before deleting
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Token was already consumed by concurrent request
            logger.warning(f"Email change token already used for user {user_id}")
            return _timed_redirect(start_time, _redirect_with_error("invalid_token", "This verification link has already been used."))
        logger.error(f"Error consuming email change token: {e}")
        return _timed_redirect(start_time, _redirect_with_error("internal_error", "Failed to update email"))

    # Now update email on all API key records (token is consumed, safe from race condition)
    try:
        for item in user_items:
            sk = item.get("sk", "")
            # Update API key records (not metadata records)
            if sk not in ["PENDING", "USER_META"] and not sk.startswith("RECOVERY_") and not sk.startswith("EMAIL_CHANGE_"):
                table.update_item(
                    Key={"pk": user_id, "sk": sk},
                    UpdateExpression="SET email = :new_email, email_changed_at = :now, previous_email = :old_email",
                    ExpressionAttributeValues={
                        ":new_email": new_email,
                        ":now": now.isoformat(),
                        ":old_email": old_email,
                    },
                )

        # Update USER_META if it exists
        try:
            table.update_item(
                Key={"pk": user_id, "sk": "USER_META"},
                UpdateExpression="SET email = :new_email, email_changed_at = :now",
                ConditionExpression="attribute_exists(pk)",
                ExpressionAttributeValues={
                    ":new_email": new_email,
                    ":now": now.isoformat(),
                },
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise

        # Delete the recovery session if it exists
        if recovery_session_sk:
            try:
                table.delete_item(Key={"pk": user_id, "sk": recovery_session_sk})
            except ClientError:
                pass  # Ignore if already deleted

    except ClientError as e:
        logger.error(f"Error updating email for user {user_id}: {e}")
        return _timed_redirect(start_time, _redirect_with_error("internal_error", "Failed to update email"))

    # Send confirmation to the old email
    try:
        _send_email_change_complete_notification(old_email, new_email)
    except Exception as e:
        logger.error(f"Failed to send email change completion notification: {e}")
        # Continue - not critical

    # Create session for the new email
    session_expires = now + timedelta(days=SESSION_TTL_DAYS)
    session_data = {
        "user_id": user_id,
        "email": new_email,
        "tier": primary_key.get("tier", "free"),
        "exp": int(session_expires.timestamp()),
    }

    session_token = _create_session_token(session_data, session_secret)

    # Set session cookie and redirect to dashboard
    cookie_value = f"session={session_token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_TTL_DAYS * 86400}"

    logger.info(f"Email change completed for user {user_id}: {old_email[:5]}*** -> {new_email[:5]}***")

    return {
        "statusCode": 302,
        "headers": {
            "Location": f"{BASE_URL}/dashboard?email_changed=true",
            "Set-Cookie": cookie_value,
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'",
            "X-Content-Type-Options": "nosniff",
        },
        "body": "",
    }


def _redirect_with_error(code: str, message: str) -> dict:
    """Redirect to recovery page with error message."""
    redirect_params = urlencode({
        "error": code,
    })
    return {
        "statusCode": 302,
        "headers": {
            "Location": f"{BASE_URL}/recover?{redirect_params}",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'",
            "X-Content-Type-Options": "nosniff",
        },
        "body": "",
    }


def _send_email_change_complete_notification(old_email: str, new_email: str):
    """Notify old email that the change is complete."""
    ses.send_email(
        Source=EMAIL_SENDER,
        Destination={"ToAddresses": [old_email]},
        Message={
            "Subject": {"Data": "PkgWatch: Your Email Has Been Changed", "Charset": "UTF-8"},
            "Body": {
                "Html": {
                    "Data": f"""
                    <html>
                    <body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h1 style="color: #1e293b;">Email Change Complete</h1>
                        <p style="color: #475569; font-size: 16px;">
                            Your PkgWatch account email has been changed to
                            <strong>{mask_email(new_email)}</strong>.
                        </p>
                        <p style="color: #475569; font-size: 16px;">
                            This email address ({old_email}) will no longer receive PkgWatch notifications
                            or be able to log in to the account.
                        </p>
                        <p style="color: #dc2626; font-size: 16px; font-weight: 500;">
                            If you did not make this change, please contact support immediately.
                            Your account may have been compromised.
                        </p>
                        <p style="color: #94a3b8; font-size: 12px;">
                            This is the final notification to this email address.
                        </p>
                    </body>
                    </html>
                    """,
                    "Charset": "UTF-8",
                },
                "Text": {
                    "Data": f"""Email Change Complete

Your PkgWatch account email has been changed to {mask_email(new_email)}.

This email address ({old_email}) will no longer receive PkgWatch notifications or be able to log in to the account.

If you did not make this change, please contact support immediately. Your account may have been compromised.

This is the final notification to this email address.
""",
                    "Charset": "UTF-8",
                },
            },
        },
    )
