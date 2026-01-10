"""
Verify Email Endpoint - GET /verify?token=xxx

Verifies email and activates the user account with an API key.
"""

import json
import logging
import os
from datetime import datetime, timezone
from urllib.parse import urlencode

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import API key generation from shared module
from shared.auth import generate_api_key

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
BASE_URL = os.environ.get("BASE_URL", "https://pkgwatch.laranjo.dev")


def handler(event, context):
    """
    Lambda handler for GET /verify?token=xxx.

    Verifies the token and creates the user's API key.
    Redirects to dashboard on success.
    """
    # Extract token from query parameters
    params = event.get("queryStringParameters") or {}
    token = params.get("token", "")

    if not token:
        return _redirect_with_error("missing_token", "Verification token is required")

    table = dynamodb.Table(API_KEYS_TABLE)
    now = datetime.now(timezone.utc)

    # Query GSI for pending signup with this token (O(1) instead of O(n) scan)
    try:
        response = table.query(
            IndexName="verification-token-index",
            KeyConditionExpression=Key("verification_token").eq(token),
        )
    except Exception as e:
        logger.error(f"Error querying for token: {e}")
        return _redirect_with_error("internal_error", "Failed to verify token")

    items = response.get("Items", [])
    if not items:
        return _redirect_with_error("invalid_token", "Invalid or expired verification token")

    # GSI returns KEYS_ONLY, so fetch full record
    gsi_item = items[0]
    user_id = gsi_item["pk"]
    sk = gsi_item["sk"]

    # Verify it's a PENDING record (not some other record with same token somehow)
    if sk != "PENDING":
        return _redirect_with_error("invalid_token", "Invalid or expired verification token")

    # Fetch full record to get email and expiration
    try:
        full_response = table.get_item(Key={"pk": user_id, "sk": sk})
        pending_user = full_response.get("Item")
        if not pending_user:
            return _redirect_with_error("invalid_token", "Invalid or expired verification token")
    except Exception as e:
        logger.error(f"Error fetching user record: {e}")
        return _redirect_with_error("internal_error", "Failed to verify token")

    email = pending_user["email"]

    # Check expiration
    expires_str = pending_user.get("verification_expires", "")
    if expires_str:
        try:
            expires = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            if expires < now:
                # Delete expired pending signup
                table.delete_item(Key={"pk": user_id, "sk": "PENDING"})
                return _redirect_with_error(
                    "token_expired",
                    "Verification link has expired. Please sign up again."
                )
        except (ValueError, TypeError):
            pass

    # Generate API key for the user
    try:
        api_key = generate_api_key(user_id=user_id, tier="free", email=email)
    except Exception as e:
        logger.error(f"Error generating API key: {e}")
        return _redirect_with_error("internal_error", "Failed to create API key")

    # Delete the pending signup record
    try:
        table.delete_item(Key={"pk": user_id, "sk": "PENDING"})
    except Exception as e:
        logger.warning(f"Failed to delete pending record: {e}")
        # Not critical - continue anyway

    # Log without full email for privacy (GDPR compliance)
    email_prefix = email.split("@")[0][:3] if "@" in email else email[:3]
    email_domain = email.split("@")[1] if "@" in email else "unknown"
    logger.info(f"Email verified for {email_prefix}***@{email_domain}, API key created")

    # Store API key in short-lived cookie for one-time display
    # SECURITY CONSIDERATIONS:
    # - NOT HttpOnly because dashboard JS needs to read and display it once
    # - Short Max-Age (60s) minimizes exposure window
    # - Secure + SameSite=Strict prevents CSRF and network interception
    # - Path=/dashboard limits cookie scope
    # - More secure than URL (appears in logs/history/referrer)
    # - CSP header on redirect helps mitigate XSS during transit
    # TODO: For enhanced security, implement server-side display token approach:
    #       1. Store display_token -> api_key mapping in DynamoDB (60s TTL)
    #       2. Redirect with display_token in URL
    #       3. Dashboard fetches API key via authenticated endpoint (one-time use)
    cookie_value = (
        f"new_api_key={api_key}; "
        f"Path=/dashboard; "  # Limit cookie scope to dashboard path
        f"Secure; "
        f"SameSite=Strict; "
        f"Max-Age=60"  # Very short - 60 seconds
    )

    return {
        "statusCode": 302,
        "headers": {
            "Location": f"{BASE_URL}/dashboard?verified=true",
            "Set-Cookie": cookie_value,
            "Cache-Control": "no-store",
            # Security headers to mitigate XSS during redirect
            "Content-Security-Policy": "default-src 'none'",
            "X-Content-Type-Options": "nosniff",
        },
        "body": "",
    }


def _redirect_with_error(code: str, message: str) -> dict:
    """Redirect to signup page with error message."""
    redirect_params = urlencode({
        "error": code,
        "message": message,
    })
    return {
        "statusCode": 302,
        "headers": {
            "Location": f"{BASE_URL}/signup?{redirect_params}",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'",
            "X-Content-Type-Options": "nosniff",
        },
        "body": "",
    }
