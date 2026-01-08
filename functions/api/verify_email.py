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
from boto3.dynamodb.conditions import Attr

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import API key generation from shared module
from shared.auth import generate_api_key

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "dephealth-api-keys")
BASE_URL = os.environ.get("BASE_URL", "https://dephealth.laranjo.dev")


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

    # Scan for pending signup with this token
    # Note: In production with many users, consider a GSI on verification_token
    try:
        response = table.scan(
            FilterExpression=Attr("verification_token").eq(token) & Attr("sk").eq("PENDING"),
            ProjectionExpression="pk, email, verification_expires, verification_token",
        )
    except Exception as e:
        logger.error(f"Error scanning for token: {e}")
        return _redirect_with_error("internal_error", "Failed to verify token")

    items = response.get("Items", [])
    if not items:
        return _redirect_with_error("invalid_token", "Invalid or expired verification token")

    pending_user = items[0]
    user_id = pending_user["pk"]
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

    logger.info(f"Email verified for {email}, API key created")

    # Redirect to dashboard with the API key (show once)
    # The dashboard should display this key and warn it won't be shown again
    redirect_params = urlencode({
        "verified": "true",
        "key": api_key,  # Only shown once on first login
    })

    return {
        "statusCode": 302,
        "headers": {
            "Location": f"{BASE_URL}/dashboard?{redirect_params}",
            "Cache-Control": "no-store",
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
        },
        "body": "",
    }
