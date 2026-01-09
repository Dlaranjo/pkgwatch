"""
Auth Callback Endpoint - GET /auth/callback?token=xxx

Validates magic link token and creates a session.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
secretsmanager = boto3.client("secretsmanager")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "dephealth-api-keys")
BASE_URL = os.environ.get("BASE_URL", "https://dephealth.laranjo.dev")

# Cached session secret (loaded from Secrets Manager)
_session_secret_cache = None


def _get_session_secret() -> str:
    """Retrieve session secret from Secrets Manager (cached)."""
    global _session_secret_cache

    if _session_secret_cache:
        return _session_secret_cache

    # Read at runtime to allow tests to set this env var
    session_secret_arn = os.environ.get("SESSION_SECRET_ARN")
    if not session_secret_arn:
        logger.error("SESSION_SECRET_ARN not configured")
        return ""

    try:
        response = secretsmanager.get_secret_value(SecretId=session_secret_arn)
        secret_string = response["SecretString"]

        # Try to parse as JSON
        try:
            secret_data = json.loads(secret_string)
            _session_secret_cache = secret_data.get("secret", secret_string)
        except json.JSONDecodeError:
            _session_secret_cache = secret_string

        return _session_secret_cache
    except ClientError as e:
        logger.error(f"Failed to retrieve session secret: {e}")
        return ""

# Session TTL (7 days)
SESSION_TTL_DAYS = 7


def handler(event, context):
    """
    Lambda handler for GET /auth/callback?token=xxx.

    Validates the magic token and creates a session cookie.
    Redirects to dashboard on success.
    """
    # Extract token from query parameters
    params = event.get("queryStringParameters") or {}
    token = params.get("token", "")

    if not token:
        return _redirect_with_error("missing_token", "Login token is required")

    session_secret = _get_session_secret()
    if not session_secret:
        return _redirect_with_error("internal_error", "Authentication not configured")

    table = dynamodb.Table(API_KEYS_TABLE)
    now = datetime.now(timezone.utc)

    # Query for user with this magic token using GSI
    try:
        response = table.query(
            IndexName="magic-token-index",
            KeyConditionExpression=Key("magic_token").eq(token),
        )
    except Exception as e:
        logger.error(f"Error querying for token: {e}")
        return _redirect_with_error("internal_error", "Failed to verify token")

    items = response.get("Items", [])
    if not items:
        return _redirect_with_error("invalid_token", "Invalid or expired login link")

    # GSI returns only pk/sk, so fetch full item
    pk = items[0]["pk"]
    sk = items[0]["sk"]

    try:
        full_response = table.get_item(Key={"pk": pk, "sk": sk})
        user = full_response.get("Item")
    except Exception as e:
        logger.error(f"Error fetching user data: {e}")
        return _redirect_with_error("internal_error", "Failed to verify token")

    if not user:
        return _redirect_with_error("invalid_token", "Invalid or expired login link")

    user_id = user["pk"]
    email = user["email"]

    # Check expiration
    expires_str = user.get("magic_expires", "")
    if expires_str:
        try:
            expires = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            if expires < now:
                # Clear the expired magic token
                table.update_item(
                    Key={"pk": user_id, "sk": user["sk"]},
                    UpdateExpression="REMOVE magic_token, magic_expires",
                )
                return _redirect_with_error(
                    "token_expired",
                    "Login link has expired. Please request a new one."
                )
        except (ValueError, TypeError):
            pass

    # Clear the magic token (single use) with conditional check to prevent replay attacks
    try:
        table.update_item(
            Key={"pk": user_id, "sk": user["sk"]},
            UpdateExpression="REMOVE magic_token, magic_expires SET last_login = :now",
            ConditionExpression="attribute_exists(magic_token) AND magic_token = :expected_token",
            ExpressionAttributeValues={
                ":now": now.isoformat(),
                ":expected_token": token,
            },
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.warning(f"Magic token replay attempt for {user_id}")
            return _redirect_with_error(
                "token_already_used",
                "This login link has already been used. Please request a new one."
            )
        logger.warning(f"Failed to clear magic token: {e}")
    except Exception as e:
        logger.warning(f"Failed to clear magic token: {e}")

    # Create session token
    session_expires = now + timedelta(days=SESSION_TTL_DAYS)
    session_data = {
        "user_id": user_id,
        "email": email,
        "tier": user.get("tier", "free"),
        "exp": int(session_expires.timestamp()),
    }

    session_token = _create_session_token(session_data, session_secret)

    logger.info(f"Session created for {email}")

    # Set session cookie and redirect to dashboard
    cookie_value = f"session={session_token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_TTL_DAYS * 86400}"

    return {
        "statusCode": 302,
        "headers": {
            "Location": f"{BASE_URL}/dashboard",
            "Set-Cookie": cookie_value,
            "Cache-Control": "no-store",
        },
        "body": "",
    }


def _create_session_token(data: dict, secret: str) -> str:
    """Create a signed session token."""
    payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
    signature = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{payload}.{signature}"


def verify_session_token(token: str) -> dict | None:
    """Verify a session token and return the data if valid."""
    session_secret = _get_session_secret()
    if not session_secret or "." not in token:
        return None

    try:
        payload, signature = token.rsplit(".", 1)
        expected_sig = hmac.new(
            session_secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            return None

        data = json.loads(base64.urlsafe_b64decode(payload.encode()))

        # Check expiration
        if data.get("exp", 0) < datetime.now(timezone.utc).timestamp():
            return None

        return data

    except Exception:
        return None


def _redirect_with_error(code: str, message: str) -> dict:
    """Redirect to login page with error message."""
    redirect_params = urlencode({
        "error": code,
        "message": message,
    })
    return {
        "statusCode": 302,
        "headers": {
            "Location": f"{BASE_URL}/login?{redirect_params}",
            "Cache-Control": "no-store",
        },
        "body": "",
    }
