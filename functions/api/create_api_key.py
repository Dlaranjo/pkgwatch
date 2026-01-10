"""
Create API Key Endpoint - POST /api-keys

Creates a new API key for the authenticated user.
"""

import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from http.cookies import SimpleCookie

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import session verification and shared utilities
from api.auth_callback import verify_session_token
from shared.response_utils import error_response

dynamodb = boto3.resource("dynamodb")
dynamodb_client = boto3.client("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")

# Max keys per user
MAX_KEYS_PER_USER = 5

# Import tier limits from shared constants
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../shared"))
from constants import TIER_LIMITS


def handler(event, context):
    """
    Lambda handler for POST /api-keys.

    Creates a new API key for the authenticated user.
    Returns the full API key (shown only once).
    """
    # Extract session cookie
    headers = event.get("headers", {})
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""

    session_token = None
    if cookie_header:
        cookies = SimpleCookie()
        cookies.load(cookie_header)
        if "session" in cookies:
            session_token = cookies["session"].value

    if not session_token:
        return error_response(401, "unauthorized", "Not authenticated")

    # Verify session token
    session_data = verify_session_token(session_token)
    if not session_data:
        return error_response(401, "session_expired", "Session expired. Please log in again.")

    user_id = session_data.get("user_id")
    email = session_data.get("email")
    tier = session_data.get("tier", "free")

    # Parse optional key name from request body
    key_name = None
    body = event.get("body")
    if body:
        try:
            body_data = json.loads(body) if isinstance(body, str) else body
            key_name = body_data.get("name")
        except (json.JSONDecodeError, AttributeError):
            pass

    # Check existing key count
    table = dynamodb.Table(API_KEYS_TABLE)
    try:
        response = table.query(
            KeyConditionExpression=Key("pk").eq(user_id),
        )
        items = response.get("Items", [])

        # Count active keys (excluding PENDING)
        active_keys = [i for i in items if i.get("sk") != "PENDING"]
        current_count = len(active_keys)

        if current_count >= MAX_KEYS_PER_USER:
            return error_response(
                400,
                "max_keys_reached",
                f"Maximum {MAX_KEYS_PER_USER} API keys allowed. Revoke an existing key to create a new one."
            )

    except Exception as e:
        logger.error(f"Error checking key count: {e}")
        return error_response(500, "internal_error", "Failed to create API key")

    # Generate new API key
    api_key = f"pw_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()

    # Build DynamoDB item in low-level format for TransactWriteItems
    new_key_item = {
        "pk": {"S": user_id},
        "sk": {"S": key_hash},
        "key_hash": {"S": key_hash},
        "tier": {"S": tier},
        "created_at": {"S": now},
        "requests_this_month": {"N": "0"},
        "payment_failures": {"N": "0"},
        "email_verified": {"BOOL": True},
    }

    # Add optional attributes
    if email:
        new_key_item["email"] = {"S": email}
    if key_name:
        new_key_item["key_name"] = {"S": key_name}
    else:
        new_key_item["key_name"] = {"S": f"Key {current_count + 1}"}

    # Atomically create key only if it doesn't already exist
    # This prevents race conditions where the same key hash could be created twice
    try:
        dynamodb_client.transact_write_items(
            TransactItems=[
                {
                    "Put": {
                        "TableName": API_KEYS_TABLE,
                        "Item": new_key_item,
                        "ConditionExpression": "attribute_not_exists(pk) OR attribute_not_exists(sk)",
                    }
                }
            ]
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "TransactionCanceledException":
            # Key already exists (hash collision - extremely rare) or race condition
            logger.warning(f"Key creation transaction failed for {user_id}: {e}")
            return error_response(
                409,
                "key_creation_failed",
                "Failed to create key. Please try again."
            )
        logger.error(f"Error creating API key: {e}")
        return error_response(500, "internal_error", "Failed to create API key")

    logger.info(f"New API key created for user {user_id}")

    return {
        "statusCode": 201,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "api_key": api_key,
            "key_id": key_hash[:16],
            "message": "API key created. Save this key - it won't be shown again.",
        }),
    }
