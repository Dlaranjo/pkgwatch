"""
Revoke API Key Endpoint - DELETE /api-keys/{key_id}

Revokes (deletes) an API key for the authenticated user.
"""

import json
import logging
import os
from http.cookies import SimpleCookie

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import session verification
from api.auth_callback import verify_session_token
from shared.response_utils import error_response, get_cors_headers

dynamodb = boto3.resource("dynamodb")
dynamodb_client = boto3.client("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")


def handler(event, context):
    """
    Lambda handler for DELETE /api-keys/{key_id}.

    Revokes the specified API key if it belongs to the authenticated user.
    """
    # Extract origin for CORS
    headers = event.get("headers", {})
    origin = headers.get("origin") or headers.get("Origin")

    # Extract session cookie
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""

    session_token = None
    if cookie_header:
        cookies = SimpleCookie()
        cookies.load(cookie_header)
        if "session" in cookies:
            session_token = cookies["session"].value

    if not session_token:
        return error_response(401, "unauthorized", "Not authenticated", origin=origin)

    # Verify session token
    session_data = verify_session_token(session_token)
    if not session_data:
        return error_response(401, "session_expired", "Session expired. Please log in again.", origin=origin)

    user_id = session_data.get("user_id")

    # Get key_id from path parameters
    path_params = event.get("pathParameters") or {}
    key_id = path_params.get("key_id")

    if not key_id:
        return error_response(400, "missing_key_id", "API key ID is required", origin=origin)

    # Get all API keys for user to find matching one
    table = dynamodb.Table(API_KEYS_TABLE)
    try:
        response = table.query(
            KeyConditionExpression=Key("pk").eq(user_id),
        )
        items = response.get("Items", [])

        # Find the key with matching key_id (first 16 chars of hash)
        target_key = None
        for item in items:
            if item.get("sk") == "PENDING" or item.get("sk") == "USER_META":
                continue
            key_hash = item.get("sk", "")
            if key_hash.startswith(key_id):
                target_key = item
                break

        if not target_key:
            return error_response(404, "key_not_found", "API key not found", origin=origin)

        # Initialize USER_META if it doesn't exist (for users created before this feature)
        try:
            # Try to get USER_META
            meta_response = table.get_item(
                Key={"pk": user_id, "sk": "USER_META"},
                ProjectionExpression="key_count",
            )

            if "Item" not in meta_response:
                # USER_META doesn't exist - count existing keys and calculate total usage
                active_keys = [
                    i for i in items
                    if i.get("sk") not in ("PENDING", "USER_META")
                ]
                current_count = len(active_keys)
                # Sum existing usage across all keys for authoritative count
                total_usage = sum(
                    int(i.get("requests_this_month", 0)) for i in active_keys
                )

                # Initialize USER_META with current count and aggregated usage
                try:
                    table.put_item(
                        Item={
                            "pk": user_id,
                            "sk": "USER_META",
                            "key_count": current_count,
                            "requests_this_month": total_usage,
                        },
                        ConditionExpression="attribute_not_exists(pk)",
                    )
                except ClientError as e:
                    # Another request might have created it - that's ok, continue
                    if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                        raise
        except Exception as e:
            logger.error(f"Error initializing USER_META: {e}")
            return error_response(500, "internal_error", "Failed to revoke API key", origin=origin)

        # Use transaction to atomically:
        # 1. Decrement key count in USER_META with condition > 1
        # 2. Delete the API key
        try:
            dynamodb_client.transact_write_items(
                TransactItems=[
                    {
                        # Update USER_META record with atomic counter decrement
                        "Update": {
                            "TableName": API_KEYS_TABLE,
                            "Key": {
                                "pk": {"S": user_id},
                                "sk": {"S": "USER_META"},
                            },
                            "UpdateExpression": "SET key_count = key_count - :dec",
                            "ConditionExpression": "key_count > :min",
                            "ExpressionAttributeValues": {
                                ":dec": {"N": "1"},
                                ":min": {"N": "1"},
                            },
                        }
                    },
                    {
                        # Delete the API key
                        "Delete": {
                            "TableName": API_KEYS_TABLE,
                            "Key": {
                                "pk": {"S": user_id},
                                "sk": {"S": target_key["sk"]},
                            },
                            "ConditionExpression": "attribute_exists(pk)",
                        }
                    },
                ]
            )
            logger.info(f"API key revoked for user {user_id}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "TransactionCanceledException":
                # Check which condition failed
                reasons = e.response.get("CancellationReasons", [])
                for reason in reasons:
                    if reason.get("Code") == "ConditionalCheckFailed":
                        logger.info(f"Key revocation failed for {user_id}: cannot revoke last key")
                        return error_response(
                            400,
                            "cannot_revoke_last_key",
                            "Cannot revoke your only API key. Create a new one first.",
                            origin=origin
                        )
                logger.error(f"Transaction failed: {e}")
                return error_response(500, "internal_error", "Failed to revoke API key", origin=origin)
            logger.error(f"Error revoking API key: {e}")
            return error_response(500, "internal_error", "Failed to revoke API key", origin=origin)

    except Exception as e:
        logger.error(f"Error revoking API key: {e}")
        return error_response(500, "internal_error", "Failed to revoke API key", origin=origin)

    # 204 No Content is the correct status for successful DELETE
    # Include CORS headers
    response_headers = get_cors_headers(origin)

    return {
        "statusCode": 204,
        "headers": response_headers,
        "body": "",
    }


