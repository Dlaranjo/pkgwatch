"""
Package Request API - Allows users to request packages not yet tracked.

POST /packages/request
{
    "ecosystem": "npm",
    "name": "package-name"
}

Self-healing mechanism: users surface blind spots in our coverage.
Rate limited: 10 requests per IP per day.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
sqs = boto3.client("sqs")

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
PACKAGE_QUEUE_URL = os.environ.get("PACKAGE_QUEUE_URL")
RATE_LIMIT_PER_DAY = 10


def handler(event, context):
    """Handle package request from user."""
    from shared.response_utils import error_response, success_response

    # Parse request body
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return error_response(400, "invalid_json", "Invalid JSON body")

    name = body.get("name", "").strip()
    ecosystem = body.get("ecosystem", "npm").lower()

    # Validate required fields
    if not name:
        return error_response(400, "missing_name", "Package name is required")

    if ecosystem not in ["npm", "pypi"]:
        return error_response(400, "invalid_ecosystem", "Ecosystem must be 'npm' or 'pypi'")

    # Check rate limit
    client_ip = get_client_ip(event)
    if rate_limit_exceeded(client_ip):
        return error_response(
            429,
            "rate_limit_exceeded",
            f"Rate limit exceeded. Maximum {RATE_LIMIT_PER_DAY} requests per day.",
        )

    table = dynamodb.Table(PACKAGES_TABLE)

    # Check if package already exists
    try:
        response = table.get_item(
            Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"},
            ProjectionExpression="pk, health_score, risk_level",
        )
        if "Item" in response:
            return success_response(
                {
                    "status": "exists",
                    "package": name,
                    "ecosystem": ecosystem,
                    "message": "Package is already tracked",
                }
            )
    except Exception as e:
        logger.error(f"Failed to check if package exists: {e}")

    # Validate package exists in registry
    exists = asyncio.run(validate_package_exists(name, ecosystem))
    if not exists:
        return error_response(
            404,
            "package_not_found",
            f"Package '{name}' not found in {ecosystem} registry",
        )

    # Add to database
    now = datetime.now(timezone.utc).isoformat()
    try:
        table.put_item(
            Item={
                "pk": f"{ecosystem}#{name}",
                "sk": "LATEST",
                "name": name,
                "ecosystem": ecosystem,
                "tier": 3,  # New packages start at tier 3
                "source": "user_request",
                "created_at": now,
                "last_updated": now,
                "data_status": "pending",
                "requested_by_ip": client_ip,
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        # Race condition - already added
        return success_response(
            {
                "status": "exists",
                "package": name,
                "ecosystem": ecosystem,
                "message": "Package was just added by another request",
            }
        )
    except Exception as e:
        logger.error(f"Failed to add package: {e}")
        return error_response(500, "db_error", "Failed to add package")

    # Queue for immediate collection
    if PACKAGE_QUEUE_URL:
        try:
            sqs.send_message(
                QueueUrl=PACKAGE_QUEUE_URL,
                MessageBody=json.dumps(
                    {
                        "ecosystem": ecosystem,
                        "name": name,
                        "tier": 3,
                        "reason": "user_request",
                    }
                ),
                # No delay - priority processing
                DelaySeconds=0,
            )
        except Exception as e:
            logger.error(f"Failed to queue package for collection: {e}")

    # Record rate limit usage
    record_rate_limit_usage(client_ip)

    logger.info(f"User requested new package: {ecosystem}/{name} from {client_ip}")

    return success_response(
        {
            "status": "queued",
            "package": name,
            "ecosystem": ecosystem,
            "message": "Package queued for collection. Data will be available within 5 minutes.",
            "eta_minutes": 5,
        }
    )


def get_client_ip(event: dict) -> str:
    """Extract client IP from request."""
    # Try X-Forwarded-For header first (API Gateway sets this)
    headers = event.get("headers", {}) or {}
    forwarded_for = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")
    if forwarded_for:
        # First IP in the chain is the original client
        return forwarded_for.split(",")[0].strip()

    # Fallback to request context
    request_context = event.get("requestContext", {})
    identity = request_context.get("identity", {})
    return identity.get("sourceIp", "unknown")


def rate_limit_exceeded(client_ip: str) -> bool:
    """Check if IP has exceeded daily rate limit."""
    table = dynamodb.Table(API_KEYS_TABLE)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rate_limit_key = f"RATE_LIMIT#{client_ip}#{today}"

    try:
        response = table.get_item(
            Key={"pk": rate_limit_key, "sk": "request_package"},
            ProjectionExpression="request_count",
        )
        if "Item" in response:
            count = response["Item"].get("request_count", 0)
            return count >= RATE_LIMIT_PER_DAY
    except Exception as e:
        logger.warning(f"Rate limit check failed: {e}")

    return False


def record_rate_limit_usage(client_ip: str):
    """Record rate limit usage for IP."""
    table = dynamodb.Table(API_KEYS_TABLE)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rate_limit_key = f"RATE_LIMIT#{client_ip}#{today}"

    # Set TTL to midnight + 1 day
    tomorrow = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    ttl = int((tomorrow.timestamp()) + 86400)

    try:
        table.update_item(
            Key={"pk": rate_limit_key, "sk": "request_package"},
            UpdateExpression="SET request_count = if_not_exists(request_count, :zero) + :inc, #ttl = :ttl",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={
                ":zero": 0,
                ":inc": 1,
                ":ttl": ttl,
            },
        )
    except Exception as e:
        logger.warning(f"Failed to record rate limit usage: {e}")


async def validate_package_exists(name: str, ecosystem: str) -> bool:
    """Validate package exists in registry."""
    try:
        from collectors.depsdev_collector import get_package_info

        info = await get_package_info(name, ecosystem)
        return info is not None
    except Exception as e:
        logger.error(f"Failed to validate package {name}: {e}")
        return False
