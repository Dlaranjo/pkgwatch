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

import hashlib
import json
import logging
import os
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from shared.aws_clients import get_dynamodb, get_sqs

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
PACKAGE_QUEUE_URL = os.environ.get("PACKAGE_QUEUE_URL")
RATE_LIMIT_PER_DAY = 10


def handler(event, context):
    """Handle package request from user."""
    from shared.package_validation import normalize_npm_name
    from shared.response_utils import error_response, success_response

    # Extract origin for CORS headers
    headers = event.get("headers", {})
    origin = headers.get("origin") or headers.get("Origin")

    # Parse request body (use `or "{}"` to handle explicit None)
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return error_response(400, "invalid_json", "Invalid JSON body", origin=origin)

    name = body.get("name", "").strip()
    ecosystem = body.get("ecosystem", "npm").lower()

    # Validate required fields
    if not name:
        return error_response(400, "missing_name", "Package name is required", origin=origin)

    if ecosystem not in ["npm", "pypi"]:
        return error_response(400, "invalid_ecosystem", "Ecosystem must be 'npm' or 'pypi'", origin=origin)

    # Normalize npm package names to lowercase (npm is case-insensitive)
    if ecosystem == "npm":
        name = normalize_npm_name(name)

    # Check and record rate limit atomically
    client_ip = get_client_ip(event)
    if not check_and_record_rate_limit(client_ip):
        return error_response(
            429,
            "rate_limit_exceeded",
            f"Rate limit exceeded. Maximum {RATE_LIMIT_PER_DAY} requests per day.",
            origin=origin,
        )

    table = get_dynamodb().Table(PACKAGES_TABLE)

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
                },
                origin=origin,
            )
    except Exception as e:
        logger.error(f"Failed to check if package exists: {e}")

    # Validate package exists in registry
    exists = validate_package_exists(name, ecosystem)
    if not exists:
        return error_response(
            404,
            "package_not_found",
            f"Package '{name}' not found in {ecosystem} registry",
            origin=origin,
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
                "requested_by_ip_hash": hashlib.sha256(
                    (client_ip + os.environ.get("IP_HASH_SALT", "pkgwatch")).encode()
                ).hexdigest()[:16],
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Race condition - already added
            return success_response(
                {
                    "status": "exists",
                    "package": name,
                    "ecosystem": ecosystem,
                    "message": "Package was just added by another request",
                },
                origin=origin,
            )
        raise  # Re-raise other ClientErrors
    except Exception as e:
        logger.error(f"Failed to add package: {e}")
        return error_response(500, "db_error", "Failed to add package", origin=origin)

    # Queue for immediate collection
    if PACKAGE_QUEUE_URL:
        try:
            get_sqs().send_message(
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

    logger.info(f"User requested new package: {ecosystem}/{name} from {client_ip}")

    return success_response(
        {
            "status": "queued",
            "package": name,
            "ecosystem": ecosystem,
            "message": "Package queued for collection. Data will be available within 5 minutes.",
            "eta_minutes": 5,
        },
        origin=origin,
    )


from shared.request_utils import get_client_ip


def check_and_record_rate_limit(client_ip: str) -> bool:
    """Atomically check and increment rate limit. Returns True if allowed."""
    from botocore.exceptions import ClientError

    table = get_dynamodb().Table(API_KEYS_TABLE)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    rate_limit_key = f"RATE_LIMIT#{client_ip}#{today}"
    ttl = int(datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()) + 86400
    try:
        table.update_item(
            Key={"pk": rate_limit_key, "sk": "request_package"},
            UpdateExpression="SET request_count = if_not_exists(request_count, :zero) + :inc, #ttl = :ttl",
            ConditionExpression="attribute_not_exists(request_count) OR request_count < :limit",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={":zero": 0, ":inc": 1, ":limit": RATE_LIMIT_PER_DAY, ":ttl": ttl},
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        logger.warning(f"Rate limit check failed: {e}")
        return False  # Fail closed
    except Exception as e:
        logger.warning(f"Rate limit check failed: {e}")
        return False  # Fail closed


def validate_package_exists(name: str, ecosystem: str) -> bool:
    """Validate package exists in registry via deps.dev API (synchronous)."""
    from urllib.parse import quote

    import httpx

    DEPSDEV_API = "https://api.deps.dev/v3"
    system = "npm" if ecosystem == "npm" else "pypi"
    encoded_name = quote(name, safe="")
    url = f"{DEPSDEV_API}/systems/{system}/packages/{encoded_name}"

    try:
        response = httpx.get(url, timeout=10.0, follow_redirects=True)
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Failed to validate package {name}: {e}")
        return False
