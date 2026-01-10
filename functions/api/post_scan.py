"""
Scan Endpoint - POST /scan

Scans a package.json file and returns health scores for all dependencies.
Requires API key authentication.
"""

import json
import logging
import os
import random
import time
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional
import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import from shared module (bundled with Lambda)
from shared.auth import validate_api_key, check_and_increment_usage_batch
from shared.response_utils import error_response, decimal_default, get_cors_headers


def get_reset_timestamp() -> int:
    """Get Unix timestamp for start of next month (when usage resets)."""
    now = datetime.now(timezone.utc)

    # First day of next month
    if now.month == 12:
        next_month = datetime(now.year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        next_month = datetime(now.year, now.month + 1, 1, tzinfo=timezone.utc)

    return int(next_month.timestamp())


def check_usage_alerts(user: dict, current_usage: int) -> Optional[dict]:
    """
    Check if user is approaching rate limit and return alert info.

    Returns dict with alert level and message if applicable, None otherwise.
    """
    limit = user.get("monthly_limit", 5000)
    usage_percent = (current_usage / limit) * 100 if limit > 0 else 100

    if usage_percent >= 100:
        return {
            "level": "exceeded",
            "percent": 100,
            "message": f"Monthly limit exceeded. Upgrade at https://pkgwatch.laranjo.dev/pricing",
        }
    elif usage_percent >= 95:
        return {
            "level": "critical",
            "percent": round(usage_percent, 1),
            "message": f"Only {limit - current_usage} requests remaining this month",
        }
    elif usage_percent >= 80:
        return {
            "level": "warning",
            "percent": round(usage_percent, 1),
            "message": f"{round(100 - usage_percent, 1)}% of monthly quota remaining",
        }

    return None


dynamodb = boto3.resource("dynamodb")
PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")


def handler(event, context):
    """
    Lambda handler for POST /scan.

    Request body:
    {
        "content": "<package.json content as string>"
    }
    or
    {
        "dependencies": {"lodash": "^4.17.21", "express": "^4.18.0"}
    }

    Returns health scores for all dependencies.
    """
    # Extract API key and origin for CORS
    headers = event.get("headers", {})
    api_key = headers.get("x-api-key") or headers.get("X-API-Key")
    origin = headers.get("origin") or headers.get("Origin")

    # Validate API key
    user = validate_api_key(api_key)

    if not user:
        return error_response(401, "invalid_api_key", "Invalid or missing API key", origin=origin)

    # Parse request body
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return error_response(400, "invalid_json", "Request body must be valid JSON", origin=origin)

    # Extract dependencies
    dependencies = _extract_dependencies(body)

    if not dependencies:
        return error_response(
            400,
            "no_dependencies",
            "No dependencies found. Provide 'content' (package.json string) or 'dependencies' object.",
            origin=origin,
        )

    # Atomically check rate limit and reserve quota for this scan
    # This prevents race conditions where concurrent scans can exceed the limit
    allowed, new_count = check_and_increment_usage_batch(
        user["user_id"],
        user["key_hash"],
        user["monthly_limit"],
        len(dependencies),
    )
    if not allowed:
        remaining = user["monthly_limit"] - new_count
        return error_response(
            429,
            "rate_limit_exceeded",
            f"Scanning {len(dependencies)} packages would exceed your remaining {remaining} requests.",
            origin=origin,
        )
    remaining = user["monthly_limit"] - new_count

    # Fetch scores for all dependencies using BatchGetItem for efficiency
    results = []
    not_found = []

    # Process in batches of 25 (DynamoDB BatchGetItem limit)
    dep_list = list(dependencies)
    for i in range(0, len(dep_list), 25):
        batch = dep_list[i:i + 25]
        batch_set = set(batch)  # Track which packages we've processed

        try:
            request_items = {
                PACKAGES_TABLE: {
                    "Keys": [{"pk": f"npm#{name}", "sk": "LATEST"} for name in batch]
                }
            }

            # Retry loop for UnprocessedKeys (with exponential backoff)
            max_retries = 3
            retry_delay = 0.1  # 100ms initial delay

            for attempt in range(max_retries + 1):
                response = dynamodb.batch_get_item(RequestItems=request_items)

                # Process found items
                for item in response.get("Responses", {}).get(PACKAGES_TABLE, []):
                    package_name = item["pk"].split("#", 1)[1]
                    if package_name in batch_set:
                        batch_set.discard(package_name)
                        results.append({
                            "package": package_name,
                            "health_score": item.get("health_score"),
                            "risk_level": item.get("risk_level"),
                            "abandonment_risk": item.get("abandonment_risk", {}),
                            "is_deprecated": item.get("is_deprecated", False),
                            "archived": item.get("archived", False),
                            "last_updated": item.get("last_updated"),
                        })

                # Check for unprocessed keys
                unprocessed = response.get("UnprocessedKeys", {})
                if not unprocessed:
                    break  # All items processed

                if attempt < max_retries:
                    # Exponential backoff with jitter to prevent thundering herd
                    jitter = random.uniform(0, retry_delay * 0.1)
                    time.sleep(retry_delay + jitter)
                    retry_delay *= 2
                    request_items = unprocessed
                    logger.warning(f"Retrying {len(unprocessed.get(PACKAGES_TABLE, {}).get('Keys', []))} unprocessed keys (attempt {attempt + 2})")
                else:
                    # Max retries exceeded, log warning
                    logger.error(f"Max retries exceeded for batch_get_item, {len(unprocessed.get(PACKAGES_TABLE, {}).get('Keys', []))} keys unprocessed")

            # Any remaining items in batch_set were not found
            not_found.extend(batch_set)

        except Exception as e:
            logger.error(f"Error in batch fetch: {e}")
            # Fall back to marking remaining items as not found on batch error
            not_found.extend(batch_set)

    # Usage was already atomically reserved at the start of the request
    # based on len(dependencies) - this prevents race conditions

    # Calculate counts by risk level
    critical_count = sum(1 for r in results if r["risk_level"] == "CRITICAL")
    high_count = sum(1 for r in results if r["risk_level"] == "HIGH")
    medium_count = sum(1 for r in results if r["risk_level"] == "MEDIUM")
    low_count = sum(1 for r in results if r["risk_level"] == "LOW")

    # Sort results by risk (CRITICAL first, LOW last)
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 4}
    results.sort(key=lambda x: (risk_order.get(x["risk_level"], 4), x["package"]))

    # Build response headers with CORS
    response_headers = {
        "Content-Type": "application/json",
        "X-RateLimit-Limit": str(user["monthly_limit"]),
        "X-RateLimit-Remaining": str(remaining),  # Already reflects reserved quota
        "X-RateLimit-Reset": str(get_reset_timestamp()),
    }
    response_headers.update(get_cors_headers(origin))

    # Check for usage alerts and add to response
    alert = check_usage_alerts(user, new_count)

    # Build response body
    response_body = {
        "total": len(dependencies),
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "packages": results,
        "not_found": not_found,
    }

    if alert:
        response_headers["X-Usage-Alert"] = alert["level"]
        response_headers["X-Usage-Percent"] = str(alert["percent"])
        # Include alert in response body for API consumers
        response_body["usage_alert"] = alert

    # Response format matches CLI/Action ScanResult interface:
    # { total, critical, high, medium, low, packages }
    return {
        "statusCode": 200,
        "headers": response_headers,
        "body": json.dumps(response_body, default=decimal_default),
    }


def _extract_dependencies(body: dict) -> list[str]:
    """
    Extract dependency names from request body.

    Supports:
    - {"content": "<package.json string>"}
    - {"dependencies": {...}}
    - {"devDependencies": {...}}
    """
    dependencies = set()

    # Option 1: Parse package.json content string
    if "content" in body:
        content = body["content"]
        # Security: Ensure content is a string before parsing
        if isinstance(content, str):
            try:
                package_json = json.loads(content)
                deps = package_json.get("dependencies", {})
                dev_deps = package_json.get("devDependencies", {})
                if isinstance(deps, dict):
                    dependencies.update(deps.keys())
                if isinstance(dev_deps, dict):
                    dependencies.update(dev_deps.keys())
            except (json.JSONDecodeError, AttributeError):
                pass

    # Option 2: Direct dependencies object
    if "dependencies" in body:
        deps = body["dependencies"]
        if isinstance(deps, dict):
            dependencies.update(deps.keys())
        elif isinstance(deps, list):
            dependencies.update(deps)

    if "devDependencies" in body:
        dev_deps = body["devDependencies"]
        if isinstance(dev_deps, dict):
            dependencies.update(dev_deps.keys())
        elif isinstance(dev_deps, list):
            dependencies.update(dev_deps)

    # Filter out invalid entries
    return [d for d in dependencies if d and isinstance(d, str)]
