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

from shared.aws_clients import get_dynamodb, get_sqs
from shared.logging_utils import configure_structured_logging, set_request_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

PACKAGE_QUEUE_URL = os.environ.get("PACKAGE_QUEUE_URL")
MAX_QUEUE_PER_SCAN = 50  # Prevent abuse - max packages to queue per scan

# NOTE: Package validation moved to shared/package_validation.py
from shared.package_validation import (
    normalize_npm_name,
    validate_npm_package_name,
    validate_pypi_package_name,
)


def _is_valid_package_name(name: str, ecosystem: str) -> tuple[bool, str]:
    """
    Validate and normalize package name.

    Returns: (is_valid, normalized_name)
    """
    if not name or not isinstance(name, str):
        return False, ""

    if ecosystem == "npm":
        is_valid, _, normalized = validate_npm_package_name(name)
    elif ecosystem == "pypi":
        is_valid, _, normalized = validate_pypi_package_name(name)
    else:
        return False, ""

    return is_valid, normalized


def _queue_packages_for_collection(packages: list[str], ecosystem: str) -> int:
    """
    Queue validated packages for async collection.

    Returns count of packages successfully queued.
    """
    if not PACKAGE_QUEUE_URL or not packages:
        return 0

    # Validate, normalize, and limit
    valid_packages = []
    for p in packages:
        is_valid, normalized = _is_valid_package_name(p, ecosystem)
        if is_valid:
            valid_packages.append(normalized)

    to_queue = valid_packages[:MAX_QUEUE_PER_SCAN]

    if not to_queue:
        return 0

    sqs = get_sqs()
    queued = 0

    # Send in batches of 10 (SQS limit)
    for i in range(0, len(to_queue), 10):
        batch = to_queue[i : i + 10]
        entries = [
            {
                "Id": str(j),
                "MessageBody": json.dumps(
                    {
                        "ecosystem": ecosystem,
                        "name": name,  # Already normalized
                        "tier": 3,  # Low priority for discovered packages
                        "reason": "scan_discovery",
                    }
                ),
            }
            for j, name in enumerate(batch)
        ]
        try:
            sqs.send_message_batch(QueueUrl=PACKAGE_QUEUE_URL, Entries=entries)
            queued += len(batch)
        except Exception as e:
            logger.error(f"Failed to queue packages for collection: {e}")

    if queued > 0:
        logger.info(f"Queued {queued} packages for collection (ecosystem={ecosystem})")

    return queued


# Import from shared module (bundled with Lambda)
from shared.auth import check_and_increment_usage_with_bonus, validate_api_key
from shared.data_quality import build_data_quality_compact
from shared.rate_limit_utils import check_usage_alerts, get_reset_timestamp
from shared.response_utils import decimal_default, error_response, get_cors_headers

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
    configure_structured_logging()
    set_request_id(event)

    # Extract API key and origin for CORS
    headers = event.get("headers", {})
    api_key = headers.get("x-api-key") or headers.get("X-API-Key")
    origin = headers.get("origin") or headers.get("Origin")

    # Validate API key
    user = validate_api_key(api_key)

    if not user:
        return error_response(401, "invalid_api_key", "Invalid or missing API key", origin=origin)

    # Parse request body (use `or "{}"` to handle explicit None)
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return error_response(400, "invalid_json", "Request body must be valid JSON", origin=origin)

    # Extract ecosystem (default to npm for backwards compatibility)
    ecosystem = body.get("ecosystem", "npm")
    if not isinstance(ecosystem, str) or ecosystem not in ("npm", "pypi"):
        return error_response(
            400,
            "invalid_ecosystem",
            f"Invalid ecosystem '{ecosystem}'. Supported: npm, pypi",
            origin=origin,
        )

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
    # Uses bonus-aware function to track total_packages_scanned and trigger referral activity gate
    allowed, new_count, bonus_remaining = check_and_increment_usage_with_bonus(
        user["user_id"],
        user["key_hash"],
        user["monthly_limit"],
        len(dependencies),
    )
    if not allowed:
        # Calculate remaining including bonus credits
        effective_limit = user["monthly_limit"] + max(0, bonus_remaining)
        remaining = effective_limit - new_count
        return error_response(
            429,
            "rate_limit_exceeded",
            f"Scanning {len(dependencies)} packages would exceed your remaining {max(0, remaining)} requests.",
            origin=origin,
        )
    # Calculate remaining including bonus credits
    effective_limit = user["monthly_limit"] + max(0, bonus_remaining)
    remaining = effective_limit - new_count

    # Fetch scores for all dependencies using BatchGetItem for efficiency
    results = []
    not_found = []

    # Process in batches of 25 (DynamoDB BatchGetItem limit)
    dep_list = list(dependencies)
    for i in range(0, len(dep_list), 25):
        batch = dep_list[i : i + 25]
        # Normalize names for DB lookup (npm is case-insensitive, DB stores lowercase)
        if ecosystem == "npm":
            normalized_batch = [normalize_npm_name(name) for name in batch]
        else:
            normalized_batch = batch
        batch_set = set(normalized_batch)  # Track using normalized names

        try:
            request_items = {
                PACKAGES_TABLE: {"Keys": [{"pk": f"{ecosystem}#{name}", "sk": "LATEST"} for name in normalized_batch]}
            }

            # Retry loop for UnprocessedKeys (with exponential backoff)
            max_retries = 3
            retry_delay = 0.1  # 100ms initial delay

            for attempt in range(max_retries + 1):
                response = get_dynamodb().batch_get_item(RequestItems=request_items)

                # Process found items
                for item in response.get("Responses", {}).get(PACKAGES_TABLE, []):
                    package_name = item["pk"].split("#", 1)[1]
                    if package_name in batch_set:
                        batch_set.discard(package_name)
                        results.append(
                            {
                                "package": package_name,
                                "health_score": item.get("health_score"),
                                "risk_level": item.get("risk_level"),
                                "abandonment_risk": item.get("abandonment_risk", {}),
                                "is_deprecated": item.get("is_deprecated", False),
                                "archived": item.get("archived", False),
                                "last_updated": item.get("last_updated"),
                                # Data completeness indicator
                                "data_quality": build_data_quality_compact(item),
                            }
                        )

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
                    logger.warning(
                        f"Retrying {len(unprocessed.get(PACKAGES_TABLE, {}).get('Keys', []))} unprocessed keys (attempt {attempt + 2})"
                    )
                else:
                    # Max retries exceeded, log warning
                    logger.error(
                        f"Max retries exceeded for batch_get_item, {len(unprocessed.get(PACKAGES_TABLE, {}).get('Keys', []))} keys unprocessed"
                    )

            # Any remaining items in batch_set were not found
            not_found.extend(batch_set)

        except Exception as e:
            logger.error(f"Error in batch fetch: {e}")
            # Fall back to marking remaining items as not found on batch error
            not_found.extend(batch_set)

    # Usage was already atomically reserved at the start of the request
    # based on len(dependencies) - this prevents race conditions

    # Queue not-found packages for async collection (if SQS configured)
    queued_count = 0
    if not_found:
        queued_count = _queue_packages_for_collection(not_found, ecosystem)

    # Calculate counts by risk level
    critical_count = sum(1 for r in results if r["risk_level"] == "CRITICAL")
    high_count = sum(1 for r in results if r["risk_level"] == "HIGH")
    medium_count = sum(1 for r in results if r["risk_level"] == "MEDIUM")
    low_count = sum(1 for r in results if r["risk_level"] == "LOW")

    # Calculate data quality summary in single pass
    quality_counts = {"verified": 0, "partial": 0, "unverified": 0, "unavailable": 0}
    verified_risk = 0
    unverified_risk = 0

    for r in results:
        assessment = r.get("data_quality", {}).get("assessment", "UNVERIFIED")
        risk = r.get("risk_level")

        if assessment == "VERIFIED":
            quality_counts["verified"] += 1
            if risk in ("HIGH", "CRITICAL"):
                verified_risk += 1
        elif assessment == "PARTIAL":
            quality_counts["partial"] += 1
            if risk in ("HIGH", "CRITICAL"):
                unverified_risk += 1
        elif assessment == "UNAVAILABLE":
            quality_counts["unavailable"] += 1
            if risk in ("HIGH", "CRITICAL"):
                unverified_risk += 1
        else:
            quality_counts["unverified"] += 1
            if risk in ("HIGH", "CRITICAL"):
                unverified_risk += 1

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
        # Data quality breakdown
        "data_quality": {
            "verified_count": quality_counts["verified"],
            "partial_count": quality_counts["partial"],
            "unverified_count": quality_counts["unverified"],
            "unavailable_count": quality_counts["unavailable"],
        },
        "verified_risk_count": verified_risk,
        "unverified_risk_count": unverified_risk,
    }

    # Add discovery info if packages were queued for collection
    if queued_count > 0:
        response_body["discovery"] = {
            "queued": queued_count,
            "skipped": len(not_found) - queued_count,
            "message": f"{queued_count} package(s) queued for collection. Re-scan later for results.",
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
