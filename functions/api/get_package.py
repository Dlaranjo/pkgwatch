"""
Get Package Endpoint - GET /packages/{ecosystem}/{name}

Returns health score and details for a single package.
Supports both authenticated (API key) and demo mode (IP rate-limited).
"""

import calendar
import json
import logging
import os
from datetime import datetime, timezone

from shared.logging_utils import configure_structured_logging, set_request_id

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import from shared module (bundled with Lambda)
from shared.auth import check_and_increment_usage_with_bonus, validate_api_key
from shared.aws_clients import get_dynamodb
from shared.constants import DEMO_REQUESTS_PER_HOUR
from shared.data_quality import build_data_quality_full, is_queryable
from shared.package_validation import (
    normalize_npm_name,
    normalize_pypi_name,
    validate_npm_package_name,
    validate_pypi_package_name,
)
from shared.rate_limit_utils import check_usage_alerts
from shared.response_utils import decimal_default, error_response, get_cors_headers

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
DEMO_RATE_LIMIT_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")


from shared.request_utils import get_client_ip as _get_client_ip


def _format_openssf_checks(checks: list) -> dict:
    """
    Format OpenSSF checks for API response.

    Highlights key security checks with pass/partial/fail status.
    """
    KEY_CHECKS = [
        "Branch-Protection",
        "Signed-Releases",
        "Security-Policy",
        "Code-Review",
        "Dependency-Update-Tool",
        "Vulnerabilities",
    ]

    result = {
        "summary": {},
        "all_checks": [],
    }

    for check in checks or []:
        name = check.get("name", "")
        score = check.get("score", 0)

        result["all_checks"].append(
            {
                "name": name,
                "score": score,
                "reason": check.get("reason", ""),
            }
        )

        if name in KEY_CHECKS:
            # Normalize to pass/partial/fail
            if score >= 8:
                status = "pass"
            elif score >= 5:
                status = "partial"
            else:
                status = "fail"

            result["summary"][name] = {
                "score": score,
                "status": status,
            }

    return result


def _check_demo_rate_limit(client_ip: str) -> tuple[bool, int]:
    """
    Check if IP is within demo rate limit using atomic conditional update.

    Uses ConditionExpression to atomically check AND increment, preventing
    race conditions where concurrent requests could exceed the limit.

    Returns:
        (allowed, requests_remaining)
    """
    from botocore.exceptions import ClientError

    table = get_dynamodb().Table(DEMO_RATE_LIMIT_TABLE)
    now = datetime.now(timezone.utc)
    current_hour = now.strftime("%Y-%m-%d-%H")
    pk = f"demo#{client_ip}"
    sk = f"hour#{current_hour}"

    try:
        # Atomic check-and-increment using ConditionExpression
        # This ensures concurrent requests don't exceed the limit
        response = table.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression="SET requests = if_not_exists(requests, :zero) + :inc, #ttl = :ttl",
            ConditionExpression="attribute_not_exists(requests) OR requests < :limit",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={
                ":zero": 0,
                ":inc": 1,
                ":limit": DEMO_REQUESTS_PER_HOUR,
                ":ttl": int(now.timestamp()) + 7200,  # Expire after 2 hours
            },
            ReturnValues="UPDATED_NEW",
        )

        current_requests = response.get("Attributes", {}).get("requests", 1)
        remaining = max(0, DEMO_REQUESTS_PER_HOUR - current_requests)

        return True, remaining

    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Rate limit exceeded - condition check failed
            return False, 0
        # Other DynamoDB errors
        logger.warning(f"Demo rate limit check failed: {e}")
        # Fail closed for security - deny on error
        return False, 0

    except Exception as e:
        logger.warning(f"Demo rate limit check failed: {e}")
        # Fail closed for security - deny on error
        return False, 0


def handler(event, context):
    """
    Lambda handler for GET /packages/{ecosystem}/{name}.

    Returns package health score and related data.
    Supports both authenticated (API key) and demo mode (IP rate-limited).
    """
    configure_structured_logging()
    set_request_id(event)

    headers = event.get("headers", {})
    origin = headers.get("origin") or headers.get("Origin") or ""
    cors_headers = get_cors_headers(origin)

    # Extract API key from headers
    api_key = headers.get("x-api-key") or headers.get("X-API-Key")
    key_was_provided = bool(api_key)

    # Try API key authentication first
    user = validate_api_key(api_key)
    is_demo_mode = False
    demo_warning = False
    demo_remaining = 0
    authenticated_usage_count = 0

    if user:
        # Usage counted after data quality gate — avoids billing for 202 responses
        pass
    else:
        # No valid API key - try demo mode
        demo_warning = key_was_provided
        client_ip = _get_client_ip(event)
        allowed, demo_remaining = _check_demo_rate_limit(client_ip)

        if not allowed:
            response = _demo_rate_limit_response(cors_headers)
            if demo_warning:
                response["headers"]["X-Auth-Warning"] = "api_key_not_recognized"
            return response

        is_demo_mode = True
        logger.info(f"Demo request from IP: {client_ip}, remaining: {demo_remaining}")

    # Extract path parameters (use `or {}` to handle explicit None)
    path_params = event.get("pathParameters") or {}
    ecosystem = path_params.get("ecosystem", "npm").lower()
    name = path_params.get("name")

    if not name:
        return error_response(400, "missing_parameter", "Package name is required", headers=cors_headers)

    # Handle URL-encoded package names (e.g., %40babel%2Fcore -> @babel/core)
    from urllib.parse import quote, unquote

    name = unquote(name)

    # Normalize package names (both registries are case-insensitive)
    if ecosystem == "npm":
        name = normalize_npm_name(name)
    elif ecosystem == "pypi":
        name = normalize_pypi_name(name)

    # Validate package name
    if ecosystem == "npm":
        is_valid, error_msg, _ = validate_npm_package_name(name)
    elif ecosystem == "pypi":
        is_valid, error_msg, _ = validate_pypi_package_name(name)
    else:
        is_valid, error_msg = True, None

    if not is_valid:
        return error_response(400, "invalid_package_name", error_msg, headers=cors_headers)

    # Validate ecosystem
    if ecosystem not in ["npm", "pypi"]:
        return error_response(
            400,
            "invalid_ecosystem",
            f"Unsupported ecosystem: {ecosystem}. Supported: npm, pypi",
            headers=cors_headers,
        )

    # Fetch package from DynamoDB
    table = get_dynamodb().Table(PACKAGES_TABLE)

    try:
        response = table.get_item(Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"})
        item = response.get("Item")
    except Exception as e:
        logger.error(f"DynamoDB error: {e}")
        return error_response(500, "internal_error", "Failed to fetch package data", headers=cors_headers)

    if not item:
        return error_response(
            404,
            "package_not_found",
            f"Package '{name}' not found in {ecosystem}",
            headers=cors_headers,
            details={"request_url": "/packages/request"},
        )

    # Data quality gate - return 202 for packages still being collected
    # Use ?include_incomplete=true to bypass for power users/debugging
    query_params = event.get("queryStringParameters") or {}
    include_incomplete = query_params.get("include_incomplete") == "true"

    # Use stored queryable flag, falling back to computed value for pre-migration packages
    queryable = item.get("queryable") if item.get("queryable") is not None else is_queryable(item)

    if not include_incomplete and not queryable:
        data_status = item.get("data_status", "pending")
        # Pending = short retry (data collection in progress)
        # Other statuses = longer retry (may need manual intervention)
        retry_after = 60 if data_status == "pending" else 300

        response_202_headers = {
            "Content-Type": "application/json",
            "Retry-After": str(retry_after),
            **cors_headers,
        }
        if demo_warning:
            response_202_headers["X-Auth-Warning"] = "api_key_not_recognized"

        return {
            "statusCode": 202,
            "headers": response_202_headers,
            "body": json.dumps(
                {
                    "status": "collecting",
                    "package": name,
                    "ecosystem": ecosystem,
                    "data_status": data_status,
                    "message": "Package data is being collected. Retry after the specified interval or use ?include_incomplete=true to get partial data.",
                    "retry_after_seconds": retry_after,
                }
            ),
        }

    # Bill authenticated users only for complete (200) responses
    # Moved after 202 gate to avoid billing for incomplete data
    if user:
        allowed, authenticated_usage_count, _bonus = check_and_increment_usage_with_bonus(
            user["user_id"], user["key_hash"], user["monthly_limit"]
        )
        if not allowed:
            return _rate_limit_response(user, cors_headers)

    # Format response
    response_data = {
        "package": name,
        "ecosystem": ecosystem,
        "health_score": item.get("health_score"),
        "risk_level": item.get("risk_level"),
        "abandonment_risk": item.get("abandonment_risk"),
        "components": item.get("score_components"),
        "confidence": item.get("confidence"),
        "signals": {
            "weekly_downloads": item.get("weekly_downloads"),
            "dependents_count": item.get("dependents_count"),
            "stars": item.get("stars"),
            "days_since_last_commit": item.get("days_since_last_commit"),
            "commits_90d": item.get("commits_90d"),
            "active_contributors_90d": item.get("active_contributors_90d"),
            "maintainer_count": item.get("maintainer_count"),
            "is_deprecated": item.get("is_deprecated"),
            "archived": item.get("archived"),
            "openssf_score": item.get("openssf_score"),
            # True bus factor: contribution distribution analysis
            # Default to 1 (solo maintainer) and LOW confidence if not calculated
            "true_bus_factor": item.get("true_bus_factor") or 1,
            "bus_factor_confidence": item.get("bus_factor_confidence") or "LOW",
        },
        # OpenSSF checks with pass/partial/fail status
        "openssf_checks": _format_openssf_checks(item.get("openssf_checks", [])),
        "advisories": item.get("advisories", []),
        "latest_version": item.get("latest_version"),
        "last_published": item.get("last_published"),
        "repository_url": item.get("repository_url"),
        "last_updated": item.get("last_updated"),
        # Data completeness transparency
        "data_quality": build_data_quality_full(item),
        # Feedback link for score disputes
        "feedback_url": f"https://github.com/Dlaranjo/pkgwatch/issues/new?title=Score+feedback:+{quote(ecosystem, safe='')}/{quote(name, safe='')}&labels=score-feedback",
    }

    # Build response headers
    response_headers = {
        "Content-Type": "application/json",
        **cors_headers,
    }

    if is_demo_mode:
        # Demo mode: hourly reset
        now = datetime.now(timezone.utc)
        next_hour = now.replace(minute=0, second=0, microsecond=0)
        # Add 1 hour to get to the next hour boundary
        reset_timestamp = int((next_hour.timestamp() + 3600))

        response_headers["X-Demo-Mode"] = "true"
        response_headers["X-RateLimit-Limit"] = str(DEMO_REQUESTS_PER_HOUR)
        response_headers["X-RateLimit-Remaining"] = str(demo_remaining)
        response_headers["X-RateLimit-Reset"] = str(reset_timestamp)
        if demo_warning:
            response_headers["X-Auth-Warning"] = "api_key_not_recognized"
    else:
        # Authenticated mode: monthly reset (end of month)
        now = datetime.now(timezone.utc)
        days_in_month = calendar.monthrange(now.year, now.month)[1]
        # Calculate seconds until end of month (midnight on the first of next month)
        reset_timestamp = int(now.replace(day=days_in_month, hour=23, minute=59, second=59).timestamp() + 1)

        # authenticated_usage_count reflects the count AFTER this request was counted
        response_headers["X-RateLimit-Limit"] = str(user["monthly_limit"])
        response_headers["X-RateLimit-Remaining"] = str(max(0, user["monthly_limit"] - authenticated_usage_count))
        response_headers["X-RateLimit-Reset"] = str(reset_timestamp)

        # Check for usage alerts and add to response
        alert = check_usage_alerts(user, authenticated_usage_count)
        if alert:
            response_headers["X-Usage-Alert"] = alert["level"]
            response_headers["X-Usage-Percent"] = str(alert["percent"])
            # Include alert in response body for API consumers
            response_data["usage_alert"] = alert

    return {
        "statusCode": 200,
        "headers": response_headers,
        "body": json.dumps(response_data, default=decimal_default),
    }


def _rate_limit_response(user: dict, cors_headers: dict = None) -> dict:
    """Generate rate limit exceeded response with Retry-After header."""
    now = datetime.now(timezone.utc)
    days_in_month = calendar.monthrange(now.year, now.month)[1]
    # Calculate exact reset timestamp (midnight on first of next month)
    reset_timestamp = int(now.replace(day=days_in_month, hour=23, minute=59, second=59).timestamp() + 1)
    seconds_until_reset = reset_timestamp - int(now.timestamp())

    headers = {
        "Content-Type": "application/json",
        "Retry-After": str(seconds_until_reset),
        "X-RateLimit-Limit": str(user["monthly_limit"]),
        "X-RateLimit-Remaining": "0",
    }
    if cors_headers:
        headers.update(cors_headers)

    return {
        "statusCode": 429,
        "headers": headers,
        "body": json.dumps(
            {
                "error": {
                    "code": "rate_limit_exceeded",
                    "message": f"Monthly limit of {user['monthly_limit']} requests exceeded",
                    "retry_after_seconds": seconds_until_reset,
                    "upgrade_url": "https://pkgwatch.dev/pricing",
                }
            }
        ),
    }


def _demo_rate_limit_response(cors_headers: dict = None) -> dict:
    """Generate rate limit response for demo mode."""
    headers = {
        "Content-Type": "application/json",
        "Retry-After": "3600",  # Reset in 1 hour
        "X-RateLimit-Limit": str(DEMO_REQUESTS_PER_HOUR),
        "X-RateLimit-Remaining": "0",
    }
    if cors_headers:
        headers.update(cors_headers)

    return {
        "statusCode": 429,
        "headers": headers,
        "body": json.dumps(
            {
                "error": {
                    "code": "demo_rate_limit_exceeded",
                    "message": f"Demo limit of {DEMO_REQUESTS_PER_HOUR} requests per hour exceeded",
                    "retry_after_seconds": 3600,
                    "signup_url": "https://pkgwatch.dev/start",
                }
            }
        ),
    }
