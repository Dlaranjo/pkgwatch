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
from decimal import Decimal

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import from shared module (bundled with Lambda)
from shared.auth import validate_api_key, check_and_increment_usage
from shared.response_utils import decimal_default, error_response
from shared.rate_limit_utils import check_usage_alerts, get_reset_timestamp
from shared.data_quality import build_data_quality_full
from shared.package_validation import normalize_npm_name

# Demo mode settings
DEMO_REQUESTS_PER_HOUR = 20
# Production CORS origins - localhost only allowed if ALLOW_DEV_CORS is set
_PROD_ORIGINS = [
    "https://pkgwatch.laranjo.dev",
    "https://app.pkgwatch.laranjo.dev",
]
_DEV_ORIGINS = [
    "http://localhost:4321",  # Astro dev server
    "http://localhost:3000",
]
DEMO_ALLOWED_ORIGINS = (
    _PROD_ORIGINS + _DEV_ORIGINS
    if os.environ.get("ALLOW_DEV_CORS") == "true"
    else _PROD_ORIGINS
)


# Lazy initialization to reduce cold start overhead
_dynamodb = None


def _get_dynamodb():
    """Get DynamoDB resource, creating it lazily on first use."""
    global _dynamodb
    if _dynamodb is None:
        import boto3
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb


PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
DEMO_RATE_LIMIT_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")


def _get_cors_headers(origin: str) -> dict:
    """Get CORS headers for allowed origins."""
    if origin in DEMO_ALLOWED_ORIGINS:
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, x-api-key",
        }
    return {}


def _get_client_ip(event: dict) -> str:
    """Extract client IP from API Gateway's verified source.

    SECURITY: Always use requestContext.identity.sourceIp which is set by
    API Gateway and cannot be spoofed by clients. Never trust X-Forwarded-For
    header for rate limiting as it can be forged.
    """
    # Use API Gateway's verified source IP (cannot be spoofed)
    source_ip = event.get("requestContext", {}).get("identity", {}).get("sourceIp")
    if source_ip:
        return source_ip

    # Log warning if missing (shouldn't happen with proper API Gateway config)
    logger.warning("Missing sourceIp in requestContext - possible misconfiguration")
    return "unknown"


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

        result["all_checks"].append({
            "name": name,
            "score": score,
            "reason": check.get("reason", ""),
        })

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

    table = _get_dynamodb().Table(DEMO_RATE_LIMIT_TABLE)
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
    headers = event.get("headers", {})
    origin = headers.get("origin") or headers.get("Origin") or ""
    cors_headers = _get_cors_headers(origin)

    # Extract API key from headers
    api_key = headers.get("x-api-key") or headers.get("X-API-Key")

    # Try API key authentication first
    user = validate_api_key(api_key)
    is_demo_mode = False
    demo_remaining = 0
    authenticated_usage_count = 0

    if user:
        # Authenticated request - atomically check limit and increment
        # This prevents race conditions where concurrent requests exceed the limit
        allowed, authenticated_usage_count = check_and_increment_usage(
            user["user_id"], user["key_hash"], user["monthly_limit"]
        )
        if not allowed:
            return _rate_limit_response(user, cors_headers)
    else:
        # No valid API key - try demo mode
        client_ip = _get_client_ip(event)
        allowed, demo_remaining = _check_demo_rate_limit(client_ip)

        if not allowed:
            return _demo_rate_limit_response(cors_headers)

        is_demo_mode = True
        logger.info(f"Demo request from IP: {client_ip}, remaining: {demo_remaining}")

    # Extract path parameters (use `or {}` to handle explicit None)
    path_params = event.get("pathParameters") or {}
    ecosystem = path_params.get("ecosystem", "npm")
    name = path_params.get("name")

    if not name:
        return error_response(400, "missing_parameter", "Package name is required", headers=cors_headers)

    # Handle URL-encoded package names (e.g., %40babel%2Fcore -> @babel/core)
    from urllib.parse import unquote
    name = unquote(name)

    # Normalize npm package names to lowercase (npm is case-insensitive)
    if ecosystem == "npm":
        name = normalize_npm_name(name)

    # Validate ecosystem
    if ecosystem not in ["npm", "pypi"]:
        return error_response(
            400,
            "invalid_ecosystem",
            f"Unsupported ecosystem: {ecosystem}. Supported: npm, pypi",
            headers=cors_headers,
        )

    # Fetch package from DynamoDB
    table = _get_dynamodb().Table(PACKAGES_TABLE)

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
        )

    # Note: Usage counter already incremented atomically in check_and_increment_usage

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
    else:
        # Authenticated mode: monthly reset (end of month)
        now = datetime.now(timezone.utc)
        days_in_month = calendar.monthrange(now.year, now.month)[1]
        # Calculate seconds until end of month (midnight on the first of next month)
        reset_timestamp = int(now.replace(day=days_in_month, hour=23, minute=59, second=59).timestamp() + 1)

        # authenticated_usage_count reflects the count AFTER this request was counted
        response_headers["X-RateLimit-Limit"] = str(user["monthly_limit"])
        response_headers["X-RateLimit-Remaining"] = str(
            max(0, user["monthly_limit"] - authenticated_usage_count)
        )
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
        "body": json.dumps({
            "error": {
                "code": "rate_limit_exceeded",
                "message": f"Monthly limit of {user['monthly_limit']} requests exceeded",
                "retry_after_seconds": seconds_until_reset,
                "upgrade_url": "https://pkgwatch.laranjo.dev/pricing",
            }
        }),
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
        "body": json.dumps({
            "error": {
                "code": "demo_rate_limit_exceeded",
                "message": f"Demo limit of {DEMO_REQUESTS_PER_HOUR} requests per hour exceeded",
                "retry_after_seconds": 3600,
                "signup_url": "https://pkgwatch.laranjo.dev/signup",
            }
        }),
    }
