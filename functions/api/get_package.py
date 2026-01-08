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

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import from shared module (bundled with Lambda)
from shared.auth import validate_api_key, increment_usage

# Demo mode settings
DEMO_REQUESTS_PER_HOUR = 20
DEMO_ALLOWED_ORIGINS = [
    "https://dephealth.laranjo.dev",
    "http://localhost:4321",  # Astro dev server
    "http://localhost:3000",
]


def decimal_default(obj):
    """JSON encoder for Decimal types from DynamoDB."""
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

dynamodb = boto3.resource("dynamodb")
PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "dephealth-packages")
DEMO_RATE_LIMIT_TABLE = os.environ.get("API_KEYS_TABLE", "dephealth-api-keys")


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
    """Extract client IP from API Gateway event."""
    # Try X-Forwarded-For first (set by API Gateway/load balancers)
    headers = event.get("headers", {})
    forwarded = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP (original client)
        return forwarded.split(",")[0].strip()

    # Fall back to requestContext
    request_context = event.get("requestContext", {})
    identity = request_context.get("identity", {})
    return identity.get("sourceIp", "unknown")


def _check_demo_rate_limit(client_ip: str) -> tuple[bool, int]:
    """
    Check if IP is within demo rate limit.

    Returns:
        (allowed, requests_remaining)
    """
    table = dynamodb.Table(DEMO_RATE_LIMIT_TABLE)
    now = datetime.now(timezone.utc)
    current_hour = now.strftime("%Y-%m-%d-%H")
    pk = f"demo#{client_ip}"
    sk = f"hour#{current_hour}"

    try:
        # Atomic increment and get
        response = table.update_item(
            Key={"pk": pk, "sk": sk},
            UpdateExpression="SET requests = if_not_exists(requests, :zero) + :inc, #ttl = :ttl",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={
                ":zero": 0,
                ":inc": 1,
                ":ttl": int(now.timestamp()) + 7200,  # Expire after 2 hours
            },
            ReturnValues="UPDATED_NEW",
        )

        current_requests = response.get("Attributes", {}).get("requests", 1)
        remaining = max(0, DEMO_REQUESTS_PER_HOUR - current_requests)

        return current_requests <= DEMO_REQUESTS_PER_HOUR, remaining

    except Exception as e:
        logger.warning(f"Demo rate limit check failed: {e}")
        # Allow on error, but log it
        return True, DEMO_REQUESTS_PER_HOUR


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

    if user:
        # Authenticated request - check monthly limit
        if user["requests_this_month"] >= user["monthly_limit"]:
            return _rate_limit_response(user, cors_headers)
    else:
        # No valid API key - try demo mode
        client_ip = _get_client_ip(event)
        allowed, demo_remaining = _check_demo_rate_limit(client_ip)

        if not allowed:
            return _demo_rate_limit_response(cors_headers)

        is_demo_mode = True
        logger.info(f"Demo request from IP: {client_ip}, remaining: {demo_remaining}")

    # Extract path parameters
    path_params = event.get("pathParameters", {})
    ecosystem = path_params.get("ecosystem", "npm")
    name = path_params.get("name")

    if not name:
        return _error_response(400, "missing_parameter", "Package name is required", cors_headers)

    # Handle URL-encoded package names (e.g., %40babel%2Fcore -> @babel/core)
    from urllib.parse import unquote
    name = unquote(name)

    # Validate ecosystem
    if ecosystem not in ["npm"]:  # Can expand later: "pypi", "maven", etc.
        return _error_response(
            400,
            "invalid_ecosystem",
            f"Unsupported ecosystem: {ecosystem}. Supported: npm",
            cors_headers,
        )

    # Fetch package from DynamoDB
    table = dynamodb.Table(PACKAGES_TABLE)

    try:
        response = table.get_item(Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"})
        item = response.get("Item")
    except Exception as e:
        logger.error(f"DynamoDB error: {e}")
        return _error_response(500, "internal_error", "Failed to fetch package data", cors_headers)

    if not item:
        return _error_response(
            404,
            "package_not_found",
            f"Package '{name}' not found in {ecosystem}",
            cors_headers,
        )

    # Increment usage counter (only for authenticated requests)
    if user:
        try:
            increment_usage(user["user_id"], user["key_hash"])
        except Exception as e:
            logger.warning(f"Failed to increment usage: {e}")

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
        },
        "advisories": item.get("advisories", []),
        "latest_version": item.get("latest_version"),
        "last_published": item.get("last_published"),
        "repository_url": item.get("repository_url"),
        "last_updated": item.get("last_updated"),
    }

    # Build response headers
    response_headers = {
        "Content-Type": "application/json",
        **cors_headers,
    }

    if is_demo_mode:
        response_headers["X-Demo-Mode"] = "true"
        response_headers["X-RateLimit-Limit"] = str(DEMO_REQUESTS_PER_HOUR)
        response_headers["X-RateLimit-Remaining"] = str(demo_remaining)
    else:
        response_headers["X-RateLimit-Limit"] = str(user["monthly_limit"])
        response_headers["X-RateLimit-Remaining"] = str(
            user["monthly_limit"] - user["requests_this_month"] - 1
        )

    return {
        "statusCode": 200,
        "headers": response_headers,
        "body": json.dumps(response_data, default=decimal_default),
    }


def _error_response(status_code: int, code: str, message: str, cors_headers: dict = None) -> dict:
    """Generate error response with optional CORS headers."""
    headers = {"Content-Type": "application/json"}
    if cors_headers:
        headers.update(cors_headers)

    return {
        "statusCode": status_code,
        "headers": headers,
        "body": json.dumps({"error": {"code": code, "message": message}}),
    }


def _rate_limit_response(user: dict, cors_headers: dict = None) -> dict:
    """Generate rate limit exceeded response with Retry-After header."""
    now = datetime.now(timezone.utc)
    days_in_month = calendar.monthrange(now.year, now.month)[1]
    seconds_until_reset = (days_in_month - now.day) * 86400 + (24 - now.hour) * 3600

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
                "upgrade_url": "https://dephealth.laranjo.dev/pricing",
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
                "signup_url": "https://dephealth.laranjo.dev/signup",
            }
        }),
    }
