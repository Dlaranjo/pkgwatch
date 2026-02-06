"""
Usage Endpoint - GET /usage

Returns API usage statistics for the current user.
Requires API key authentication.
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import from shared module (bundled with Lambda)
from shared.auth import TIER_LIMITS, validate_api_key
from shared.response_utils import decimal_default, error_response, get_cors_headers

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")


def handler(event, context):
    """
    Lambda handler for GET /usage.

    Returns current usage statistics and limits.
    """
    origin = None
    try:
        # Extract headers for auth and CORS
        headers = event.get("headers") or {}
        api_key = headers.get("x-api-key") or headers.get("X-API-Key")
        origin = headers.get("origin") or headers.get("Origin")

        # Validate API key
        user = validate_api_key(api_key)

        if not user:
            return error_response(401, "invalid_api_key", "Invalid or missing API key", origin=origin)

        # Get authoritative usage and billing cycle from USER_META
        table = dynamodb.Table(API_KEYS_TABLE)
        meta_response = table.get_item(
            Key={"pk": user["user_id"], "sk": "USER_META"},
            ProjectionExpression="requests_this_month, current_period_end",
        )

        # Use USER_META.requests_this_month if available, fall back to per-key for backward compatibility
        meta_item = meta_response.get("Item", {})
        if "requests_this_month" in meta_item:
            requests_this_month = int(meta_item["requests_this_month"])
        else:
            requests_this_month = user["requests_this_month"]

        # Get billing cycle end from USER_META or per-key record
        current_period_end = meta_item.get("current_period_end") or user.get("current_period_end")

        # Calculate reset date based on tier and billing cycle
        now = datetime.now(timezone.utc)
        tier = user.get("tier", "free")

        if tier == "free" or not current_period_end:
            # Free users and legacy paid users: reset on 1st of month
            if now.month == 12:
                reset_date = datetime(now.year + 1, 1, 1, tzinfo=timezone.utc)
            else:
                reset_date = datetime(now.year, now.month + 1, 1, tzinfo=timezone.utc)
        else:
            # Paid users with billing data: reset on billing cycle end
            reset_date = datetime.fromtimestamp(int(current_period_end), tz=timezone.utc)

        seconds_until_reset = (reset_date - now).total_seconds()

        # Calculate usage percentage
        usage_percentage = requests_this_month / user["monthly_limit"] * 100 if user["monthly_limit"] > 0 else 0

        response_headers = {
            "Content-Type": "application/json",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "X-RateLimit-Limit": str(user["monthly_limit"]),
            "X-RateLimit-Remaining": str(max(0, user["monthly_limit"] - requests_this_month)),
        }
        response_headers.update(get_cors_headers(origin))

        return {
            "statusCode": 200,
            "headers": response_headers,
            "body": json.dumps(
                {
                    "tier": user["tier"],
                    "usage": {
                        "requests_this_month": requests_this_month,
                        "monthly_limit": user["monthly_limit"],
                        "remaining": max(0, user["monthly_limit"] - requests_this_month),
                        "usage_percentage": round(usage_percentage, 1),
                    },
                    "reset": {
                        "date": reset_date.isoformat(),
                        "seconds_until_reset": int(seconds_until_reset),
                    },
                    "limits_by_tier": {tier: limit for tier, limit in TIER_LIMITS.items()},
                },
                default=decimal_default,
            ),
        }
    except Exception as e:
        logger.error(f"Error in get_usage handler: {e}")
        return error_response(500, "internal_error", "An error occurred processing your request", origin=origin)
