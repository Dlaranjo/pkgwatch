"""
Auth Me Endpoint - GET /auth/me

Returns current authenticated user info from session cookie.

Supports optional ?refresh=stripe query parameter to fetch fresh
subscription data from Stripe and update DynamoDB cache.
"""

import json
import logging
import os
import time
from decimal import Decimal
from http.cookies import SimpleCookie

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from shared.response_utils import decimal_default, error_response, get_cors_headers
from shared.constants import TIER_LIMITS

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import session verification
from api.auth_callback import verify_session_token

dynamodb = boto3.resource("dynamodb")
secretsmanager = boto3.client("secretsmanager")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")

# Price ID to tier mapping (configured via environment)
PRICE_TO_TIER = {
    (os.environ.get("STRIPE_PRICE_STARTER") or "price_starter"): "starter",
    (os.environ.get("STRIPE_PRICE_PRO") or "price_pro"): "pro",
    (os.environ.get("STRIPE_PRICE_BUSINESS") or "price_business"): "business",
}

# Cached Stripe API key with TTL
_stripe_api_key_cache: str | None = None
_stripe_api_key_cache_time = 0.0
STRIPE_CACHE_TTL = 300  # 5 minutes


def _get_stripe_api_key() -> str | None:
    """Retrieve Stripe API key from Secrets Manager (cached with TTL)."""
    global _stripe_api_key_cache, _stripe_api_key_cache_time

    if _stripe_api_key_cache and (time.time() - _stripe_api_key_cache_time) < STRIPE_CACHE_TTL:
        return _stripe_api_key_cache

    if not STRIPE_SECRET_ARN:
        return None

    try:
        response = secretsmanager.get_secret_value(SecretId=STRIPE_SECRET_ARN)
        secret_value = response.get("SecretString", "")
        try:
            secret_json = json.loads(secret_value)
            api_key = secret_json.get("key") or secret_value
        except json.JSONDecodeError:
            api_key = secret_value

        _stripe_api_key_cache = api_key
        _stripe_api_key_cache_time = time.time()
        return api_key
    except ClientError as e:
        logger.error(f"Failed to retrieve Stripe API key: {e}")
        return None


def handler(event, context):
    """
    Lambda handler for GET /auth/me.

    Returns the current authenticated user's info.

    Query Parameters:
        refresh=stripe: Fetch fresh subscription data from Stripe and update DynamoDB
    """
    # Extract origin for CORS (outside try block so exception handler can use it)
    headers = event.get("headers", {}) or {}
    origin = headers.get("origin") or headers.get("Origin")

    try:

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
        email = session_data.get("email")

        # Check for refresh parameter
        query_params = event.get("queryStringParameters") or {}
        should_refresh = query_params.get("refresh") == "stripe"

        # Get fresh user data from DynamoDB
        table = dynamodb.Table(API_KEYS_TABLE)
        response = table.query(
            KeyConditionExpression=Key("pk").eq(user_id),
        )
        items = response.get("Items", [])

        # Separate API keys from metadata records
        api_keys = []
        user_meta = None
        for item in items:
            sk = item.get("sk", "")
            if sk == "PENDING":
                continue
            elif sk == "USER_META":
                user_meta = item
            else:
                api_keys.append(item)

        if not api_keys:
            return error_response(404, "user_not_found", "User account not found", origin=origin)

        # Use the first key for metadata (tier, created_at, etc.)
        # All keys should have the same tier
        primary_key = api_keys[0]

        # Track data source for response
        data_source = "cache"

        # Handle Stripe refresh if requested and user has subscription
        stripe_subscription_id = primary_key.get("stripe_subscription_id")
        if should_refresh and stripe_subscription_id:
            refreshed_data = _refresh_from_stripe(
                table, user_id, primary_key, api_keys, stripe_subscription_id
            )
            if refreshed_data:
                # Use refreshed data
                primary_key = refreshed_data
                data_source = "live"
                logger.info(f"Refreshed subscription data from Stripe for user {user_id}")

        # Get authoritative usage from USER_META (if exists)
        # Fall back to aggregating per-key counters for backward compatibility
        if user_meta and "requests_this_month" in user_meta:
            total_requests = int(user_meta.get("requests_this_month", 0))
        else:
            # Backward compatibility: sum per-key counters
            total_requests = sum(
                int(key.get("requests_this_month", 0))
                for key in api_keys
            )

        # Return user info with CORS headers and no-cache to prevent stale data
        response_headers = {
            "Content-Type": "application/json",
            "Cache-Control": "no-store, no-cache, must-revalidate",
        }
        response_headers.update(get_cors_headers(origin))

        # Get cancellation state if present
        cancellation_pending = primary_key.get("cancellation_pending", False)
        cancellation_date = primary_key.get("cancellation_date")

        # Get billing cycle end for reset date calculation
        current_period_end = primary_key.get("current_period_end")

        return {
            "statusCode": 200,
            "headers": response_headers,
            "body": json.dumps({
                "user_id": user_id,
                "email": email,
                "tier": primary_key.get("tier", "free"),
                "requests_this_month": total_requests,
                "monthly_limit": TIER_LIMITS.get(primary_key.get("tier", "free"), TIER_LIMITS["free"]),
                "created_at": primary_key.get("created_at"),
                "last_login": primary_key.get("last_login"),
                "cancellation_pending": cancellation_pending,
                "cancellation_date": cancellation_date,
                "current_period_end": current_period_end,
                "data_source": data_source,
            }, default=decimal_default),
        }
    except Exception as e:
        logger.error(f"Error in auth_me handler: {e}")
        return error_response(500, "internal_error", "An error occurred processing your request", origin=origin)


def _refresh_from_stripe(table, user_id: str, primary_key: dict, api_keys: list, subscription_id: str) -> dict | None:
    """Fetch fresh subscription data from Stripe and update DynamoDB.

    Args:
        table: DynamoDB table resource
        user_id: User ID for USER_META update
        primary_key: Primary API key record to update
        api_keys: All API key records for the user
        subscription_id: Stripe subscription ID

    Returns:
        Updated primary_key dict with fresh data, or None if refresh failed
    """
    import stripe

    stripe_api_key = _get_stripe_api_key()
    if not stripe_api_key:
        logger.warning("Stripe API key not available for refresh")
        return None

    stripe.api_key = stripe_api_key

    try:
        # Fetch subscription from Stripe
        subscription = stripe.Subscription.retrieve(subscription_id)

        # Extract relevant fields
        status = subscription.get("status")
        cancel_at_period_end = subscription.get("cancel_at_period_end", False)

        # Determine tier and billing cycle from subscription items
        # Note: current_period_start/end are on the item, not the subscription
        items = subscription.get("items", {}).get("data", [])
        tier = primary_key.get("tier", "free")  # Default to current tier
        current_period_end = None
        if items:
            item = items[0]
            price_id = item.get("price", {}).get("id")
            tier = PRICE_TO_TIER.get(price_id, tier)
            current_period_end = item.get("current_period_end")

        # Determine cancellation date
        cancellation_date = current_period_end if cancel_at_period_end else None

        # Handle non-active subscriptions
        if status not in ["active", "trialing"]:
            # Subscription is no longer active
            tier = "free"
            cancel_at_period_end = False
            cancellation_date = None
            current_period_end = None

        # Update all API key records in DynamoDB
        for key in api_keys:
            table.update_item(
                Key={"pk": key["pk"], "sk": key["sk"]},
                UpdateExpression=(
                    "SET tier = :tier, "
                    "cancellation_pending = :cancel_pending, "
                    "cancellation_date = :cancel_date, "
                    "current_period_end = :period_end"
                ),
                ExpressionAttributeValues={
                    ":tier": tier,
                    ":cancel_pending": cancel_at_period_end,
                    ":cancel_date": cancellation_date,
                    ":period_end": current_period_end,
                },
            )

        # Also update USER_META
        try:
            table.update_item(
                Key={"pk": user_id, "sk": "USER_META"},
                UpdateExpression=(
                    "SET tier = :tier, "
                    "cancellation_pending = :cancel_pending, "
                    "cancellation_date = :cancel_date, "
                    "current_period_end = :period_end"
                ),
                ConditionExpression="attribute_exists(pk)",
                ExpressionAttributeValues={
                    ":tier": tier,
                    ":cancel_pending": cancel_at_period_end,
                    ":cancel_date": cancellation_date,
                    ":period_end": current_period_end,
                },
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                logger.error(f"Failed to update USER_META during refresh: {e}")

        # Return updated data
        return {
            **primary_key,
            "tier": tier,
            "cancellation_pending": cancel_at_period_end,
            "cancellation_date": cancellation_date,
            "current_period_end": current_period_end,
        }

    except stripe.StripeError as e:
        logger.error(f"Stripe error during refresh: {e}")
        return None
    except Exception as e:
        logger.error(f"Error refreshing from Stripe: {e}")
        return None




