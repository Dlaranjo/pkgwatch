"""
Upgrade Preview Endpoint - POST /upgrade/preview

Previews the prorated cost for a subscription upgrade.
Requires session authentication (logged-in user with active subscription).
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie

import stripe
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")

# Import shared utilities
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../shared"))
from billing_utils import get_stripe_api_key
from constants import TIER_ORDER
from response_utils import error_response, success_response

from shared.aws_clients import get_dynamodb

# Price ID to tier mapping (configured via environment)
TIER_TO_PRICE = {
    "starter": os.environ.get("STRIPE_PRICE_STARTER") or None,
    "pro": os.environ.get("STRIPE_PRICE_PRO") or None,
    "business": os.environ.get("STRIPE_PRICE_BUSINESS") or None,
}


def _get_origin(event: dict) -> str | None:
    """Extract Origin header from request."""
    headers = event.get("headers", {}) or {}
    return headers.get("origin") or headers.get("Origin")


def handler(event, context):
    """
    Lambda handler for POST /upgrade/preview.

    Request body:
    {
        "tier": "pro" | "business"
    }

    Returns:
    {
        "preview": {
            "current_tier": "starter",
            "new_tier": "pro",
            "credit_amount_cents": 500,
            "new_plan_prorated_cents": 4900,
            "amount_due_cents": 4400,
            "amount_due_formatted": "$44.00",
            "currency": "usd",
            "current_period_end": "2026-02-13",
            "proration_date": 1736812800,
            "cancellation_will_clear": false
        }
    }
    """
    origin = _get_origin(event)
    headers = event.get("headers", {}) or {}

    # Get Stripe API key
    stripe_api_key = get_stripe_api_key()
    if not stripe_api_key:
        logger.error("Stripe API key not configured")
        return error_response(500, "stripe_not_configured", "Payment system not configured", origin=origin)

    stripe.api_key = stripe_api_key

    # Authenticate user via session cookie
    cookie_header = headers.get("cookie") or headers.get("Cookie") or ""
    session_token = None
    if cookie_header:
        cookies = SimpleCookie()
        cookies.load(cookie_header)
        if "session" in cookies:
            session_token = cookies["session"].value

    if not session_token:
        return error_response(401, "unauthorized", "Please log in to upgrade", origin=origin)

    # Import here to avoid circular imports at module level
    from api.auth_callback import verify_session_token

    session_data = verify_session_token(session_token)
    if not session_data:
        return error_response(401, "session_expired", "Session expired. Please log in again.", origin=origin)

    user_id = session_data.get("user_id")
    email = session_data.get("email")

    # Parse request body
    try:
        body = json.loads(event.get("body", "{}") or "{}")
    except json.JSONDecodeError:
        return error_response(400, "invalid_json", "Request body must be valid JSON", origin=origin)

    tier = body.get("tier", "").lower()

    # Validate tier - only allow upgrade tiers (not starter since can't upgrade to it)
    if tier not in ["pro", "business"]:
        return error_response(
            400,
            "invalid_tier",
            "Invalid tier. Choose: pro or business",
            origin=origin,
        )

    new_price_id = TIER_TO_PRICE.get(tier)
    if not new_price_id:
        logger.error(f"Price ID not configured for tier: {tier}")
        return error_response(500, "price_not_configured", "Pricing not configured for this tier", origin=origin)

    # Get user's current subscription data from DynamoDB
    table = get_dynamodb().Table(API_KEYS_TABLE)
    response = table.query(
        IndexName="email-index",
        KeyConditionExpression=Key("email").eq(email),
    )
    items = response.get("Items", [])

    stripe_customer_id = None
    stripe_subscription_id = None
    current_tier = "free"

    for item in items:
        # Skip PENDING records
        if item.get("sk") == "PENDING":
            continue
        if item.get("email_verified"):
            stripe_customer_id = item.get("stripe_customer_id")
            stripe_subscription_id = item.get("stripe_subscription_id")
            current_tier = item.get("tier", "free")
            break

    # Validate user has an active subscription
    if not stripe_subscription_id:
        return error_response(
            400,
            "no_active_subscription",
            "No active subscription found. Use checkout for new subscriptions.",
            origin=origin,
        )

    # Validate it's an upgrade (not same tier or downgrade)
    if TIER_ORDER.get(tier, 0) <= TIER_ORDER.get(current_tier, 0):
        if tier == current_tier:
            return error_response(
                400,
                "same_tier",
                f"You are already on the {tier} plan.",
                origin=origin,
            )
        else:
            return error_response(
                400,
                "downgrade_not_allowed",
                "Use billing portal for downgrades.",
                origin=origin,
            )

    try:
        # Fetch subscription from Stripe to get current item ID (NOT stored in DynamoDB)
        subscription = stripe.Subscription.retrieve(stripe_subscription_id)

        # Validate subscription status
        status = subscription.get("status")
        if status == "past_due":
            return error_response(
                402,
                "payment_required",
                "Please update your payment method before upgrading.",
                origin=origin,
            )

        if status not in ["active", "trialing"]:
            return error_response(
                400,
                "subscription_invalid",
                f"Cannot upgrade subscription with status: {status}",
                origin=origin,
            )

        # Get item ID from Stripe (critical - this is not stored in DB)
        current_item_id = subscription["items"]["data"][0]["id"]

        # Check if cancellation is pending
        cancel_at_period_end = subscription.get("cancel_at_period_end", False)

        # Generate proration timestamp
        proration_date = int(time.time())

        # Preview with Stripe API (v7 uses upcoming(), v8+ uses create_preview())
        if hasattr(stripe.Invoice, "create_preview"):
            preview = stripe.Invoice.create_preview(
                customer=stripe_customer_id,
                subscription=stripe_subscription_id,
                subscription_details={
                    "items": [
                        {
                            "id": current_item_id,
                            "price": new_price_id,
                        }
                    ],
                    "proration_behavior": "always_invoice",
                    "proration_date": proration_date,
                },
            )
        else:
            preview = stripe.Invoice.upcoming(
                customer=stripe_customer_id,
                subscription=stripe_subscription_id,
                subscription_items=[
                    {
                        "id": current_item_id,
                        "price": new_price_id,
                    }
                ],
                subscription_proration_behavior="always_invoice",
                subscription_proration_date=proration_date,
            )

        # Parse preview to extract proration details
        credit_amount = 0
        new_plan_amount = 0

        # Log line items for debugging
        lines_data = preview.get("lines", {}).get("data", [])
        logger.info(f"Invoice preview has {len(lines_data)} line items")
        for i, line in enumerate(lines_data):
            logger.info(
                f"Line {i}: amount={line.get('amount')}, proration={line.get('proration')}, "
                f"type={line.get('type')}, description={line.get('description', '')[:50]}"
            )

        for line in lines_data:
            amount = line.get("amount", 0)

            if amount < 0:
                # Negative amount = credit for unused time on old plan
                credit_amount += abs(amount)
            else:
                # Positive amount = new plan charge
                new_plan_amount += amount

        amount_due = preview.get("amount_due", 0)
        currency = preview.get("currency", "usd")

        # Format amount for display
        if currency == "usd":
            amount_due_formatted = f"${amount_due / 100:.2f}"
        else:
            amount_due_formatted = f"{amount_due / 100:.2f} {currency.upper()}"

        # Get current period end from subscription item (not subscription object)
        subscription_item = subscription["items"]["data"][0]
        current_period_end = subscription_item.get("current_period_end")
        period_end_str = (
            datetime.fromtimestamp(current_period_end, tz=timezone.utc).strftime("%Y-%m-%d")
            if current_period_end
            else None
        )

        logger.info(
            f"Generated upgrade preview for user {user_id}: "
            f"{current_tier} -> {tier}, amount_due: {amount_due}, "
            f"credit_calculated: {credit_amount}, new_plan_calculated: {new_plan_amount}"
        )

        return success_response(
            {
                "preview": {
                    "current_tier": current_tier,
                    "new_tier": tier,
                    "credit_amount_cents": credit_amount,
                    "new_plan_prorated_cents": new_plan_amount,
                    "amount_due_cents": amount_due,
                    "amount_due_formatted": amount_due_formatted,
                    "currency": currency,
                    "current_period_end": period_end_str,
                    "proration_date": proration_date,
                    "cancellation_will_clear": cancel_at_period_end,
                }
            },
            origin=origin,
        )

    except stripe.StripeError as e:
        logger.error(f"Stripe error creating upgrade preview: {e}")
        return error_response(500, "stripe_error", "Failed to create upgrade preview", origin=origin)
    except Exception as e:
        logger.error(f"Error creating upgrade preview: {e}")
        return error_response(500, "internal_error", "An error occurred", origin=origin)
