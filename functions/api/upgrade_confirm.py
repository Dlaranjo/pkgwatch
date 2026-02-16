"""
Upgrade Confirm Endpoint - POST /upgrade/confirm

Executes a prorated subscription upgrade.
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
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")

# Import shared utilities
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../shared"))
from billing_utils import get_stripe_api_key
from constants import TIER_LIMITS, TIER_ORDER
from response_utils import error_response, success_response

from shared.aws_clients import get_dynamodb

# Price ID to tier mapping (configured via environment)
TIER_TO_PRICE = {
    "starter": os.environ.get("STRIPE_PRICE_STARTER") or None,
    "pro": os.environ.get("STRIPE_PRICE_PRO") or None,
    "business": os.environ.get("STRIPE_PRICE_BUSINESS") or None,
}

# Maximum age for proration_date (5 minutes)
PRORATION_DATE_MAX_AGE = 300


def _get_origin(event: dict) -> str | None:
    """Extract Origin header from request."""
    headers = event.get("headers", {}) or {}
    return headers.get("origin") or headers.get("Origin")


def handler(event, context):
    """
    Lambda handler for POST /upgrade/confirm.

    Request body:
    {
        "tier": "pro" | "business",
        "proration_date": 1736812800
    }

    Returns:
    {
        "success": true,
        "new_tier": "pro",
        "amount_charged_cents": 4400,
        "invoice_id": "in_xxx"
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
    proration_date = body.get("proration_date")

    # Validate tier
    if tier not in ["pro", "business"]:
        return error_response(
            400,
            "invalid_tier",
            "Invalid tier. Choose: pro or business",
            origin=origin,
        )

    # Validate proration_date is provided
    if not proration_date or not isinstance(proration_date, int):
        return error_response(
            400,
            "invalid_proration_date",
            "proration_date is required and must be an integer",
            origin=origin,
        )

    # Validate proration date isn't in the future (security check)
    now = int(time.time())
    if proration_date > now:
        return error_response(
            400,
            "invalid_proration_date",
            "Invalid proration date.",
            origin=origin,
        )

    # Validate proration date isn't stale (5 minutes max)
    if proration_date < now - PRORATION_DATE_MAX_AGE:
        return error_response(
            400,
            "proration_date_expired",
            "Preview expired. Please get a new preview.",
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

    stripe_subscription_id = None
    current_tier = "free"
    user_items = []

    for item in items:
        # Skip PENDING records
        if item.get("sk") == "PENDING":
            continue
        if item.get("email_verified"):
            stripe_subscription_id = item.get("stripe_subscription_id")
            current_tier = item.get("tier", "free")
            user_items.append(item)

    # Validate user has an active subscription
    if not stripe_subscription_id:
        return error_response(
            400,
            "no_active_subscription",
            "No active subscription found. Use checkout for new subscriptions.",
            origin=origin,
        )

    # Validate it's an upgrade
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
        # Fetch subscription from Stripe to validate and get item ID
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

        # Execute the upgrade with proration
        updated_subscription = stripe.Subscription.modify(
            stripe_subscription_id,
            cancel_at_period_end=False,  # Clear any pending cancellation
            idempotency_key=f"upgrade-{user_id}-{tier}-{proration_date}",
            items=[
                {
                    "id": current_item_id,
                    "price": new_price_id,
                }
            ],
            proration_behavior="always_invoice",
            proration_date=proration_date,
            payment_behavior="error_if_incomplete",
        )

        # Get the latest invoice ID
        latest_invoice = updated_subscription.get("latest_invoice")
        invoice_id = (
            latest_invoice if isinstance(latest_invoice, str) else latest_invoice.get("id") if latest_invoice else None
        )

        # Get amount charged from the invoice
        amount_charged = 0
        if invoice_id:
            try:
                invoice = stripe.Invoice.retrieve(invoice_id)
                amount_charged = invoice.get("amount_paid", 0)
            except stripe.StripeError:
                # Non-critical - just log and continue
                logger.warning(f"Could not retrieve invoice {invoice_id}")

        logger.info(
            f"Subscription upgrade successful for user {user_id}: {current_tier} -> {tier}, invoice: {invoice_id}"
        )

        # CRITICAL: Update DynamoDB synchronously (don't rely solely on webhook)
        # This ensures immediate UI consistency; webhook will also update (idempotent)
        from shared.billing_utils import update_billing_state

        update_billing_state(
            user_id=user_id,
            api_key_records=user_items,
            tier=tier,
            cancellation_pending=False,
            cancellation_date=None,
            payment_failures=0,
            table=table,
        )

        return success_response(
            {
                "success": True,
                "new_tier": tier,
                "amount_charged_cents": amount_charged,
                "invoice_id": invoice_id,
            },
            origin=origin,
        )

    except stripe.CardError as e:
        logger.warning(f"Card error during upgrade for user {user_id}: {e}")
        return error_response(402, "payment_failed", e.user_message or str(e), origin=origin)
    except stripe.InvalidRequestError as e:
        logger.error(f"Invalid Stripe request during upgrade: {e}")
        return error_response(400, "invalid_request", "Invalid upgrade request", origin=origin)
    except stripe.APIError as e:
        logger.error(f"Stripe API error during upgrade: {e}")
        return error_response(503, "stripe_unavailable", "Payment system temporarily unavailable", origin=origin)
    except stripe.StripeError as e:
        logger.error(f"Stripe error during upgrade: {e}")
        return error_response(500, "stripe_error", "Failed to process upgrade", origin=origin)
    except Exception as e:
        logger.error(f"Error processing upgrade: {e}")
        return error_response(500, "internal_error", "An error occurred", origin=origin)
