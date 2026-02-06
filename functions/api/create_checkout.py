"""
Create Checkout Session Endpoint - POST /checkout/create

Creates a Stripe Checkout session for subscription upgrades.
Requires session authentication (logged-in user).
"""

import json
import logging
import os
from http.cookies import SimpleCookie

import stripe
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
BASE_URL = os.environ.get("BASE_URL", "https://pkgwatch.dev")

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
    Lambda handler for POST /checkout/create.

    Request body:
    {
        "tier": "starter" | "pro" | "business"
    }

    Returns:
    {
        "checkout_url": "https://checkout.stripe.com/..."
    }
    """
    origin = _get_origin(event)
    headers = event.get("headers", {}) or {}

    # Get Stripe API key
    stripe_api_key = get_stripe_api_key()
    if not stripe_api_key:
        logger.error("Stripe API key not configured")
        return error_response(
            500, "stripe_not_configured", "Payment system not configured", origin=origin
        )

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
        return error_response(
            401, "unauthorized", "Please log in to upgrade", origin=origin
        )

    # Import here to avoid circular imports at module level
    from api.auth_callback import verify_session_token

    session_data = verify_session_token(session_token)
    if not session_data:
        return error_response(
            401, "session_expired", "Session expired. Please log in again.", origin=origin
        )

    user_id = session_data.get("user_id")
    email = session_data.get("email")

    # Parse request body
    try:
        body = json.loads(event.get("body", "{}") or "{}")
    except json.JSONDecodeError:
        return error_response(
            400, "invalid_json", "Request body must be valid JSON", origin=origin
        )

    tier = body.get("tier", "").lower()

    # Validate tier
    if tier not in TIER_TO_PRICE:
        return error_response(
            400,
            "invalid_tier",
            "Invalid tier. Choose: starter, pro, or business",
            origin=origin,
        )

    # Get user's current tier and existing Stripe customer ID FIRST
    # (so existing subscribers get directed to upgrade flow before price check)
    table = get_dynamodb().Table(API_KEYS_TABLE)
    response = table.query(
        IndexName="email-index",
        KeyConditionExpression=Key("email").eq(email),
    )
    items = response.get("Items", [])

    existing_customer_id = None
    existing_subscription_id = None
    current_tier = "free"
    for item in items:
        # Skip PENDING records
        if item.get("sk") == "PENDING":
            continue
        if item.get("email_verified"):
            existing_customer_id = item.get("stripe_customer_id")
            existing_subscription_id = item.get("stripe_subscription_id")
            current_tier = item.get("tier", "free")
            break

    # Existing subscribers must use the upgrade flow for proper proration
    if existing_subscription_id:
        return error_response(
            409,
            "upgrade_required",
            "Use /upgrade/preview and /upgrade/confirm for subscription upgrades with proration",
            origin=origin,
        )

    # Now check if price is configured (only matters for new subscriptions)
    price_id = TIER_TO_PRICE[tier]
    if not price_id:
        logger.error(f"Price ID not configured for tier: {tier}")
        return error_response(
            500, "price_not_configured", "Pricing not configured for this tier", origin=origin
        )

    # Prevent downgrade via checkout (should use customer portal instead)
    if TIER_ORDER.get(tier, 0) <= TIER_ORDER.get(current_tier, 0):
        return error_response(
            400,
            "invalid_upgrade",
            f"Cannot checkout for {tier} tier. You're currently on {current_tier}.",
            origin=origin,
        )

    try:
        # Create Stripe Checkout session
        checkout_params = {
            "mode": "subscription",
            "line_items": [{"price": price_id, "quantity": 1}],
            "success_url": f"{BASE_URL}/dashboard?upgraded=true",
            "cancel_url": f"{BASE_URL}/pricing?cancelled=true",
            "client_reference_id": user_id,
            "metadata": {
                "user_id": user_id,
                "tier": tier,
            },
            "subscription_data": {
                "metadata": {
                    "user_id": user_id,
                    "tier": tier,
                },
            },
            "allow_promotion_codes": True,
        }

        # If user already has Stripe customer, reuse it
        if existing_customer_id:
            checkout_params["customer"] = existing_customer_id
        else:
            # Pre-fill email for new customers
            checkout_params["customer_email"] = email

        session = stripe.checkout.Session.create(**checkout_params)

        logger.info(f"Created checkout session for user {user_id}, tier {tier}")

        return success_response({"checkout_url": session.url}, origin=origin)

    except stripe.StripeError as e:
        logger.error(f"Stripe error creating checkout session: {e}")
        return error_response(
            500, "stripe_error", "Failed to create checkout session", origin=origin
        )
    except Exception as e:
        logger.error(f"Error creating checkout session: {e}")
        return error_response(500, "internal_error", "An error occurred", origin=origin)
