"""
Create Billing Portal Session Endpoint - POST /billing-portal/create

Creates a Stripe Billing Portal session for subscription management.
Requires session authentication (logged-in user with active subscription).
"""

import json
import logging
import os
from http.cookies import SimpleCookie

import boto3
import stripe
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
BASE_URL = os.environ.get("BASE_URL", "https://pkgwatch.dev")

# Import shared utilities
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../shared"))
from response_utils import error_response, success_response
from billing_utils import get_stripe_api_key

# Lazy initialization
_dynamodb = None


def _get_dynamodb():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb


def _get_origin(event: dict) -> str | None:
    """Extract Origin header from request."""
    headers = event.get("headers", {}) or {}
    return headers.get("origin") or headers.get("Origin")


def handler(event, context):
    """
    Lambda handler for POST /billing-portal/create.

    No request body required - uses session to identify user.

    Returns:
    {
        "portal_url": "https://billing.stripe.com/..."
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
            401, "unauthorized", "Please log in to manage subscription", origin=origin
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

    # Get user's Stripe customer ID from DynamoDB
    table = _get_dynamodb().Table(API_KEYS_TABLE)
    response = table.query(
        IndexName="email-index",
        KeyConditionExpression=Key("email").eq(email),
    )
    items = response.get("Items", [])

    stripe_customer_id = None
    for item in items:
        # Skip PENDING records
        if item.get("sk") == "PENDING":
            continue
        if item.get("email_verified"):
            stripe_customer_id = item.get("stripe_customer_id")
            break

    # Check if user has a Stripe customer ID (has subscribed before)
    if not stripe_customer_id:
        return error_response(
            400,
            "no_subscription",
            "No active subscription found. You are on the free tier.",
            origin=origin,
        )

    try:
        # Create Stripe Billing Portal session
        # Include portal_return=1 param so dashboard knows to refresh subscription data
        portal_session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=f"{BASE_URL}/dashboard?portal_return=1",
        )

        logger.info(f"Created billing portal session for user {user_id}")

        return success_response({"portal_url": portal_session.url}, origin=origin)

    except stripe.StripeError as e:
        logger.error(f"Stripe error creating billing portal session: {e}")
        return error_response(
            500, "stripe_error", "Failed to create billing portal session", origin=origin
        )
    except Exception as e:
        logger.error(f"Error creating billing portal session: {e}")
        return error_response(500, "internal_error", "An error occurred", origin=origin)
