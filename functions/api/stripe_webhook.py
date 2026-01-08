"""
Stripe Webhook Endpoint - POST /webhooks/stripe

Handles Stripe webhook events for subscription management.
Uses Stripe signature verification instead of API key auth.
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
secretsmanager = boto3.client("secretsmanager")

API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "dephealth-api-keys")
STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")
STRIPE_WEBHOOK_SECRET_ARN = os.environ.get("STRIPE_WEBHOOK_SECRET_ARN")

# Tier mapping from Stripe price IDs
# These should match your Stripe product configuration
PRICE_TO_TIER = {
    "price_starter": "starter",
    "price_pro": "pro",
    "price_business": "business",
}


def get_stripe_secrets() -> tuple[str, str]:
    """Retrieve Stripe API key and webhook secret from Secrets Manager."""
    api_key = None
    webhook_secret = None

    if STRIPE_SECRET_ARN:
        try:
            response = secretsmanager.get_secret_value(SecretId=STRIPE_SECRET_ARN)
            secret_value = response.get("SecretString", "")
            try:
                secret_json = json.loads(secret_value)
                api_key = secret_json.get("key") or secret_value
            except json.JSONDecodeError:
                api_key = secret_value
        except ClientError as e:
            logger.error(f"Failed to retrieve Stripe API key: {e}")

    if STRIPE_WEBHOOK_SECRET_ARN:
        try:
            response = secretsmanager.get_secret_value(SecretId=STRIPE_WEBHOOK_SECRET_ARN)
            secret_value = response.get("SecretString", "")
            try:
                secret_json = json.loads(secret_value)
                webhook_secret = secret_json.get("secret") or secret_value
            except json.JSONDecodeError:
                webhook_secret = secret_value
        except ClientError as e:
            logger.error(f"Failed to retrieve Stripe webhook secret: {e}")

    return api_key, webhook_secret


def handler(event, context):
    """
    Lambda handler for Stripe webhooks.

    Handles:
    - checkout.session.completed: Upgrade user tier
    - customer.subscription.updated: Tier changes
    - customer.subscription.deleted: Downgrade to free
    - invoice.payment_failed: Handle failed payments
    """
    import stripe

    stripe_api_key, webhook_secret = get_stripe_secrets()

    if not stripe_api_key or not webhook_secret:
        logger.error("Stripe secrets not configured")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Stripe not configured"}),
        }

    stripe.api_key = stripe_api_key

    # Get payload and signature
    payload = event.get("body", "")
    headers = event.get("headers", {})
    sig_header = headers.get("stripe-signature") or headers.get("Stripe-Signature")

    if not sig_header:
        logger.warning("Missing Stripe signature")
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Missing Stripe signature"}),
        }

    # Verify webhook signature
    try:
        stripe_event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except stripe.error.SignatureVerificationError as e:
        logger.warning(f"Invalid Stripe signature: {e}")
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Invalid signature"}),
        }
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Invalid webhook payload"}),
        }

    # Handle event types
    event_type = stripe_event["type"]
    data = stripe_event["data"]["object"]

    logger.info(f"Processing Stripe event: {event_type}")

    try:
        if event_type == "checkout.session.completed":
            _handle_checkout_completed(data)

        elif event_type == "customer.subscription.updated":
            _handle_subscription_updated(data)

        elif event_type == "customer.subscription.deleted":
            _handle_subscription_deleted(data)

        elif event_type == "invoice.payment_failed":
            _handle_payment_failed(data)

        else:
            logger.info(f"Unhandled event type: {event_type}")

    except Exception as e:
        logger.error(f"Error handling {event_type}: {e}")
        # Return 200 anyway to prevent Stripe retries for handled errors
        # Don't expose internal error details in response
        return {
            "statusCode": 200,
            "body": json.dumps({"received": True, "processed": False}),
        }

    return {
        "statusCode": 200,
        "body": json.dumps({"received": True}),
    }


def _handle_checkout_completed(session: dict):
    """Handle successful checkout - upgrade user to paid tier."""
    customer_email = session.get("customer_email")
    customer_id = session.get("customer")
    subscription_id = session.get("subscription")

    logger.info(f"Checkout completed for {customer_email}")

    if not customer_email:
        logger.warning("No customer email in checkout session")
        return

    # Get subscription details to determine tier
    import stripe
    subscription = stripe.Subscription.retrieve(subscription_id)
    price_id = subscription["items"]["data"][0]["price"]["id"]
    tier = PRICE_TO_TIER.get(price_id, "starter")

    # Update user tier in DynamoDB
    _update_user_tier(customer_email, tier, customer_id, subscription_id)


def _handle_subscription_updated(subscription: dict):
    """Handle subscription changes (upgrades/downgrades)."""
    customer_id = subscription.get("customer")
    status = subscription.get("status")

    logger.info(f"Subscription updated for customer {customer_id}: {status}")

    if status != "active":
        return

    # Get new tier from subscription items
    items = subscription.get("items", {}).get("data", [])
    if items:
        price_id = items[0].get("price", {}).get("id")
        tier = PRICE_TO_TIER.get(price_id, "starter")

        # Find user by customer_id and update tier
        _update_user_tier_by_customer_id(customer_id, tier)


def _handle_subscription_deleted(subscription: dict):
    """Handle subscription cancellation - downgrade to free."""
    customer_id = subscription.get("customer")

    logger.info(f"Subscription deleted for customer {customer_id}")

    # Downgrade to free tier
    _update_user_tier_by_customer_id(customer_id, "free")


def _handle_payment_failed(invoice: dict):
    """Handle failed payment - could downgrade or notify."""
    customer_id = invoice.get("customer")
    customer_email = invoice.get("customer_email")

    logger.warning(f"Payment failed for {customer_email or customer_id}")

    # For MVP, just log it. In production, could:
    # - Send notification email
    # - Downgrade after X failed attempts
    # - Add grace period


def _update_user_tier(
    email: str,
    tier: str,
    customer_id: str = None,
    subscription_id: str = None,
):
    """Update user tier by email."""
    table = dynamodb.Table(API_KEYS_TABLE)

    # Query by email (would need a GSI for this in production)
    # For MVP, we'll store email as part of user_id
    # Format: pk = user_<email_hash>

    # This is a simplified implementation
    # In production, you'd have a users table with email->user_id mapping
    logger.info(f"Upgrading {email} to {tier}")

    # For now, log the upgrade - would need users table for proper implementation


def _update_user_tier_by_customer_id(customer_id: str, tier: str):
    """Update user tier by Stripe customer ID."""
    table = dynamodb.Table(API_KEYS_TABLE)

    # Query by stripe_customer_id (would need GSI)
    # For MVP, this is a placeholder

    logger.info(f"Updating customer {customer_id} to {tier}")
