"""
Stripe Webhook Endpoint - POST /webhooks/stripe

Handles Stripe webhook events for subscription management.
Uses Stripe signature verification instead of API key auth.
"""

import json
import logging
import os
import time

import boto3
import stripe
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
secretsmanager = boto3.client("secretsmanager")

API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")
STRIPE_WEBHOOK_SECRET_ARN = os.environ.get("STRIPE_WEBHOOK_SECRET_ARN")

# Import shared utilities
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../shared"))
from constants import TIER_LIMITS

# Tier mapping from Stripe price IDs (configured via environment)
# Use `or` to handle empty string env vars (CDK fallback sets "" when not configured)
PRICE_TO_TIER = {
    (os.environ.get("STRIPE_PRICE_STARTER") or "price_starter"): "starter",
    (os.environ.get("STRIPE_PRICE_PRO") or "price_pro"): "pro",
    (os.environ.get("STRIPE_PRICE_BUSINESS") or "price_business"): "business",
}

# Cached Stripe secrets with TTL
_stripe_secrets_cache: tuple[str | None, str | None] = (None, None)
_stripe_secrets_cache_time = 0.0
STRIPE_SECRETS_CACHE_TTL = 300  # 5 minutes


def get_stripe_secrets() -> tuple[str | None, str | None]:
    """Retrieve Stripe API key and webhook secret from Secrets Manager (cached with TTL)."""
    global _stripe_secrets_cache, _stripe_secrets_cache_time

    # Check if cache is still valid
    if _stripe_secrets_cache[0] and (time.time() - _stripe_secrets_cache_time) < STRIPE_SECRETS_CACHE_TTL:
        return _stripe_secrets_cache

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

    _stripe_secrets_cache = (api_key, webhook_secret)
    _stripe_secrets_cache_time = time.time()
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
    stripe_api_key, webhook_secret = get_stripe_secrets()

    if not stripe_api_key or not webhook_secret:
        logger.error("Stripe secrets not configured")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
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
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Missing Stripe signature"}),
        }

    # Verify webhook signature
    try:
        stripe_event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except stripe.SignatureVerificationError as e:
        logger.warning(f"Invalid Stripe signature: {e}")
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Invalid signature"}),
        }
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
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

    except ClientError as e:
        # DynamoDB errors are transient - return 500 so Stripe retries
        logger.error(f"Transient error handling {event_type}: {e}")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "Temporary error, please retry"}),
        }
    except Exception as e:
        logger.error(f"Error handling {event_type}: {e}")
        # Non-transient errors - return 200 to prevent Stripe retries
        # Don't expose internal error details in response
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"received": True, "processed": False}),
        }

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"received": True}),
    }


def _customer_exists(customer_id: str) -> bool:
    """Check if a Stripe customer already exists in our database."""
    if not customer_id:
        return False

    table = dynamodb.Table(API_KEYS_TABLE)
    try:
        response = table.query(
            IndexName="stripe-customer-index",
            KeyConditionExpression=Key("stripe_customer_id").eq(customer_id),
            Limit=1,
        )
        return len(response.get("Items", [])) > 0
    except Exception as e:
        logger.error(f"Error checking customer existence: {e}")
        return False


def _handle_checkout_completed(session: dict):
    """Handle successful checkout - upgrade user to paid tier."""
    customer_email = session.get("customer_email")
    customer_id = session.get("customer")
    subscription_id = session.get("subscription")

    logger.info(f"Checkout completed for {customer_email}")

    if not customer_email:
        logger.warning("No customer email in checkout session")
        return

    # Handle one-time payments (no subscription)
    if not subscription_id:
        logger.info(f"One-time payment for {customer_email} (no subscription)")
        # For one-time payments, just update customer ID without tier change
        _update_user_tier(customer_email, "starter", customer_id, None)
        return

    # Get subscription details to determine tier
    import stripe
    subscription = stripe.Subscription.retrieve(subscription_id)
    price_id = subscription["items"]["data"][0]["price"]["id"]
    tier = PRICE_TO_TIER.get(price_id, "starter")

    # Check if this is an upgrade (existing customer) vs new signup
    is_upgrade = customer_id and _customer_exists(customer_id)

    # Update user tier in DynamoDB
    # Reset usage on upgrade to give users a fresh start with new limit
    _update_user_tier(customer_email, tier, customer_id, subscription_id, reset_usage=is_upgrade)


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
    """Handle failed payment - downgrade after 3 failures."""
    customer_id = invoice.get("customer")
    customer_email = invoice.get("customer_email")
    attempt_count = invoice.get("attempt_count", 1)

    logger.warning(f"Payment failed for {customer_email or customer_id} (attempt {attempt_count})")

    if not customer_id:
        logger.warning("No customer ID in failed payment invoice")
        return

    table = dynamodb.Table(API_KEYS_TABLE)

    # Query by stripe_customer_id using GSI
    response = table.query(
        IndexName="stripe-customer-index",
        KeyConditionExpression=Key("stripe_customer_id").eq(customer_id),
    )

    items = response.get("Items", [])
    if not items:
        logger.warning(f"No user found for Stripe customer {customer_id}")
        return

    for item in items:
        if attempt_count >= 3:
            # Downgrade to free after 3 failed attempts
            table.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression="SET tier = :tier, payment_failures = :fails, tier_updated_at = :now",
                ExpressionAttributeValues={
                    ":tier": "free",
                    ":fails": attempt_count,
                    ":now": datetime.now(timezone.utc).isoformat(),
                },
            )
            logger.warning(f"Downgraded {item['pk']} to free after {attempt_count} failed payments")
        else:
            # Just track the failure count
            table.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression="SET payment_failures = :fails",
                ExpressionAttributeValues={":fails": attempt_count},
            )
            logger.info(f"Recorded payment failure {attempt_count} for {item['pk']}")


def _update_user_tier(
    email: str,
    tier: str,
    customer_id: str = None,
    subscription_id: str = None,
    reset_usage: bool = False,
):
    """Update user tier in DynamoDB after successful payment.

    Uses email-index GSI to find user by email address.

    Args:
        email: User email
        tier: New tier name
        customer_id: Stripe customer ID
        subscription_id: Stripe subscription ID
        reset_usage: If True, reset requests_this_month to 0 (for upgrades)
    """
    if not email:
        logger.error("Cannot update tier: no email provided")
        return

    table = dynamodb.Table(API_KEYS_TABLE)

    # Query by email using GSI
    response = table.query(
        IndexName="email-index",
        KeyConditionExpression=Key("email").eq(email),
    )

    items = response.get("Items", [])
    if not items:
        logger.error(f"No user found for email {email} during tier update")
        return

    new_limit = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

    # Update all API keys for this user (skip PENDING signups)
    updated_count = 0
    for item in items:
        # Skip PENDING records - they will be deleted upon email verification
        # and a new API key record will be created
        if item.get("sk") == "PENDING":
            logger.debug(f"Skipping PENDING record for {email}")
            continue

        update_expr = "SET tier = :tier, tier_updated_at = :now, monthly_limit = :limit"
        expr_values = {
            ":tier": tier,
            ":now": datetime.now(timezone.utc).isoformat(),
            ":limit": new_limit,
        }

        # Also set Stripe IDs if provided
        if customer_id:
            update_expr += ", stripe_customer_id = :cust"
            expr_values[":cust"] = customer_id
        if subscription_id:
            update_expr += ", stripe_subscription_id = :sub"
            expr_values[":sub"] = subscription_id

        # Reset payment failures on successful tier update
        update_expr += ", payment_failures = :zero"
        expr_values[":zero"] = 0

        # Reset usage on upgrade to give fresh start with new limit
        if reset_usage:
            update_expr += ", requests_this_month = :zero_usage"
            expr_values[":zero_usage"] = 0
            logger.info(f"Resetting usage for {item['pk']} on tier upgrade to {tier}")

        table.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values,
        )
        updated_count += 1

    if updated_count == 0:
        logger.warning(f"No verified API keys found for {email} - user may not have completed signup")
    else:
        logger.info(f"Updated {updated_count} API keys for {email} to tier {tier}")


def _update_user_tier_by_customer_id(customer_id: str, tier: str):
    """Update tier by Stripe customer ID (for upgrades/downgrades).

    Uses stripe-customer-index GSI to find user by Stripe customer ID.
    """
    if not customer_id:
        logger.error("Cannot update tier: no customer_id provided")
        return

    table = dynamodb.Table(API_KEYS_TABLE)

    # Query GSI by stripe_customer_id
    response = table.query(
        IndexName="stripe-customer-index",
        KeyConditionExpression=Key("stripe_customer_id").eq(customer_id),
    )

    items = response.get("Items", [])
    if not items:
        logger.warning(f"No user found for Stripe customer {customer_id}")
        return

    new_limit = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

    for item in items:
        current_usage = item.get("requests_this_month", 0)

        # Warn if downgrading and user is over new limit
        if current_usage > new_limit:
            logger.warning(
                f"User {item['pk']} downgraded to {tier} but has {current_usage} "
                f"requests (limit: {new_limit}). User is over limit until reset."
            )

        table.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET tier = :tier, tier_updated_at = :now, payment_failures = :zero",
            ExpressionAttributeValues={
                ":tier": tier,
                ":now": datetime.now(timezone.utc).isoformat(),
                ":zero": 0,
            },
        )

    logger.info(f"Updated {len(items)} API keys for customer {customer_id} to tier {tier}")
