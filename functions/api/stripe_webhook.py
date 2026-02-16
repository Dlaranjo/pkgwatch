"""
Stripe Webhook Endpoint - POST /webhooks/stripe

Handles Stripe webhook events for subscription management.
Uses Stripe signature verification instead of API key auth.
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import boto3
import stripe
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from shared.aws_clients import get_dynamodb, get_secretsmanager, get_sns
from shared.logging_utils import configure_structured_logging, set_request_id
from shared.response_utils import error_response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
BILLING_EVENTS_TABLE = os.environ.get("BILLING_EVENTS_TABLE", "pkgwatch-billing-events")
STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")
STRIPE_WEBHOOK_SECRET_ARN = os.environ.get("STRIPE_WEBHOOK_SECRET_ARN")

# Import shared utilities
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../shared"))
from constants import TIER_LIMITS, TIER_ORDER

from shared.referral_utils import (
    REFERRAL_REWARDS,
    RETENTION_MONTHS,
    add_bonus_with_cap,
    record_referral_event,
    update_referrer_stats,
)

# Payment failure grace period - days to wait before downgrading
GRACE_PERIOD_DAYS = int(os.environ.get("PAYMENT_GRACE_PERIOD_DAYS", "7"))

# SES email for payment failure notifications
ses = boto3.client("ses")
LOGIN_EMAIL_SENDER = os.environ.get("LOGIN_EMAIL_SENDER", "noreply@pkgwatch.dev")

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
    sm = get_secretsmanager()

    if STRIPE_SECRET_ARN:
        try:
            response = sm.get_secret_value(SecretId=STRIPE_SECRET_ARN)
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
            response = sm.get_secret_value(SecretId=STRIPE_WEBHOOK_SECRET_ARN)
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


# ===========================================
# Billing Event Audit Trail
# ===========================================


def _check_and_claim_event(event_id: str, event_type: str) -> bool:
    """Atomically check if event exists and claim it if not.

    Uses conditional write to prevent race conditions - if two Lambda
    invocations try to process the same event simultaneously, only one
    will succeed in claiming it.

    Returns:
        True if successfully claimed (should process)
        False if already exists (duplicate - skip processing)
    """
    table = get_dynamodb().Table(BILLING_EVENTS_TABLE)
    try:
        table.put_item(
            Item={
                "pk": event_id,
                "sk": event_type,
                "status": "processing",
                "processed_at": datetime.now(timezone.utc).isoformat(),
                "ttl": int((datetime.now(timezone.utc) + timedelta(days=90)).timestamp()),
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
        return True  # Successfully claimed
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False  # Already exists - duplicate
        raise


def _release_event_claim(event_id: str, event_type: str):
    """Release event claim so Stripe retries can re-process.

    Called when a transient error occurs after claiming an event.
    This allows the next Stripe retry to successfully claim and process the event.

    Args:
        event_id: Stripe event ID
        event_type: Stripe event type
    """
    try:
        table = get_dynamodb().Table(BILLING_EVENTS_TABLE)
        table.delete_item(Key={"pk": event_id, "sk": event_type})
        logger.info(f"Released event claim for {event_id} to allow retry")
    except Exception as e:
        # Best-effort - log but don't fail the webhook response
        logger.error(f"Failed to release event claim {event_id}: {e}")


def _record_billing_event(event: dict, status: str, error: str = None):
    """Record webhook event for audit trail (best-effort).

    Uses event_id as PK for reliable deduplication (some events lack customer_id).
    Failures are logged but do not affect webhook response.

    Args:
        event: Stripe event object
        status: "processing", "success", or "failed"
        error: Error message if status is "failed"
    """
    try:
        table = get_dynamodb().Table(BILLING_EVENTS_TABLE)
        ttl = int((datetime.now(timezone.utc) + timedelta(days=90)).timestamp())
        customer_id = event.get("data", {}).get("object", {}).get("customer") or "unknown"

        table.put_item(
            Item={
                "pk": event["id"],
                "sk": event["type"],
                "customer_id": customer_id,
                "processed_at": datetime.now(timezone.utc).isoformat(),
                "event_created_at": event.get("created"),  # Stripe's event timestamp
                "livemode": event.get("livemode"),  # Distinguish test vs production
                "status": status,
                "error": error,
                "ttl": ttl,
            }
        )
    except Exception as e:
        # Best-effort - audit recording should not block webhook response
        logger.error(f"Failed to record billing event {event.get('id')}: {e}")


def handler(event, context):
    """
    Lambda handler for Stripe webhooks.

    Handles:
    - checkout.session.completed: Upgrade user tier
    - customer.subscription.updated: Tier changes
    - customer.subscription.deleted: Downgrade to free
    - invoice.payment_failed: Handle failed payments
    """
    configure_structured_logging()
    set_request_id(event)

    stripe_api_key, webhook_secret = get_stripe_secrets()

    if not stripe_api_key or not webhook_secret:
        logger.error("Stripe secrets not configured")
        return error_response(500, "stripe_not_configured", "Stripe not configured")

    stripe.api_key = stripe_api_key

    # Get payload and signature
    payload = event.get("body", "")
    headers = event.get("headers", {})
    sig_header = headers.get("stripe-signature") or headers.get("Stripe-Signature")

    if not sig_header:
        logger.warning("Missing Stripe signature")
        return error_response(400, "missing_signature", "Missing Stripe signature")

    # Verify webhook signature
    try:
        stripe_event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except stripe.SignatureVerificationError as e:
        logger.warning(f"Invalid Stripe signature: {e}")
        return error_response(400, "invalid_signature", "Invalid signature")
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return error_response(400, "invalid_webhook_payload", "Invalid webhook payload")

    # Handle event types
    event_type = stripe_event["type"]
    data = stripe_event["data"]["object"]

    logger.info(f"Processing Stripe event: {event_type} (id={stripe_event['id']})")

    # Check for duplicate event and atomically claim it
    if not _check_and_claim_event(stripe_event["id"], event_type):
        logger.info(f"Skipping duplicate event {stripe_event['id']}")
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"received": True, "duplicate": True}),
        }

    try:
        if event_type == "checkout.session.completed":
            _handle_checkout_completed(data)

        elif event_type == "customer.subscription.updated":
            _handle_subscription_updated(data)

        elif event_type == "customer.subscription.deleted":
            _handle_subscription_deleted(data)

        elif event_type == "customer.subscription.created":
            _handle_subscription_created(data)

        elif event_type == "invoice.payment_failed":
            _handle_payment_failed(data)

        elif event_type == "invoice.paid":
            _handle_invoice_paid(data)

        elif event_type == "charge.refunded":
            _handle_charge_refunded(data)

        elif event_type == "charge.dispute.created":
            _handle_dispute_created(data)

        else:
            logger.info(f"Unhandled event type: {event_type}")

        # Record successful processing
        _record_billing_event(stripe_event, "success")

    except ClientError as e:
        # DynamoDB errors are transient - release claim so Stripe retry can re-process
        _release_event_claim(stripe_event["id"], event_type)
        _record_billing_event(stripe_event, "failed", str(e))
        logger.error(f"Transient error handling {event_type}: {e}")
        return error_response(500, "temporary_error", "Temporary error, please retry")
    except (stripe.error.APIConnectionError, stripe.error.RateLimitError, stripe.error.APIError) as e:
        # Transient Stripe errors - release claim so retry can re-process
        _release_event_claim(stripe_event["id"], event_type)
        _record_billing_event(stripe_event, "failed", str(e))
        logger.error(f"Transient Stripe error handling {event_type}: {e}")
        return error_response(500, "stripe_error", "Stripe error, please retry")
    except stripe.error.StripeError as e:
        # Permanent Stripe errors (InvalidRequestError, AuthenticationError, etc.)
        _record_billing_event(stripe_event, "failed", str(e))
        logger.error(f"Permanent Stripe error handling {event_type}: {e}")
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(
                {
                    "error": {"code": "stripe_validation_error", "message": "Stripe validation error"},
                    "received": True,
                    "processed": False,
                }
            ),
        }
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        # Data validation errors are permanent - return 200, don't retry
        # Don't leak internal field names in response
        _record_billing_event(stripe_event, "failed", str(e))
        logger.error(f"Permanent error handling {event_type}: {e}")
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(
                {
                    "error": {"code": "invalid_event_data", "message": "Invalid event data"},
                    "received": True,
                    "processed": False,
                }
            ),
        }
    except Exception as e:
        # Unknown errors - release claim and return 500 to be safe
        _release_event_claim(stripe_event["id"], event_type)
        _record_billing_event(stripe_event, "failed", str(e))
        logger.error(f"Unexpected error handling {event_type}: {e}", exc_info=True)
        return error_response(500, "processing_failed", "Processing failed")

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"received": True}),
    }


def _process_paid_referral_reward(user_id: str, referred_email: str):
    """
    Award paid conversion bonus to referrer.

    Called when a referred user upgrades to a paid tier.

    Args:
        user_id: The referred user's ID
        referred_email: Email for logging (masked)
    """
    table = get_dynamodb().Table(API_KEYS_TABLE)

    try:
        # Get user's referral info
        response = table.get_item(
            Key={"pk": user_id, "sk": "USER_META"},
            ProjectionExpression="referred_by",
        )

        meta = response.get("Item", {})
        referrer_id = meta.get("referred_by")

        if not referrer_id:
            # User was not referred
            return

        # Check if we already processed a "paid" event for this user
        # (idempotency - in case webhook fires multiple times)
        events_table = get_dynamodb().Table(BILLING_EVENTS_TABLE)
        existing = events_table.get_item(
            Key={"pk": f"referral_paid:{referrer_id}:{user_id}", "sk": "paid"},
        )
        if existing.get("Item"):
            logger.info(f"Paid referral reward already processed for {user_id}")
            return

        # Credit referrer with paid conversion bonus
        reward_amount = REFERRAL_REWARDS["paid"]
        actual_reward = add_bonus_with_cap(referrer_id, reward_amount)

        # Calculate retention check date (2 months from now)
        retention_check_date = (datetime.now(timezone.utc) + timedelta(days=30 * RETENTION_MONTHS)).isoformat()

        # Record paid event with retention check
        record_referral_event(
            referrer_id=referrer_id,
            referred_id=user_id,
            event_type="paid",
            referred_email=referred_email,
            reward_amount=actual_reward,
            retention_check_date=retention_check_date,
        )

        # Update referrer stats
        update_referrer_stats(
            referrer_id,
            paid_delta=1,
            rewards_delta=actual_reward,
        )

        # Mark as processed (idempotency record)
        events_table.put_item(
            Item={
                "pk": f"referral_paid:{referrer_id}:{user_id}",
                "sk": "paid",
                "processed_at": datetime.now(timezone.utc).isoformat(),
                "reward_amount": actual_reward,
                "ttl": int((datetime.now(timezone.utc) + timedelta(days=365)).timestamp()),
            }
        )

        logger.info(
            f"Paid referral reward: credited {referrer_id} with {actual_reward} for referred user {user_id} upgrade"
        )

    except Exception as e:
        logger.error(f"Error processing paid referral reward for {user_id}: {e}")
        # Don't re-raise - the tier upgrade should still succeed


def _handle_checkout_completed(session: dict):
    """Handle successful checkout - upgrade user to paid tier."""
    customer_email = session.get("customer_email")
    customer_id = session.get("customer")
    subscription_id = session.get("subscription")

    logger.info(f"Checkout completed for {customer_email or customer_id}")

    # Handle one-time payments (no subscription)
    if not subscription_id:
        if customer_email:
            logger.info(f"One-time payment for {customer_email} (no subscription)")
            _update_user_tier(customer_email, "starter", customer_id, None)
        elif customer_id:
            logger.info(f"One-time payment for customer {customer_id} (no subscription)")
            _update_user_tier_by_customer_id(customer_id, "starter")
        else:
            logger.warning("No customer email or customer ID in checkout session")
        return

    # Get subscription details to determine tier and billing cycle
    import stripe

    subscription = stripe.Subscription.retrieve(subscription_id)
    subscription_item = subscription["items"]["data"][0]
    price_id = subscription_item["price"]["id"]
    tier = PRICE_TO_TIER.get(price_id, "starter")

    # Extract billing cycle fields for per-user reset tracking
    # Note: These are on the subscription item, not the subscription itself
    current_period_start = subscription_item.get("current_period_start")
    current_period_end = subscription_item.get("current_period_end")

    logger.info(f"Subscription tier from price {price_id}: {tier}, period={current_period_start}-{current_period_end}")

    # Update user tier in DynamoDB
    # For customers with email, use email lookup
    # For customers without email, use customer_id lookup
    if customer_email:
        _update_user_tier(
            customer_email,
            tier,
            customer_id,
            subscription_id,
            current_period_start=current_period_start,
            current_period_end=current_period_end,
        )
    elif customer_id:
        # Existing customer upgrading - lookup by customer ID
        logger.info(f"Upgrading existing customer {customer_id} to {tier}")
        _update_user_tier_by_customer_id(
            customer_id,
            tier,
            current_period_start=current_period_start,
            current_period_end=current_period_end,
            subscription_id=subscription_id,
        )
    else:
        logger.warning("No customer email or customer ID in checkout session")
        return

    # Process referral reward if this user was referred
    # Need to find user_id from email or customer_id
    user_id = None
    if customer_email:
        user_id = _get_user_id_by_email(customer_email)
    elif customer_id:
        user_id = _get_user_id_by_customer_id(customer_id)

    if user_id:
        _process_paid_referral_reward(user_id, customer_email or "")


def _get_user_id_by_email(email: str) -> str | None:
    """Look up user_id by email using GSI."""
    table = get_dynamodb().Table(API_KEYS_TABLE)
    try:
        response = table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(email),
            Limit=1,
        )
        items = response.get("Items", [])
        for item in items:
            if item.get("sk") != "PENDING":
                return item.get("pk")
    except Exception as e:
        logger.error(f"Error looking up user by email: {e}")
    return None


def _get_user_id_by_customer_id(customer_id: str) -> str | None:
    """Look up user_id by Stripe customer ID using GSI."""
    table = get_dynamodb().Table(API_KEYS_TABLE)
    try:
        response = table.query(
            IndexName="stripe-customer-index",
            KeyConditionExpression=Key("stripe_customer_id").eq(customer_id),
            Limit=1,
        )
        items = response.get("Items", [])
        if items:
            return items[0].get("pk")
    except Exception as e:
        logger.error(f"Error looking up user by customer ID: {e}")
    return None


def _handle_subscription_updated(subscription: dict):
    """Handle subscription changes (upgrades/downgrades) and cancellation pending state."""
    customer_id = subscription.get("customer")
    status = subscription.get("status")
    cancel_at_period_end = subscription.get("cancel_at_period_end", False)

    # Handle both active and trialing subscriptions
    if status not in ["active", "trialing"]:
        return

    # Get tier and billing cycle from subscription items
    # Note: current_period_start/end are on the item, not the subscription
    items = subscription.get("items", {}).get("data", [])
    tier = None
    current_period_start = None
    current_period_end = None
    if items:
        item = items[0]
        price_id = item.get("price", {}).get("id")
        tier = PRICE_TO_TIER.get(price_id, "starter")
        current_period_start = item.get("current_period_start")
        current_period_end = item.get("current_period_end")

    logger.info(
        f"Subscription updated for customer {customer_id}: status={status}, "
        f"cancel_at_period_end={cancel_at_period_end}, period={current_period_start}-{current_period_end}"
    )

    # Update user with tier, cancellation state, and billing cycle
    _update_user_subscription_state(
        customer_id=customer_id,
        tier=tier,
        cancellation_pending=cancel_at_period_end,
        cancellation_date=current_period_end if cancel_at_period_end else None,
        current_period_start=current_period_start,
        current_period_end=current_period_end,
    )


def _handle_subscription_deleted(subscription: dict):
    """Handle subscription cancellation - downgrade to free and clear cancellation state.

    This event fires when a subscription is actually deleted, which happens:
    - At the end of the billing period if cancel_at_period_end was true
    - Immediately if the subscription was cancelled without cancel_at_period_end

    We trust Stripe as source of truth and always downgrade when this fires.
    """
    customer_id = subscription.get("customer")
    canceled_at = subscription.get("canceled_at")
    ended_at = subscription.get("ended_at")
    current_period_end = subscription.get("current_period_end")

    logger.info(
        f"Subscription deleted for customer {customer_id}: "
        f"canceled_at={canceled_at}, ended_at={ended_at}, period_end={current_period_end}"
    )

    # Safety check: Log warning if period end is in the future
    # This could indicate out-of-order webhook delivery or immediate cancellation
    now = int(datetime.now(timezone.utc).timestamp())
    if current_period_end and current_period_end > now:
        logger.warning(
            f"Subscription deleted but period_end ({current_period_end}) is in future "
            f"(now={now}). This may be an immediate cancellation or out-of-order webhook. "
            f"Proceeding with downgrade per Stripe state."
        )

    # Downgrade to free tier and clear cancellation pending state
    # Stripe is the source of truth - if it says subscription is deleted, we downgrade
    _update_user_subscription_state(
        customer_id=customer_id,
        tier="free",
        cancellation_pending=False,
        cancellation_date=None,
        remove_attributes=["stripe_subscription_id"],
    )


def _handle_subscription_created(subscription: dict):
    """Handle new subscription creation - set user tier.

    Note: For subscriptions via Checkout, checkout.session.completed also fires.
    This handler covers subscriptions created via API or Stripe dashboard.
    Both handlers are idempotent - safe to run twice.
    """
    customer_id = subscription.get("customer")
    status = subscription.get("status")

    logger.info(f"Subscription created for customer {customer_id}: status={status}")

    # Only process active/trialing (skip incomplete, past_due, canceled)
    if status not in ["active", "trialing"]:
        logger.info(f"Skipping subscription.created with status={status}")
        return

    if not customer_id:
        logger.warning("No customer ID in subscription.created event")
        return

    # Get tier and billing cycle from subscription items
    # Note: current_period_start/end are on the item, not the subscription
    items = subscription.get("items", {}).get("data", [])
    if not items:
        logger.warning(f"No items in subscription for customer {customer_id}")
        return

    item = items[0]
    price_id = item.get("price", {}).get("id")
    tier = PRICE_TO_TIER.get(price_id, "starter")
    current_period_start = item.get("current_period_start")
    current_period_end = item.get("current_period_end")

    logger.info(f"Setting tier {tier} for customer {customer_id} from price {price_id}")

    # Use _update_user_subscription_state for consistency with subscription_updated
    _update_user_subscription_state(
        customer_id=customer_id,
        tier=tier,
        cancellation_pending=False,
        cancellation_date=None,
        current_period_start=current_period_start,
        current_period_end=current_period_end,
    )


def _handle_payment_failed(invoice: dict):
    """Handle failed payment with grace period before downgrade.

    Grace period workflow:
    1. First failure: Set first_payment_failure_at, start grace period
    2. Subsequent failures within grace period: Update failure count, no downgrade
    3. After grace period expires AND 3+ failures: Downgrade to free tier
    """
    customer_id = invoice.get("customer")
    customer_email = invoice.get("customer_email")
    attempt_count = invoice.get("attempt_count", 1)

    logger.warning(f"Payment failed for {customer_email or customer_id} (attempt {attempt_count})")

    if not customer_id:
        logger.warning("No customer ID in failed payment invoice")
        return

    table = get_dynamodb().Table(API_KEYS_TABLE)

    # Query by stripe_customer_id using GSI
    response = table.query(
        IndexName="stripe-customer-index",
        KeyConditionExpression=Key("stripe_customer_id").eq(customer_id),
    )

    items = response.get("Items", [])
    if not items:
        logger.warning(f"No user found for Stripe customer {customer_id}")
        return

    now = datetime.now(timezone.utc)

    downgraded = False
    for item in items:
        first_failure = item.get("first_payment_failure_at")

        if attempt_count == 1 or not first_failure:
            # First failure - start grace period
            # Use conditional write to prevent race with successful payment
            try:
                table.update_item(
                    Key={"pk": item["pk"], "sk": item["sk"]},
                    UpdateExpression="SET payment_failures = :fails, first_payment_failure_at = :now",
                    ConditionExpression="attribute_not_exists(first_payment_failure_at)",
                    ExpressionAttributeValues={
                        ":fails": attempt_count,
                        ":now": now.isoformat(),
                    },
                )
                # Send payment failure notification email (best-effort)
                recipient_email = customer_email or item.get("email")
                if recipient_email:
                    _send_payment_failed_email(recipient_email, item.get("tier", "paid"), GRACE_PERIOD_DAYS)
                logger.info(f"Payment failed for {item['pk']}, grace period started ({GRACE_PERIOD_DAYS} days)")
            except ClientError as e:
                if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                    # Grace period already started by concurrent request - just update count
                    table.update_item(
                        Key={"pk": item["pk"], "sk": item["sk"]},
                        UpdateExpression="SET payment_failures = :fails",
                        ExpressionAttributeValues={":fails": attempt_count},
                    )
                else:
                    raise
        elif attempt_count >= 3:
            # Check if grace period expired
            first_failure_dt = datetime.fromisoformat(first_failure.replace("Z", "+00:00"))
            days_since_first = (now - first_failure_dt).days

            if days_since_first >= GRACE_PERIOD_DAYS:
                # Grace period expired - downgrade to free
                # Use conditional write to prevent race with successful payment
                try:
                    table.update_item(
                        Key={"pk": item["pk"], "sk": item["sk"]},
                        UpdateExpression=(
                            "SET tier = :tier, payment_failures = :fails, tier_updated_at = :now, monthly_limit = :limit "
                            "REMOVE first_payment_failure_at"
                        ),
                        ConditionExpression="attribute_exists(first_payment_failure_at)",
                        ExpressionAttributeValues={
                            ":tier": "free",
                            ":fails": attempt_count,
                            ":now": now.isoformat(),
                            ":limit": TIER_LIMITS["free"],
                        },
                    )
                    downgraded = True
                    logger.warning(
                        f"Downgraded {item['pk']} to free after {days_since_first} days "
                        f"grace period and {attempt_count} failed payments"
                    )
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                        # Successful payment cleared grace period - don't downgrade
                        logger.info(f"Skipping downgrade for {item['pk']} - payment succeeded during processing")
                    else:
                        raise
            else:
                # Still in grace period - update failure count only
                days_remaining = GRACE_PERIOD_DAYS - days_since_first
                table.update_item(
                    Key={"pk": item["pk"], "sk": item["sk"]},
                    UpdateExpression="SET payment_failures = :fails",
                    ExpressionAttributeValues={":fails": attempt_count},
                )
                logger.info(f"Payment failed for {item['pk']}, {days_remaining} days left in grace period")
        else:
            # 2nd failure - just track the failure count
            table.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression="SET payment_failures = :fails",
                ExpressionAttributeValues={":fails": attempt_count},
            )
            logger.info(f"Recorded payment failure {attempt_count} for {item['pk']}")

    # Update USER_META tier/limit if downgrade occurred (once, after loop)
    if downgraded and items:
        user_id = items[0]["pk"]
        try:
            table.update_item(
                Key={"pk": user_id, "sk": "USER_META"},
                UpdateExpression="SET tier = :tier, monthly_limit = :limit",
                ConditionExpression="attribute_exists(pk)",
                ExpressionAttributeValues={":tier": "free", ":limit": TIER_LIMITS["free"]},
            )
        except ClientError:
            pass  # USER_META may not exist for legacy accounts


def _send_payment_failed_email(email: str, tier: str, grace_period_days: int):
    """Send payment failure notification email via SES (best-effort)."""
    try:
        ses.send_email(
            Source=LOGIN_EMAIL_SENDER,
            Destination={"ToAddresses": [email]},
            Message={
                "Subject": {
                    "Data": "PkgWatch: Payment failed — action required",
                    "Charset": "UTF-8",
                },
                "Body": {
                    "Html": {
                        "Data": (
                            '<html><body style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;padding:20px;">'
                            '<h1 style="color:#1e293b;">Payment Failed</h1>'
                            f'<p style="color:#475569;font-size:16px;">We were unable to process your payment for your PkgWatch <strong>{tier}</strong> plan.</p>'
                            f'<p style="color:#475569;font-size:16px;">Your subscription is still active for the next <strong>{grace_period_days} days</strong>. '
                            "Please update your payment method to avoid losing access to your plan features.</p>"
                            '<a href="https://pkgwatch.dev/dashboard" '
                            'style="display:inline-block;background:#3b82f6;color:white;padding:12px 24px;text-decoration:none;border-radius:6px;margin:20px 0;">'
                            "Update Payment Method</a>"
                            f'<p style="color:#dc2626;font-size:14px;"><strong>Important:</strong> If payment is not resolved within {grace_period_days} days, '
                            "your account will be downgraded to the free tier.</p>"
                            "</body></html>"
                        ),
                        "Charset": "UTF-8",
                    },
                    "Text": {
                        "Data": (
                            f"Payment Failed\n\n"
                            f"We were unable to process your payment for your PkgWatch {tier} plan.\n\n"
                            f"Your subscription is still active for the next {grace_period_days} days. "
                            f"Please update your payment method to avoid losing access.\n\n"
                            f"Update your payment method at: https://pkgwatch.dev/dashboard\n\n"
                            f"If payment is not resolved within {grace_period_days} days, "
                            f"your account will be downgraded to the free tier."
                        ),
                        "Charset": "UTF-8",
                    },
                },
            },
        )
        logger.info(f"Payment failure notification sent to {email[:3]}***")
    except Exception as e:
        logger.error(f"Failed to send payment failure email: {e}")


def _handle_invoice_paid(invoice: dict):
    """Handle successful invoice payment - reset usage for billing cycle renewal.

    This is the PRIMARY trigger for resetting paid user usage counters.
    Fires when: subscription renews, initial payment succeeds.

    Args:
        invoice: Stripe invoice object
    """
    customer_id = invoice.get("customer")
    subscription_id = invoice.get("subscription")
    billing_reason = invoice.get("billing_reason")

    logger.info(f"Invoice paid for customer {customer_id}, subscription={subscription_id}, reason={billing_reason}")

    if not customer_id:
        logger.warning("No customer ID in paid invoice")
        return

    # Only reset for subscription renewals and initial creation
    # Skip for manual payments, updates, threshold invoices, etc.
    if billing_reason not in ("subscription_cycle", "subscription_create"):
        logger.info(f"Skipping usage reset for billing_reason={billing_reason}")
        return

    # Extract period from invoice lines
    period_start, period_end = _extract_period_from_invoice(invoice)

    if not period_start or not period_end:
        logger.warning(f"Could not extract period from invoice for customer {customer_id}")
        return

    # Reset usage with idempotency check
    _reset_user_usage_for_billing_cycle(
        customer_id=customer_id,
        period_start=period_start,
        period_end=period_end,
    )


def _handle_charge_refunded(charge: dict):
    """Handle refund event - log for audit trail, no tier change needed.

    Refunds are recorded in billing_events for dispute investigation.
    The main handler already records the event, so we just log details here.

    Args:
        charge: Stripe charge object
    """
    customer_id = charge.get("customer")
    amount_refunded = charge.get("amount_refunded", 0)
    refund_reason = charge.get("refund_reason") or "not_specified"

    logger.info(f"Refund processed for customer {customer_id}: ${amount_refunded / 100:.2f} (reason: {refund_reason})")


def _handle_dispute_created(dispute: dict):
    """Handle dispute event - log, notify admins via SNS, and flag for review.

    Disputes are recorded in billing_events for investigation.
    The main handler already records the event, so we just log details here.
    If ALERT_TOPIC_ARN is configured, publishes an SNS notification for admin awareness.

    Args:
        dispute: Stripe dispute object
    """
    # Customer ID can be nested in charge object
    customer_id = dispute.get("customer") or dispute.get("charge", {}).get("customer")
    reason = dispute.get("reason", "not_specified")
    amount = dispute.get("amount", 0)

    logger.warning(f"Dispute created for customer {customer_id}: ${amount / 100:.2f} (reason: {reason})")

    # Notify admins via SNS if configured
    alert_topic_arn = os.environ.get("ALERT_TOPIC_ARN")
    if not alert_topic_arn:
        logger.debug("ALERT_TOPIC_ARN not configured, skipping dispute notification")
        return

    try:
        sns = get_sns()
        sns.publish(
            TopicArn=alert_topic_arn,
            Subject="PkgWatch: Dispute Created",
            Message=(
                f"A payment dispute has been created.\n\n"
                f"Customer ID: {customer_id}\n"
                f"Amount: ${amount / 100:.2f}\n"
                f"Reason: {reason}\n\n"
                f"Please investigate in the Stripe dashboard."
            ),
        )
        logger.info(f"Dispute notification sent for customer {customer_id}")
    except Exception as e:
        # Don't let SNS failures break dispute handling
        logger.error(f"Failed to send dispute notification: {e}")


def _extract_period_from_invoice(invoice: dict) -> tuple[int | None, int | None]:
    """Extract billing period start/end from invoice lines.

    Args:
        invoice: Stripe invoice object

    Returns:
        Tuple of (period_start, period_end) as Unix timestamps, or (None, None)
    """
    lines = invoice.get("lines", {}).get("data", [])

    for line in lines:
        # Look for subscription line items
        if line.get("type") == "subscription":
            period = line.get("period", {})
            return period.get("start"), period.get("end")

    return None, None


def _reset_user_usage_for_billing_cycle(
    customer_id: str,
    period_start: int,
    period_end: int,
):
    """Reset usage counters for a paid user when billing cycle renews.

    Uses atomic ConditionExpression to prevent TOCTOU race conditions and ensure
    idempotent processing. Only updates records where:
    - last_reset_period_start doesn't exist (new users), OR
    - last_reset_period_start < period_start (new billing period)

    Also clears payment failure grace period state on successful billing.

    Updates both per-key and USER_META counters for consistency.

    Args:
        customer_id: Stripe customer ID
        period_start: Unix timestamp of new billing period start
        period_end: Unix timestamp of new billing period end
    """
    table = get_dynamodb().Table(API_KEYS_TABLE)
    reset_time = datetime.now(timezone.utc).isoformat()

    # Query all records for this Stripe customer
    response = table.query(
        IndexName="stripe-customer-index",
        KeyConditionExpression=Key("stripe_customer_id").eq(customer_id),
    )

    items = response.get("Items", [])
    if not items:
        logger.warning(f"No user found for Stripe customer {customer_id} during billing reset")
        return

    user_id = items[0]["pk"]  # Get user_id for USER_META update

    # Reset all API key records with atomic idempotency check
    reset_count = 0
    skipped_count = 0
    for item in items:
        # Skip PENDING records
        if item.get("sk") == "PENDING":
            continue

        try:
            # Use ConditionExpression for atomic idempotency (prevents TOCTOU race)
            table.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression=(
                    "SET requests_this_month = :zero, "
                    "current_period_start = :period_start, "
                    "current_period_end = :period_end, "
                    "last_reset_period_start = :period_start, "
                    "last_usage_reset = :now, "
                    "payment_failures = :zero "
                    "REMOVE first_payment_failure_at"
                ),
                ConditionExpression=(
                    "attribute_not_exists(last_reset_period_start) OR last_reset_period_start < :period_start"
                ),
                ExpressionAttributeValues={
                    ":zero": 0,
                    ":period_start": period_start,
                    ":period_end": period_end,
                    ":now": reset_time,
                },
            )
            reset_count += 1
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # Already reset for this period - skip silently
                skipped_count += 1
            else:
                raise

    # Also reset USER_META (authoritative for rate limiting)
    try:
        table.update_item(
            Key={"pk": user_id, "sk": "USER_META"},
            UpdateExpression=(
                "SET requests_this_month = :zero, "
                "current_period_end = :period_end, "
                "last_reset_period_start = :period_start, "
                "last_usage_reset = :now"
            ),
            ConditionExpression=(
                "attribute_exists(pk) AND ("
                "attribute_not_exists(last_reset_period_start) OR "
                "last_reset_period_start < :period_start)"
            ),
            ExpressionAttributeValues={
                ":zero": 0,
                ":period_start": period_start,
                ":period_end": period_end,
                ":now": reset_time,
            },
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        # USER_META doesn't exist or already reset - that's OK

    logger.info(
        f"Reset usage for customer {customer_id}: "
        f"{reset_count} records reset, {skipped_count} already processed, "
        f"period={period_start}-{period_end}"
    )


def _update_user_tier(
    email: str,
    tier: str,
    customer_id: str = None,
    subscription_id: str = None,
    current_period_start: int = None,
    current_period_end: int = None,
):
    """Update user tier in DynamoDB after successful payment.

    Uses email-index GSI to find user by email address.

    Args:
        email: User email
        tier: New tier name
        customer_id: Stripe customer ID
        subscription_id: Stripe subscription ID
        current_period_start: Unix timestamp of billing period start
        current_period_end: Unix timestamp of billing period end
    """
    if not email:
        logger.error("Cannot update tier: no email provided")
        return

    table = get_dynamodb().Table(API_KEYS_TABLE)

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
            # If user has a subscription, they're verified (Stripe verified via payment)
            update_expr += ", email_verified = :verified"
            expr_values[":verified"] = True

        # Store billing cycle fields for per-user reset tracking
        if current_period_start:
            update_expr += ", current_period_start = :period_start"
            expr_values[":period_start"] = current_period_start
            # Set last_reset_period_start on initial signup (idempotency key)
            update_expr += ", last_reset_period_start = :period_start"
        if current_period_end:
            update_expr += ", current_period_end = :period_end"
            expr_values[":period_end"] = current_period_end

        # Reset payment failures on successful tier update
        update_expr += ", payment_failures = :zero"
        expr_values[":zero"] = 0

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


def _update_user_tier_by_customer_id(
    customer_id: str,
    tier: str,
    current_period_start: int = None,
    current_period_end: int = None,
    subscription_id: str = None,
):
    """Update tier by Stripe customer ID (for upgrades/downgrades).

    Uses stripe-customer-index GSI to find user by Stripe customer ID.

    Args:
        customer_id: Stripe customer ID
        tier: New tier name
        current_period_start: Unix timestamp of billing period start
        current_period_end: Unix timestamp of billing period end
    """
    if not customer_id:
        logger.error("Cannot update tier: no customer_id provided")
        return

    table = get_dynamodb().Table(API_KEYS_TABLE)

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
        current_tier = item.get("tier", "free")
        current_usage = item.get("requests_this_month", 0)

        # Check if this is an upgrade
        is_upgrade = TIER_ORDER.get(tier, 0) > TIER_ORDER.get(current_tier, 0)

        # Warn if downgrading and user is over new limit
        if current_usage > new_limit and not is_upgrade:
            logger.warning(
                f"User {item['pk']} downgraded to {tier} but has {current_usage} "
                f"requests (limit: {new_limit}). User is over limit until reset."
            )

        # Users with Stripe customer ID are verified (Stripe verified via payment)
        update_expr = "SET tier = :tier, tier_updated_at = :now, payment_failures = :zero, monthly_limit = :limit, email_verified = :verified"
        expr_values = {
            ":tier": tier,
            ":now": datetime.now(timezone.utc).isoformat(),
            ":zero": 0,
            ":limit": new_limit,
            ":verified": True,
        }

        # Store billing cycle fields for per-user reset tracking
        if current_period_start:
            update_expr += ", current_period_start = :period_start"
            expr_values[":period_start"] = current_period_start
            # Set last_reset_period_start on initial signup (idempotency key)
            update_expr += ", last_reset_period_start = :period_start"
        if current_period_end:
            update_expr += ", current_period_end = :period_end"
            expr_values[":period_end"] = current_period_end

        if subscription_id:
            update_expr += ", stripe_subscription_id = :sub_id"
            expr_values[":sub_id"] = subscription_id

        table.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values,
        )

    logger.info(f"Updated {len(items)} API keys for customer {customer_id} to tier {tier}")


def _update_user_subscription_state(
    customer_id: str,
    tier: str | None = None,
    cancellation_pending: bool = False,
    cancellation_date: int | None = None,
    current_period_start: int | None = None,
    current_period_end: int | None = None,
    remove_attributes: list[str] | None = None,
):
    """Update user subscription state including tier and cancellation status.

    Uses stripe-customer-index GSI to find user by Stripe customer ID.

    Args:
        customer_id: Stripe customer ID
        tier: New tier name (if changing)
        cancellation_pending: Whether subscription is set to cancel at period end
        cancellation_date: Unix timestamp of when subscription will end (if canceling)
        current_period_start: Unix timestamp of billing period start
        current_period_end: Unix timestamp of billing period end
        remove_attributes: Attribute names to REMOVE from API key records (e.g. on cancellation)
    """
    if not customer_id:
        logger.error("Cannot update subscription state: no customer_id provided")
        return

    table = get_dynamodb().Table(API_KEYS_TABLE)

    # Query GSI by stripe_customer_id
    response = table.query(
        IndexName="stripe-customer-index",
        KeyConditionExpression=Key("stripe_customer_id").eq(customer_id),
    )

    items = response.get("Items", [])
    if not items:
        logger.warning(f"No user found for Stripe customer {customer_id}")
        return

    for item in items:
        update_expr_parts = []
        expr_values = {}

        # Update tier if provided
        if tier:
            current_tier = item.get("tier", "free")
            new_limit = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
            current_usage = item.get("requests_this_month", 0)

            is_upgrade = TIER_ORDER.get(tier, 0) > TIER_ORDER.get(current_tier, 0)

            # Warn if downgrading and user is over new limit
            if current_usage > new_limit and not is_upgrade:
                logger.warning(
                    f"User {item['pk']} downgraded to {tier} but has {current_usage} "
                    f"requests (limit: {new_limit}). User is over limit until reset."
                )

            update_expr_parts.extend(
                [
                    "tier = :tier",
                    "tier_updated_at = :now",
                    "payment_failures = :zero",
                    "monthly_limit = :limit",
                ]
            )
            expr_values.update(
                {
                    ":tier": tier,
                    ":now": datetime.now(timezone.utc).isoformat(),
                    ":zero": 0,
                    ":limit": new_limit,
                }
            )

        # Store billing cycle fields for per-user reset tracking
        if current_period_start:
            update_expr_parts.append("current_period_start = :period_start")
            expr_values[":period_start"] = current_period_start
        if current_period_end:
            update_expr_parts.append("current_period_end = :period_end")
            expr_values[":period_end"] = current_period_end

        # Update cancellation state
        update_expr_parts.append("cancellation_pending = :cancel_pending")
        expr_values[":cancel_pending"] = cancellation_pending

        if cancellation_pending and cancellation_date:
            update_expr_parts.append("cancellation_date = :cancel_date")
            expr_values[":cancel_date"] = cancellation_date
            logger.info(f"User {item['pk']} subscription set to cancel at {cancellation_date}")
        else:
            # Clear cancellation date if not canceling
            update_expr_parts.append("cancellation_date = :null_date")
            expr_values[":null_date"] = None

        if update_expr_parts:
            update_expr = "SET " + ", ".join(update_expr_parts)
            if remove_attributes:
                update_expr += " REMOVE " + ", ".join(remove_attributes)
            table.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression=update_expr,
                ExpressionAttributeValues=expr_values,
            )

    action = f"tier={tier}" if tier else "cancellation state"
    logger.info(
        f"Updated {len(items)} records for customer {customer_id}: {action}, "
        f"cancellation_pending={cancellation_pending}"
    )

    # Also update USER_META for consistency
    # This ensures dashboard reads consistent billing/cancellation state
    if items:
        user_id = items[0]["pk"]
        try:
            meta_update_parts = [
                "cancellation_pending = :cancel_pending",
                "cancellation_date = :cancel_date",
            ]
            meta_values = {
                ":cancel_pending": cancellation_pending,
                ":cancel_date": cancellation_date,
            }

            # Add tier and monthly_limit if provided
            if tier:
                meta_update_parts.append("tier = :tier")
                meta_update_parts.append("monthly_limit = :limit")
                meta_values[":tier"] = tier
                meta_values[":limit"] = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

            # Add billing cycle fields if provided
            if current_period_end:
                meta_update_parts.append("current_period_end = :period_end")
                meta_values[":period_end"] = current_period_end

            table.update_item(
                Key={"pk": user_id, "sk": "USER_META"},
                UpdateExpression="SET " + ", ".join(meta_update_parts),
                ConditionExpression="attribute_exists(pk)",
                ExpressionAttributeValues=meta_values,
            )
            logger.info(f"Updated USER_META for {user_id}: {action}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # USER_META doesn't exist yet - this is OK for legacy accounts
                logger.debug(f"USER_META not found for {user_id}, skipping sync")
            else:
                # Log error but don't fail - API key updates already succeeded
                logger.error(f"Failed to update USER_META for {user_id}: {e}")
