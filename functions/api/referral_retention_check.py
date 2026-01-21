"""
Referral Retention Check - Scheduled Lambda (daily at 1:30 AM UTC)

Processes referrals that have reached the 2-month retention milestone.
Awards the retention bonus (25,000 requests) to referrers whose referred
users are still active paid subscribers.
"""

import logging
import os
from datetime import datetime, timezone

import boto3
import stripe
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from shared.referral_utils import (
    add_bonus_with_cap,
    record_referral_event,
    update_referrer_stats,
    mark_retention_checked,
    REFERRAL_REWARDS,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Lazy initialization
_dynamodb = None
_secretsmanager = None


def _get_dynamodb():
    """Get DynamoDB resource."""
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb


def _get_secretsmanager():
    """Get Secrets Manager client."""
    global _secretsmanager
    if _secretsmanager is None:
        _secretsmanager = boto3.client("secretsmanager")
    return _secretsmanager


API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
REFERRAL_EVENTS_TABLE = os.environ.get("REFERRAL_EVENTS_TABLE", "pkgwatch-referral-events")
STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")


def _get_stripe_api_key() -> str | None:
    """Retrieve Stripe API key from Secrets Manager."""
    if not STRIPE_SECRET_ARN:
        return None

    try:
        import json
        response = _get_secretsmanager().get_secret_value(SecretId=STRIPE_SECRET_ARN)
        secret_value = response.get("SecretString", "")
        try:
            secret_json = json.loads(secret_value)
            return secret_json.get("key") or secret_value
        except json.JSONDecodeError:
            return secret_value
    except ClientError as e:
        logger.error(f"Failed to retrieve Stripe API key: {e}")
        return None


def handler(event, context):
    """
    Lambda handler for daily retention check.

    Queries retention-due-index for referrals where:
    - needs_retention_check = "true"
    - retention_check_date <= now

    For each matching referral:
    1. Verify referred user still has active Stripe subscription
    2. If active: credit referrer with retention bonus
    3. Record "retained" event
    4. Clear needs_retention_check flag
    """
    stripe_api_key = _get_stripe_api_key()
    if not stripe_api_key:
        logger.error("Stripe API key not configured")
        return {"processed": 0, "credited": 0, "error": "Stripe not configured"}

    stripe.api_key = stripe_api_key

    events_table = _get_dynamodb().Table(REFERRAL_EVENTS_TABLE)
    api_keys_table = _get_dynamodb().Table(API_KEYS_TABLE)

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    processed = 0
    credited = 0
    errors = 0

    try:
        # Query for referrals due for retention check
        response = events_table.query(
            IndexName="retention-due-index",
            KeyConditionExpression=(
                Key("needs_retention_check").eq("true") &
                Key("retention_check_date").lte(now_iso)
            ),
            Limit=100,  # Process in batches
        )

        items = response.get("Items", [])
        logger.info(f"Found {len(items)} referrals due for retention check")

        for item in items:
            processed += 1
            referrer_id = item.get("pk")
            referred_id = item.get("referred_id")

            try:
                # Get referred user's subscription status
                user_response = api_keys_table.query(
                    KeyConditionExpression=Key("pk").eq(referred_id),
                )

                user_items = user_response.get("Items", [])
                has_active_subscription = False
                stripe_subscription_id = None

                for user_item in user_items:
                    if user_item.get("sk") not in ("PENDING", "USER_META"):
                        stripe_subscription_id = user_item.get("stripe_subscription_id")
                        if stripe_subscription_id:
                            break

                if stripe_subscription_id:
                    # Verify subscription is still active via Stripe
                    try:
                        subscription = stripe.Subscription.retrieve(stripe_subscription_id)
                        if subscription.status in ["active", "trialing"]:
                            has_active_subscription = True
                    except stripe.StripeError as e:
                        logger.warning(
                            f"Error checking subscription {stripe_subscription_id}: {e}"
                        )

                if has_active_subscription:
                    # Credit referrer with retention bonus
                    reward_amount = REFERRAL_REWARDS["retained"]
                    actual_reward = add_bonus_with_cap(referrer_id, reward_amount)

                    # Record retained event
                    record_referral_event(
                        referrer_id=referrer_id,
                        referred_id=referred_id,
                        event_type="retained",
                        reward_amount=actual_reward,
                    )

                    # Update referrer stats
                    update_referrer_stats(
                        referrer_id,
                        retained_delta=1,
                        rewards_delta=actual_reward,
                    )

                    logger.info(
                        f"Retention bonus: credited {referrer_id} with {actual_reward} "
                        f"for referred user {referred_id}"
                    )
                    credited += 1
                else:
                    logger.info(
                        f"Skipping retention for {referred_id} - "
                        f"subscription not active (referrer: {referrer_id})"
                    )

                # Clear the retention check flag (regardless of outcome)
                mark_retention_checked(referrer_id, referred_id)

            except Exception as e:
                logger.error(f"Error processing retention for {referred_id}: {e}")
                errors += 1

    except Exception as e:
        logger.error(f"Error querying retention-due-index: {e}")
        return {"processed": 0, "credited": 0, "error": str(e)}

    logger.info(
        f"Retention check complete: processed={processed}, credited={credited}, errors={errors}"
    )

    return {
        "processed": processed,
        "credited": credited,
        "errors": errors,
    }
