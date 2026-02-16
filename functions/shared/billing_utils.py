"""Shared billing utilities for Stripe-related operations."""

import json
import logging
import os
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from shared.aws_clients import get_dynamodb, get_secretsmanager
from shared.constants import THROTTLING_ERRORS, TIER_LIMITS

logger = logging.getLogger(__name__)

# Sentinel for distinguishing "not provided" from None/False/0
UNSET = object()

API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")

STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")

# Cached Stripe API key with TTL
_stripe_api_key_cache = None
_stripe_api_key_cache_time = 0.0
STRIPE_CACHE_TTL = 300  # 5 minutes


def get_stripe_api_key():
    """Retrieve Stripe API key from Secrets Manager (cached with TTL)."""
    global _stripe_api_key_cache, _stripe_api_key_cache_time

    if _stripe_api_key_cache and (time.time() - _stripe_api_key_cache_time) < STRIPE_CACHE_TTL:
        return _stripe_api_key_cache

    if not STRIPE_SECRET_ARN:
        return None

    try:
        response = get_secretsmanager().get_secret_value(SecretId=STRIPE_SECRET_ARN)
        secret_value = response.get("SecretString", "")
        try:
            secret_json = json.loads(secret_value)
            api_key = secret_json.get("key") or secret_value
        except json.JSONDecodeError:
            api_key = secret_value

        _stripe_api_key_cache = api_key
        _stripe_api_key_cache_time = time.time()
        return api_key
    except Exception as e:
        logger.error(f"Failed to retrieve Stripe API key: {e}")
        return None


def update_billing_state(
    user_id: str,
    api_key_records: list[dict],
    *,
    tier: str = UNSET,
    cancellation_pending: bool = UNSET,
    cancellation_date: int | None = UNSET,
    current_period_start: int = UNSET,
    current_period_end: int | None = UNSET,
    payment_failures: int = UNSET,
    stripe_customer_id: str = UNSET,
    stripe_subscription_id: str = UNSET,
    remove_subscription_id: bool = False,
    email_verified: bool = UNSET,
    table=None,
) -> None:
    """Centralized billing state writer.

    Writes to USER_META (authoritative) first, then updates API key records
    (cache). All callers that modify billing/subscription state should use
    this function to ensure consistency.

    Args:
        user_id: The user's pk (e.g. "user_abc123")
        api_key_records: Pre-queried API key record items. PENDING records
            are filtered internally.
        tier: New tier name. Also derives monthly_limit and tier_updated_at.
        cancellation_pending: Whether subscription cancels at period end.
        cancellation_date: Unix timestamp of cancellation, or None to clear.
        current_period_start: Also sets last_reset_period_start on API key records.
        current_period_end: End of current billing period.
        payment_failures: Payment failure count (0 to clear).
        stripe_customer_id: Stripe customer ID (API key records only).
        stripe_subscription_id: Stripe subscription ID (API key records only).
        remove_subscription_id: If True, REMOVE stripe_subscription_id (API key records only).
        email_verified: Mark email verified (API key records only).
        table: DynamoDB table resource. Fetched if not provided.
    """
    if table is None:
        table = get_dynamodb().Table(API_KEYS_TABLE)

    now_iso = datetime.now(timezone.utc).isoformat()

    # Build common billing fields (written to both USER_META and API key records)
    common_set_parts = []
    common_values = {}

    if tier is not UNSET:
        new_limit = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
        common_set_parts.extend([
            "tier = :tier",
            "tier_updated_at = :now",
            "monthly_limit = :limit",
        ])
        common_values[":tier"] = tier
        common_values[":now"] = now_iso
        common_values[":limit"] = new_limit

    if cancellation_pending is not UNSET:
        common_set_parts.append("cancellation_pending = :cancel_pending")
        common_values[":cancel_pending"] = cancellation_pending

    if cancellation_date is not UNSET:
        common_set_parts.append("cancellation_date = :cancel_date")
        common_values[":cancel_date"] = cancellation_date

    if current_period_start is not UNSET:
        common_set_parts.append("current_period_start = :period_start")
        common_values[":period_start"] = current_period_start

    if current_period_end is not UNSET:
        common_set_parts.append("current_period_end = :period_end")
        common_values[":period_end"] = current_period_end

    if payment_failures is not UNSET:
        common_set_parts.append("payment_failures = :pay_fail")
        common_values[":pay_fail"] = payment_failures

    # -- Phase 1: Write to USER_META (authoritative) --
    meta_updated = False
    if common_set_parts:
        meta_expr = "SET " + ", ".join(common_set_parts)
        try:
            table.update_item(
                Key={"pk": user_id, "sk": "USER_META"},
                UpdateExpression=meta_expr,
                ConditionExpression="attribute_exists(pk)",
                ExpressionAttributeValues=common_values,
            )
            meta_updated = True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ConditionalCheckFailedException":
                logger.info(f"USER_META not found for {user_id}, skipping")
            elif error_code in THROTTLING_ERRORS:
                raise  # Let caller handle retry (e.g. webhook releases event claim)
            else:
                logger.error(f"Failed to update USER_META billing state for {user_id}: {e}")

    # -- Phase 2: Write to API key records (cache + Stripe IDs) --
    # Build API-key-specific fields on top of common fields
    key_set_parts = list(common_set_parts)
    key_values = dict(common_values)
    key_remove_parts = []

    # last_reset_period_start mirrors current_period_start on API key records
    if current_period_start is not UNSET:
        key_set_parts.append("last_reset_period_start = :period_start")

    if stripe_customer_id is not UNSET:
        key_set_parts.append("stripe_customer_id = :cust_id")
        key_values[":cust_id"] = stripe_customer_id

    if stripe_subscription_id is not UNSET:
        key_set_parts.append("stripe_subscription_id = :sub_id")
        key_values[":sub_id"] = stripe_subscription_id

    if remove_subscription_id:
        key_remove_parts.append("stripe_subscription_id")

    if email_verified is not UNSET:
        key_set_parts.append("email_verified = :verified")
        key_values[":verified"] = email_verified

    if not key_set_parts and not key_remove_parts:
        return

    expr_parts = []
    if key_set_parts:
        expr_parts.append("SET " + ", ".join(key_set_parts))
    if key_remove_parts:
        expr_parts.append("REMOVE " + ", ".join(key_remove_parts))
    key_expr = " ".join(expr_parts)

    updated_count = 0
    failed_count = 0
    for item in api_key_records:
        sk = item.get("sk", "")
        if sk == "PENDING" or sk == "USER_META":
            continue

        try:
            table.update_item(
                Key={"pk": item["pk"], "sk": sk},
                UpdateExpression=key_expr,
                ExpressionAttributeValues=key_values if key_values else None,
            )
            updated_count += 1
        except ClientError as e:
            failed_count += 1
            logger.warning(f"Failed to update API key record {sk} for {user_id}: {e}")

    changed_fields = [p.split(" = ")[0].strip() for p in key_set_parts]
    if key_remove_parts:
        changed_fields.extend([f"-{r}" for r in key_remove_parts])
    meta_status = "USER_META" if meta_updated else "USER_META(skipped)"
    logger.info(
        f"Billing state updated for {user_id}: "
        f"{', '.join(changed_fields)} across {updated_count} records + {meta_status}"
        + (f" ({failed_count} failed)" if failed_count else "")
    )
