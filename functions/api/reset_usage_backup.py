"""
Backup Usage Reset - Daily Scheduled Lambda

Catches missed billing cycle resets for paid users.
Runs daily at 00:05 UTC, checking for users whose current_period_end
has passed but haven't been reset yet.

This is a BACKUP mechanism - primary reset is via invoice.paid webhook.
"""

import logging
import os
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")


def handler(event, context):
    """Check for missed billing resets and reset any overdue users.

    Scans for paid users whose billing period has ended but haven't been reset.
    Uses idempotency check via last_reset_period_start to prevent double resets.

    Uses a 1-hour grace period to avoid race conditions with webhooks.

    Args:
        event: EventBridge scheduled event
        context: Lambda context

    Returns:
        Dict with count of items checked and reset
    """
    table_name = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
    table = dynamodb.Table(table_name)

    now = datetime.now(timezone.utc)
    reset_time = now.isoformat()

    # Grace period to avoid race with webhooks (1 hour)
    grace_period = timedelta(hours=1)
    cutoff_timestamp = int((now - grace_period).timestamp())

    items_checked = 0
    items_reset = 0
    items_already_reset = 0

    logger.info(f"Starting backup reset check, cutoff={cutoff_timestamp} ({(now - grace_period).isoformat()})")

    # Scan for paid users with current_period_end in the past
    # Note: This scan is intentionally broad - we check idempotency per-item
    scan_kwargs = {
        "ProjectionExpression": (
            "pk, sk, tier, current_period_start, current_period_end, last_reset_period_start, stripe_customer_id"
        ),
        "FilterExpression": (
            "attribute_exists(current_period_end) AND "
            "current_period_end < :cutoff AND "
            "tier <> :free AND "
            "NOT begins_with(pk, :system) AND "
            "sk <> :pending"
        ),
        "ExpressionAttributeValues": {
            ":cutoff": cutoff_timestamp,
            ":free": "free",
            ":system": "SYSTEM#",
            ":pending": "PENDING",
        },
    }

    while True:
        response = table.scan(**scan_kwargs)

        for item in response.get("Items", []):
            items_checked += 1

            current_period_start = item.get("current_period_start", 0)
            current_period_end = item.get("current_period_end", 0)
            last_reset_period_start = item.get("last_reset_period_start", 0)

            # Idempotency check - skip if already reset for this period
            if current_period_start <= last_reset_period_start:
                items_already_reset += 1
                continue

            # This user needs a backup reset
            logger.warning(
                f"Backup reset needed for {item['pk']}: "
                f"period_end={current_period_end}, "
                f"last_reset_period_start={last_reset_period_start}"
            )

            try:
                # Calculate next period (estimate ~30 days from old period end)
                # The actual values will be corrected on next invoice.paid webhook
                next_period_start = current_period_end
                next_period_end = current_period_end + (30 * 24 * 60 * 60)

                try:
                    table.update_item(
                        Key={"pk": item["pk"], "sk": item["sk"]},
                        UpdateExpression=(
                            "SET requests_this_month = :zero, "
                            "current_period_start = :new_start, "
                            "current_period_end = :new_end, "
                            "last_reset_period_start = :new_start, "
                            "last_usage_reset = :now"
                        ),
                        ConditionExpression=(
                            "attribute_not_exists(last_reset_period_start) OR last_reset_period_start < :new_start"
                        ),
                        ExpressionAttributeValues={
                            ":zero": 0,
                            ":new_start": next_period_start,
                            ":new_end": next_period_end,
                            ":now": reset_time,
                        },
                    )
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                        logger.info(f"Skipping backup reset for {item['pk']} - already reset by webhook")
                        items_already_reset += 1
                        continue
                    raise
                items_reset += 1

                # Also try to reset USER_META if it exists
                user_id = item["pk"]
                try:
                    table.update_item(
                        Key={"pk": user_id, "sk": "USER_META"},
                        UpdateExpression=(
                            "SET requests_this_month = :zero, "
                            "current_period_end = :new_end, "
                            "last_reset_period_start = :new_start, "
                            "last_usage_reset = :now"
                        ),
                        ExpressionAttributeValues={
                            ":zero": 0,
                            ":new_start": next_period_start,
                            ":new_end": next_period_end,
                            ":now": reset_time,
                        },
                        ConditionExpression=(
                            "attribute_exists(pk) AND ("
                            "attribute_not_exists(last_reset_period_start) OR "
                            "last_reset_period_start < :new_start)"
                        ),
                    )
                except ClientError:
                    pass  # USER_META may not exist or already reset

            except Exception as e:
                logger.error(f"Error in backup reset for {item['pk']}: {e}")

        # Pagination
        if "LastEvaluatedKey" not in response:
            break
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    logger.info(
        f"Backup reset complete: checked={items_checked}, reset={items_reset}, already_reset={items_already_reset}"
    )

    # Log warning if we had to do backup resets (indicates webhook issues)
    if items_reset > 0:
        logger.warning(f"ALERT: {items_reset} users required backup reset - check Stripe webhook delivery")

    return {
        "statusCode": 200,
        "items_checked": items_checked,
        "items_reset": items_reset,
        "items_already_reset": items_already_reset,
        "timestamp": reset_time,
    }
