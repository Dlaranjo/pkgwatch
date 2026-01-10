"""
Monthly Usage Reset - Scheduled Lambda

Triggered by EventBridge on the 1st of each month at midnight UTC.
Resets all users' monthly usage counters.

Supports resumption via DynamoDB state storage if the Lambda times out.
Uses per-page checkpointing for reliability.
"""

import boto3
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
lambda_client = boto3.client("lambda")

# State key for storing resume position
RESET_STATE_PK = "SYSTEM#RESET_STATE"
RESET_STATE_SK = "monthly_reset"


def handler(event, context):
    """Reset all users' monthly usage counters on 1st of each month.

    Uses pagination to handle large user bases without timeout.
    Checkpoints after each page for reliable resumption.
    Checks remaining Lambda execution time to avoid timeouts.
    Stores resume state in DynamoDB and re-invokes self if needed.

    Args:
        event: EventBridge scheduled event or resume event with last_key
        context: Lambda context with get_remaining_time_in_millis()

    Returns:
        Dict with count of items processed
    """
    table_name = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
    table = dynamodb.Table(table_name)

    reset_time = datetime.now(timezone.utc).isoformat()
    reset_month = datetime.now(timezone.utc).strftime("%Y-%m")
    items_processed = 0
    pages_processed = 0

    # Check if this is a resume invocation or if we have stored state
    last_evaluated_key = event.get("resume_key")

    if not last_evaluated_key:
        # Check for stored resume state from a previous timeout
        stored_state = _get_reset_state(table, reset_month)
        if stored_state:
            last_evaluated_key = stored_state.get("last_key")
            logger.info(f"Resuming from stored state: {last_evaluated_key}")

    logger.info(f"Starting monthly usage reset for table {table_name}, month {reset_month}")

    while True:
        # Paginated scan - only need pk, sk for update
        # Filter out: SYSTEM# records, PENDING signups, demo# rate limit records
        scan_kwargs = {
            "ProjectionExpression": "pk, sk",
            "FilterExpression": "NOT begins_with(pk, :system) AND NOT begins_with(pk, :demo) AND sk <> :pending",
            "ExpressionAttributeValues": {
                ":system": "SYSTEM#",
                ":demo": "demo#",
                ":pending": "PENDING",
            },
        }
        if last_evaluated_key:
            scan_kwargs["ExclusiveStartKey"] = last_evaluated_key

        response = table.scan(**scan_kwargs)
        page_items = response.get("Items", [])
        page_errors = 0

        for item in page_items:
            try:
                table.update_item(
                    Key={"pk": item["pk"], "sk": item["sk"]},
                    UpdateExpression="SET requests_this_month = :zero, last_reset = :now, payment_failures = :zero",
                    ExpressionAttributeValues={
                        ":zero": 0,
                        ":now": reset_time,
                    },
                )
                items_processed += 1
            except Exception as e:
                page_errors += 1
                logger.error(f"Error resetting usage for {item['pk']}/{item['sk']}: {e}")

        pages_processed += 1
        last_evaluated_key = response.get("LastEvaluatedKey")

        # Checkpoint after each page - store state for potential resume
        if last_evaluated_key:
            _store_reset_state(table, reset_month, last_evaluated_key, items_processed)

        if not last_evaluated_key:
            # All done - clear any stored state
            _clear_reset_state(table)
            logger.info(f"Monthly reset complete: {items_processed} items in {pages_processed} pages")
            break

        # Check remaining Lambda time (leave 60s buffer for self-invoke)
        remaining_time = context.get_remaining_time_in_millis()
        if remaining_time < 60000:
            logger.warning(
                f"Running low on time ({remaining_time}ms remaining), "
                f"processed {items_processed} items in {pages_processed} pages - will resume"
            )
            # State already stored after page processing
            # Invoke self to continue - MUST succeed or we raise
            _invoke_self_async(context.function_name, last_evaluated_key)
            break

    return {
        "statusCode": 200,
        "items_processed": items_processed,
        "pages_processed": pages_processed,
        "reset_time": reset_time,
        "reset_month": reset_month,
        "completed": last_evaluated_key is None,
    }


def _get_reset_state(table, reset_month: str) -> dict | None:
    """Get stored reset state for the current month."""
    try:
        response = table.get_item(
            Key={"pk": RESET_STATE_PK, "sk": RESET_STATE_SK}
        )
        item = response.get("Item")
        if item and item.get("reset_month") == reset_month:
            return item
    except Exception as e:
        logger.error(f"Error getting reset state: {e}")
    return None


def _store_reset_state(table, reset_month: str, last_key: dict, items_so_far: int = 0):
    """Store reset state for resumption after each page."""
    try:
        table.put_item(
            Item={
                "pk": RESET_STATE_PK,
                "sk": RESET_STATE_SK,
                "reset_month": reset_month,
                "last_key": last_key,
                "items_processed": items_so_far,
                "stored_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        logger.debug(f"Checkpointed reset state: {items_so_far} items processed")
    except Exception as e:
        # Log error but don't fail - we can still continue
        logger.error(f"Error storing reset state: {e}")


def _clear_reset_state(table):
    """Clear stored reset state after successful completion."""
    try:
        table.delete_item(
            Key={"pk": RESET_STATE_PK, "sk": RESET_STATE_SK}
        )
        logger.info("Cleared reset state after completion")
    except Exception as e:
        logger.error(f"Error clearing reset state: {e}")


def _invoke_self_async(function_name: str, resume_key: dict):
    """Invoke this Lambda asynchronously to continue the reset.

    IMPORTANT: Raises exception on failure to prevent silent incomplete resets.
    The EventBridge rule will retry the original invocation if this fails.
    """
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType="Event",  # Async
            Payload=json.dumps({"resume_key": resume_key}),
        )
        status_code = response.get("StatusCode", 0)
        if status_code not in (200, 202):
            raise RuntimeError(f"Lambda invoke returned status {status_code}")
        logger.info(f"Invoked self ({function_name}) to continue reset")
    except Exception as e:
        logger.error(f"CRITICAL: Failed to invoke self for resume: {e}")
        # Raise to fail the Lambda - EventBridge will retry
        raise RuntimeError(f"Failed to schedule reset continuation: {e}") from e
