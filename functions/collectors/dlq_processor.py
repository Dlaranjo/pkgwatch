"""
DLQ Processor - Reprocesses failed messages with exponential backoff.

Processes messages from the dead-letter queue, implementing:
- Retry tracking to prevent infinite retry loops
- Exponential backoff to reduce load during issues
- Permanent failure storage for messages that exceed max retries
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

sqs = boto3.client("sqs")
dynamodb = boto3.resource("dynamodb")

# Import shared utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../shared"))
from metrics import emit_metric, emit_batch_metrics, emit_dlq_metric

DLQ_URL = os.environ.get("DLQ_URL")
MAIN_QUEUE_URL = os.environ.get("MAIN_QUEUE_URL")
PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "dephealth-packages")
MAX_DLQ_RETRIES = int(os.environ.get("MAX_DLQ_RETRIES", "5"))

# Error classification patterns (merged from multiple sources)
TRANSIENT_ERRORS = [
    "timeout",
    "timed out",
    "503",
    "502",
    "504",
    "rate limit",
    "too many requests",
    "connection",
    "connection reset",
    "connection refused",
    "unavailable",
    "temporarily",
    "temporarily unavailable",
    "service unavailable",
]
PERMANENT_ERRORS = [
    "404",
    "not found",
    "does not exist",
    "invalid package",
    "malformed",
    "forbidden",
    "unauthorized",
    "validation_error",
    "Invalid package name",
]


def classify_error(error_message: str) -> str:
    """
    Classify error as transient or permanent.

    Args:
        error_message: The error message to classify

    Returns:
        "permanent", "transient", or "unknown"
    """
    if not error_message:
        return "unknown"

    error_lower = error_message.lower()

    # Check for permanent errors first (don't retry these)
    for pattern in PERMANENT_ERRORS:
        if pattern.lower() in error_lower:
            return "permanent"

    # Check for transient errors (worth retrying)
    for pattern in TRANSIENT_ERRORS:
        if pattern.lower() in error_lower:
            return "transient"

    return "unknown"


def should_retry(body: dict) -> bool:
    """
    Determine if message should be retried based on error and retry count.

    Args:
        body: Message body with _retry_count, _last_error, _error_class

    Returns:
        True if message should be retried, False otherwise
    """
    retry_count = body.get("_retry_count", 0)
    last_error = body.get("_last_error", "")
    error_class = body.get("_error_class", "unknown")

    # Don't retry permanent errors
    if error_class == "permanent":
        logger.info(f"Skipping retry for permanent error: {last_error}")
        return False

    # Don't retry if max retries exceeded
    if retry_count >= MAX_DLQ_RETRIES:
        return False

    return True


def handler(event, context):
    """
    Process messages from DLQ with retry tracking.

    Scheduled to run every 15 minutes via EventBridge.
    """
    if not DLQ_URL:
        logger.error("DLQ_URL not configured")
        return {"error": "DLQ_URL not configured"}

    if not MAIN_QUEUE_URL:
        logger.error("MAIN_QUEUE_URL not configured")
        return {"error": "MAIN_QUEUE_URL not configured"}

    processed = 0
    requeued = 0
    permanently_failed = 0
    skipped = 0

    # Process messages in batches until queue is empty or we hit a limit
    max_iterations = 10  # Process up to 100 messages per invocation
    for _ in range(max_iterations):
        # Receive up to 10 messages
        response = sqs.receive_message(
            QueueUrl=DLQ_URL,
            MaxNumberOfMessages=10,
            MessageAttributeNames=["All"],
            WaitTimeSeconds=1,  # Short poll to quickly detect empty queue
        )

        messages = response.get("Messages", [])
        if not messages:
            break  # Queue is empty

        for message in messages:
            try:
                result = _process_dlq_message(message)
                processed += 1

                if result == "requeued":
                    requeued += 1
                elif result == "permanently_failed":
                    permanently_failed += 1
                elif result == "skipped":
                    skipped += 1

            except Exception as e:
                logger.error(f"Error processing DLQ message {message.get('MessageId')}: {e}")

    logger.info(
        f"DLQ processed: {processed}, requeued: {requeued}, "
        f"permanently_failed: {permanently_failed}, skipped: {skipped}"
    )

    # Emit metrics
    try:
        emit_batch_metrics([
            {"metric_name": "DLQMessagesProcessed", "value": processed},
            {"metric_name": "DLQMessagesRequeued", "value": requeued},
            {"metric_name": "DLQPermanentFailures", "value": permanently_failed},
            {"metric_name": "DLQMessagesSkipped", "value": skipped},
        ])
    except Exception as e:
        logger.warning(f"Failed to emit DLQ metrics: {e}")

    return {
        "processed": processed,
        "requeued": requeued,
        "permanently_failed": permanently_failed,
        "skipped": skipped,
    }


def _process_dlq_message(message: dict) -> str:
    """
    Process a single DLQ message with error classification.

    Returns:
        "requeued" if message was requeued for retry
        "permanently_failed" if message exceeded max retries or has permanent error
        "skipped" if message was invalid
    """
    message_id = message.get("MessageId", "unknown")

    try:
        body = json.loads(message["Body"])
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Invalid message body in DLQ message {message_id}: {e}")
        # Delete invalid messages - they can't be processed
        _delete_dlq_message(message)
        return "skipped"

    retry_count = int(body.get("_retry_count", 0))
    last_error = body.get("_last_error", "unknown")

    # Classify the error to determine if we should retry
    error_type = classify_error(last_error)

    # Store error classification for should_retry helper
    body["_error_class"] = error_type

    # Use should_retry helper for consistent retry logic
    if not should_retry(body):
        # Move to permanent failure storage
        if error_type == "permanent":
            logger.warning(
                f"Message {message_id} has permanent error, not retrying: {last_error}"
            )
        else:
            logger.warning(
                f"Message {message_id} exceeded max retries ({retry_count}), "
                f"last error: {last_error}"
            )
        _store_permanent_failure(body, message_id, last_error, error_type)
        _delete_dlq_message(message)
        emit_dlq_metric("permanent_failure", body.get("name"))
        return "permanently_failed"

    # Requeue with incremented retry count and delay
    body["_retry_count"] = retry_count + 1

    # Exponential backoff: 60s, 120s, 240s, 480s, 900s (max 15 min)
    delay_seconds = min(900, 60 * (2**retry_count))

    try:
        sqs.send_message(
            QueueUrl=MAIN_QUEUE_URL,
            MessageBody=json.dumps(body),
            DelaySeconds=delay_seconds,
        )
        logger.info(
            f"Requeued message {message_id} with delay {delay_seconds}s "
            f"(retry {retry_count + 1}/{MAX_DLQ_RETRIES}, error_type: {error_type})"
        )
        emit_dlq_metric("requeued", body.get("name"))
    except Exception as e:
        logger.error(f"Failed to requeue message {message_id}: {e}")
        # Don't delete from DLQ if requeue failed - will be retried
        return "skipped"

    # Delete from DLQ after successful requeue
    _delete_dlq_message(message)
    return "requeued"


def _delete_dlq_message(message: dict) -> None:
    """Delete a message from the DLQ."""
    try:
        sqs.delete_message(
            QueueUrl=DLQ_URL,
            ReceiptHandle=message["ReceiptHandle"],
        )
    except Exception as e:
        logger.error(f"Failed to delete DLQ message: {e}")


def _store_permanent_failure(body: dict, message_id: str, last_error: str, error_type: str = "unknown") -> None:
    """Store permanently failed message for manual review."""
    table = dynamodb.Table(PACKAGES_TABLE)

    # Extract package info for easier identification
    ecosystem = body.get("ecosystem", "unknown")
    name = body.get("name", "unknown")

    try:
        table.put_item(
            Item={
                "pk": f"FAILED#{message_id}",
                "sk": datetime.now(timezone.utc).isoformat(),
                "ecosystem": ecosystem,
                "name": name,
                "body": body,
                "failure_reason": last_error,
                "error_type": error_type,
                "retry_count": body.get("_retry_count", 0),
                "failed_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        logger.info(f"Stored permanent failure for {ecosystem}/{name} (error_type: {error_type})")
    except Exception as e:
        logger.error(f"Failed to store permanent failure: {e}")
