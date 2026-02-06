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
from error_classification import classify_error
from logging_utils import configure_structured_logging, request_id_var
from metrics import emit_batch_metrics, emit_dlq_metric

DLQ_URL = os.environ.get("DLQ_URL")
MAIN_QUEUE_URL = os.environ.get("MAIN_QUEUE_URL")
PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
MAX_DLQ_RETRIES = int(os.environ.get("MAX_DLQ_RETRIES", "5"))


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
    configure_structured_logging()
    request_id_var.set(getattr(context, "aws_request_id", "unknown"))

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
        if context and hasattr(context, "get_remaining_time_in_millis"):
            remaining_ms = context.get_remaining_time_in_millis()
            if remaining_ms < 30000:
                logger.warning(f"Approaching timeout ({remaining_ms}ms remaining), stopping early")
                break

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
        emit_batch_metrics(
            [
                {"metric_name": "DLQMessagesProcessed", "value": processed},
                {"metric_name": "DLQMessagesRequeued", "value": requeued},
                {"metric_name": "DLQPermanentFailures", "value": permanently_failed},
                {"metric_name": "DLQMessagesSkipped", "value": skipped},
            ]
        )
    except Exception as e:
        logger.warning(f"Failed to emit DLQ metrics: {e}")

    return {
        "processed": processed,
        "requeued": requeued,
        "permanently_failed": permanently_failed,
        "skipped": skipped,
    }


def _get_package_error_info(ecosystem: str, name: str) -> tuple[str, str]:
    """
    Fetch error info from package record stored by package_collector.

    Returns:
        Tuple of (error_message, error_class)
    """
    table = dynamodb.Table(PACKAGES_TABLE)
    try:
        response = table.get_item(
            Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"},
            ProjectionExpression="collection_error, collection_error_class",
        )
        item = response.get("Item", {})
        error_msg = item.get("collection_error", "unknown")
        error_class = item.get("collection_error_class", "unknown")
        return error_msg, error_class
    except Exception as e:
        logger.warning(f"Failed to fetch error info for {ecosystem}/{name}: {e}")
        return "unknown", "unknown"


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
        if not _delete_dlq_message(message):
            logger.warning(f"Failed to delete invalid message {message_id} from DLQ")
        return "skipped"

    retry_count = int(body.get("_retry_count", 0))

    # Try to get error info from message first, then from package record
    last_error = body.get("_last_error", "")
    if not last_error or last_error == "unknown":
        # Fetch error info from package record (stored by package_collector)
        ecosystem = body.get("ecosystem", "")
        name = body.get("name", "")
        if ecosystem and name:
            last_error, stored_error_class = _get_package_error_info(ecosystem, name)
            # Use stored error class if available
            if stored_error_class and stored_error_class != "unknown":
                body["_error_class"] = stored_error_class
    else:
        stored_error_class = None

    # If we still don't have an error message, use "unknown"
    if not last_error:
        last_error = "unknown"

    # Classify the error to determine if we should retry
    error_type = classify_error(last_error)

    # Store error classification for should_retry helper
    body["_error_class"] = error_type

    # Use should_retry helper for consistent retry logic
    if not should_retry(body):
        # Move to permanent failure storage
        if error_type == "permanent":
            logger.warning(f"Message {message_id} has permanent error, not retrying: {last_error}")
        else:
            logger.warning(f"Message {message_id} exceeded max retries ({retry_count}), last error: {last_error}")
        _store_permanent_failure(body, message_id, last_error, error_type)
        if _delete_dlq_message(message):
            emit_dlq_metric("permanent_failure", body.get("name"))
        else:
            logger.warning(f"Failed to delete permanently failed message {message_id} from DLQ")
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
    except Exception as e:
        logger.error(f"Failed to requeue message {message_id}: {e}")
        # Don't delete from DLQ if requeue failed - will be retried
        return "skipped"

    # Delete from DLQ after successful requeue
    # If delete fails, the message will be reprocessed but the main queue
    # has deduplication that will catch duplicates within DEDUP_WINDOW_MINUTES
    if _delete_dlq_message(message):
        emit_dlq_metric("requeued", body.get("name"))
        return "requeued"
    else:
        # Delete failed - message may be reprocessed, but requeue succeeded
        # so the work will be done. Log warning but report as requeued.
        logger.warning(f"Message {message_id} requeued but delete failed - may cause duplicate processing")
        emit_dlq_metric("requeued", body.get("name"))
        return "requeued"


def _delete_dlq_message(message: dict, max_retries: int = 3) -> bool:
    """
    Delete a message from the DLQ with retry logic.

    Returns:
        True if deletion succeeded, False otherwise.
    """
    import time

    for attempt in range(max_retries):
        try:
            sqs.delete_message(
                QueueUrl=DLQ_URL,
                ReceiptHandle=message["ReceiptHandle"],
            )
            return True
        except Exception as e:
            if attempt == max_retries - 1:
                logger.error(f"Failed to delete DLQ message after {max_retries} attempts: {e}")
                return False
            # Exponential backoff
            delay = 0.5 * (2**attempt)
            logger.warning(f"DLQ delete attempt {attempt + 1} failed, retrying in {delay}s: {e}")
            time.sleep(delay)

    return False


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
