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
from datetime import datetime, timezone

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

sqs = boto3.client("sqs")
dynamodb = boto3.resource("dynamodb")

DLQ_URL = os.environ.get("DLQ_URL")
MAIN_QUEUE_URL = os.environ.get("MAIN_QUEUE_URL")
PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "dephealth-packages")
MAX_DLQ_RETRIES = int(os.environ.get("MAX_DLQ_RETRIES", "5"))


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

            except Exception as e:
                logger.error(f"Error processing DLQ message {message.get('MessageId')}: {e}")

    logger.info(
        f"DLQ processed: {processed}, requeued: {requeued}, "
        f"permanently_failed: {permanently_failed}"
    )

    return {
        "processed": processed,
        "requeued": requeued,
        "permanently_failed": permanently_failed,
    }


def _process_dlq_message(message: dict) -> str:
    """
    Process a single DLQ message.

    Returns:
        "requeued" if message was requeued for retry
        "permanently_failed" if message exceeded max retries
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

    if retry_count >= MAX_DLQ_RETRIES:
        # Move to permanent failure storage
        logger.warning(
            f"Message {message_id} exceeded max retries ({retry_count}), "
            f"last error: {last_error}"
        )
        _store_permanent_failure(body, message_id, last_error)
        _delete_dlq_message(message)
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
            f"(retry {retry_count + 1}/{MAX_DLQ_RETRIES})"
        )
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


def _store_permanent_failure(body: dict, message_id: str, last_error: str) -> None:
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
                "retry_count": body.get("_retry_count", 0),
                "failed_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        logger.info(f"Stored permanent failure for {ecosystem}/{name}")
    except Exception as e:
        logger.error(f"Failed to store permanent failure: {e}")
