"""
Streams DLQ Processor - Reprocesses failed score calculation messages.

When score_package.py fails and exhausts retries, messages land in the
streams DLQ (pkgwatch-streams-dlq). This processor:

1. Reads failed DynamoDB Streams events from SQS
2. Extracts package identifiers from the stream records
3. Sets a force_rescore flag on the package to trigger re-scoring

The DynamoDB Streams format includes NEW_AND_OLD_IMAGES, so we can
extract the package key from the event.
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")

# Import shared utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../shared"))
try:
    from metrics import emit_batch_metrics, emit_metric
except ImportError:
    # Fallback for testing
    def emit_metric(*args, **kwargs):
        pass

    def emit_batch_metrics(*args, **kwargs):
        pass


PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")


def _parse_dynamodb_value(value: dict):
    """Parse a DynamoDB typed value to Python native type."""
    if "S" in value:
        return value["S"]
    if "N" in value:
        return int(value["N"]) if "." not in value["N"] else float(value["N"])
    if "BOOL" in value:
        return value["BOOL"]
    if "NULL" in value:
        return None
    if "L" in value:
        return [_parse_dynamodb_value(v) for v in value["L"]]
    if "M" in value:
        return {k: _parse_dynamodb_value(v) for k, v in value["M"].items()}
    return None


def _extract_package_key(stream_record: dict) -> tuple[str, str] | None:
    """
    Extract ecosystem and name from a DynamoDB Streams record.

    Args:
        stream_record: A single record from DynamoDB Streams event

    Returns:
        Tuple of (ecosystem, name) or None if extraction fails
    """
    try:
        # Try NewImage first (INSERT/MODIFY), then Keys
        dynamodb_data = stream_record.get("dynamodb", {})
        new_image = dynamodb_data.get("NewImage", {})
        keys = dynamodb_data.get("Keys", {})

        # Get pk from NewImage or Keys
        pk_value = new_image.get("pk", keys.get("pk", {}))
        pk = _parse_dynamodb_value(pk_value) if pk_value else None

        if not pk or "#" not in pk:
            return None

        ecosystem, name = pk.split("#", 1)
        return ecosystem, name

    except Exception as e:
        logger.warning(f"Failed to extract package key from stream record: {e}")
        return None


def _trigger_rescore(ecosystem: str, name: str) -> bool:
    """
    Set force_rescore flag on package to trigger re-scoring.

    The score_package Lambda checks for this flag and will recalculate
    scores even if the idempotency window hasn't passed.

    Returns:
        True if update succeeded, False otherwise
    """
    table = dynamodb.Table(PACKAGES_TABLE)
    now = datetime.now(timezone.utc).isoformat()

    try:
        table.update_item(
            Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"},
            UpdateExpression=("SET force_rescore = :true, rescore_requested_at = :now, rescore_reason = :reason"),
            ExpressionAttributeValues={
                ":true": True,
                ":now": now,
                ":reason": "streams_dlq_recovery",
            },
            ConditionExpression="attribute_exists(pk)",  # Only if package exists
        )
        logger.info(f"Triggered rescore for {ecosystem}/{name}")
        return True

    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        # Package doesn't exist (maybe deleted)
        logger.warning(f"Package {ecosystem}/{name} not found, skipping rescore")
        return False

    except Exception as e:
        logger.error(f"Failed to trigger rescore for {ecosystem}/{name}: {e}")
        return False


def handler(event, context):
    """
    Process messages from the streams DLQ.

    Triggered by SQS with messages containing failed DynamoDB Streams events.
    Each SQS message body contains the original DynamoDB Streams event that
    failed processing in score_package.py.
    """
    records = event.get("Records", [])
    logger.info(f"Processing {len(records)} streams DLQ messages")

    processed = 0
    rescored = 0
    skipped = 0
    failed = 0
    packages_seen = set()  # Dedupe within batch

    for record in records:
        try:
            # Parse the SQS message body which contains the DynamoDB Streams event
            body = json.loads(record.get("body", "{}"))

            # Handle both single records and batched records
            # DynamoDB Streams events have a "Records" array
            stream_records = body.get("Records", [body])

            for stream_record in stream_records:
                processed += 1

                # Extract package key from stream record
                result = _extract_package_key(stream_record)
                if not result:
                    logger.warning("Could not extract package key from stream record")
                    skipped += 1
                    continue

                ecosystem, name = result
                pkg_key = f"{ecosystem}#{name}"

                # Skip if we've already processed this package in this batch
                if pkg_key in packages_seen:
                    logger.debug(f"Skipping duplicate {pkg_key}")
                    continue
                packages_seen.add(pkg_key)

                # Trigger rescore
                if _trigger_rescore(ecosystem, name):
                    rescored += 1
                else:
                    failed += 1

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse DLQ message body: {e}")
            skipped += 1
        except Exception as e:
            logger.error(f"Error processing DLQ message: {e}")
            failed += 1

    # Emit metrics
    try:
        emit_batch_metrics(
            [
                {"metric_name": "StreamsDLQProcessed", "value": processed},
                {"metric_name": "StreamsDLQRescored", "value": rescored},
                {"metric_name": "StreamsDLQSkipped", "value": skipped},
                {"metric_name": "StreamsDLQFailed", "value": failed},
            ]
        )
    except Exception as e:
        logger.warning(f"Failed to emit metrics: {e}")

    logger.info(f"Streams DLQ processed: {processed}, rescored: {rescored}, skipped: {skipped}, failed: {failed}")

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "processed": processed,
                "rescored": rescored,
                "skipped": skipped,
                "failed": failed,
            }
        ),
    }
