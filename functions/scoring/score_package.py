"""
Score Package - Lambda handler for calculating and storing scores.

Can be triggered:
1. After data collection (via SQS/SNS)
2. On-demand for specific packages
3. Batch processing for all packages
"""

import json
import logging
import os
import random
import threading
import time
from datetime import datetime, timezone
from decimal import Decimal
from typing import Callable, Optional, TypeVar

import boto3
from botocore.exceptions import ClientError

# Support both Lambda (direct imports) and pytest (package-qualified imports)
try:
    # Lambda environment - all files deployed to same directory
    from abandonment_risk import calculate_abandonment_risk
    from health_score import calculate_health_score

    from shared.data_quality import is_queryable
    from shared.logging_utils import configure_structured_logging, set_request_id
except ImportError:
    # pytest environment - functions dir added to sys.path
    from scoring.abandonment_risk import calculate_abandonment_risk
    from scoring.health_score import calculate_health_score
    from shared.data_quality import is_queryable
    from shared.logging_utils import configure_structured_logging, set_request_id

# Backward compatibility alias for tests
_is_queryable = is_queryable

logger = logging.getLogger(__name__)


# Defense in depth: skip scoring if package was scored recently
# This prevents infinite loops if the DynamoDB Streams filter doesn't work as expected
IDEMPOTENCY_WINDOW_SECONDS = int(os.environ.get("IDEMPOTENCY_WINDOW_SECONDS", "60"))

# Retry configuration for DynamoDB operations
DYNAMODB_MAX_RETRIES = 3
DYNAMODB_BASE_DELAY = 0.1
DYNAMODB_MAX_DELAY = 2.0

T = TypeVar("T")


def _retry_sync(
    func: Callable[..., T],
    *args,
    max_retries: int = DYNAMODB_MAX_RETRIES,
    base_delay: float = DYNAMODB_BASE_DELAY,
    max_delay: float = DYNAMODB_MAX_DELAY,
    retryable_exceptions: tuple = (ClientError,),
    **kwargs
) -> T:
    """
    Execute sync function with retry logic and exponential backoff.

    Only retries on throttling/transient errors, not on validation errors.
    """
    last_exception: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        try:
            return func(*args, **kwargs)
        except retryable_exceptions as e:
            # Only retry on throttling errors, not on validation errors
            if isinstance(e, ClientError):
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code not in (
                    "ProvisionedThroughputExceededException",
                    "ThrottlingException",
                    "InternalServerError",
                    "ServiceUnavailable",
                ):
                    raise  # Don't retry validation errors

            last_exception = e

            if attempt == max_retries:
                logger.error(
                    f"All {max_retries + 1} attempts failed for {func.__name__}",
                    extra={
                        "function": func.__name__,
                        "attempts": max_retries + 1,
                        "error_type": type(e).__name__,
                    }
                )
                raise

            # Exponential backoff with jitter
            delay = min(base_delay * (2 ** attempt), max_delay)
            jitter = random.uniform(0, delay * 0.3)
            sleep_time = delay + jitter

            logger.warning(
                f"Attempt {attempt + 1}/{max_retries + 1} failed, "
                f"retrying in {sleep_time:.2f}s: {type(e).__name__}"
            )
            time.sleep(sleep_time)

    raise last_exception or RuntimeError("Unexpected retry state")


def to_decimal(obj):
    """Convert floats to Decimal for DynamoDB compatibility."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [to_decimal(v) for v in obj]
    return obj


def from_decimal(obj):
    """Convert Decimals to floats for math operations."""
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: from_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [from_decimal(v) for v in obj]
    return obj

# Lazy initialization - avoid boto3 calls at import time
# This prevents cold start failures if credentials are not yet available
_dynamodb_resource = None
_dynamodb_lock = threading.Lock()
PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")


def _get_dynamodb():
    """Get DynamoDB resource with thread-safe lazy initialization."""
    global _dynamodb_resource
    if _dynamodb_resource is None:
        with _dynamodb_lock:
            # Double-check pattern for thread safety
            if _dynamodb_resource is None:
                _dynamodb_resource = boto3.resource("dynamodb")
    return _dynamodb_resource


def handler(event, context):
    """
    Lambda handler for score calculation.

    Event formats:
    1. Single package: {"ecosystem": "npm", "name": "lodash"}
    2. DynamoDB Streams or SQS batch: {"Records": [...]}
    3. Recalculate all: {"action": "recalculate_all"}
    """
    # Initialize structured logging for CloudWatch Logs Insights queryability
    configure_structured_logging()
    request_id = set_request_id(event)
    logger.info(
        "Score calculation handler invoked",
        extra={
            "request_id": request_id,
            "event_type": "stream_batch" if "Records" in event else event.get("action", "single_package"),
        }
    )

    if "Records" in event:
        # DynamoDB Streams or SQS batch processing
        return _process_stream_batch(event)
    elif event.get("action") == "recalculate_all":
        # Batch recalculation
        return _recalculate_all()
    else:
        # Single package
        return _score_single_package(event)


def _score_single_package(event: dict) -> dict:
    """Score a single package."""
    ecosystem = event.get("ecosystem", "npm")
    name = event.get("name")

    if not name:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Package name is required"}),
        }

    table = _get_dynamodb().Table(PACKAGES_TABLE)

    # Fetch package data with retry
    try:
        response = _retry_sync(
            table.get_item,
            Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"}
        )
        item = response.get("Item")

        if not item:
            return {
                "statusCode": 404,
                "body": json.dumps({"error": f"Package {name} not found"}),
            }
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        logger.error(
            f"DynamoDB error fetching package {name}: {error_code}",
            extra={"error_code": error_code, "package": name},
            exc_info=True,
        )
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Failed to fetch package data"}),
        }
    except Exception as e:
        logger.error(
            f"Unexpected error fetching package {name}: {type(e).__name__}",
            exc_info=True,
        )
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Internal server error"}),
        }

    # Convert Decimals to floats for math operations
    item = from_decimal(item)

    # Defense in depth: skip if recently scored (prevents infinite loop)
    if IDEMPOTENCY_WINDOW_SECONDS > 0:
        scored_at = item.get("scored_at")
        if scored_at:
            try:
                scored_time = datetime.fromisoformat(
                    scored_at.replace("Z", "+00:00") if isinstance(scored_at, str) else scored_at
                )
                seconds_since_scored = (datetime.now(timezone.utc) - scored_time).total_seconds()
                if seconds_since_scored < IDEMPOTENCY_WINDOW_SECONDS:
                    logger.debug(f"Skipping {name} - scored {seconds_since_scored:.1f}s ago")
                    return {
                        "statusCode": 200,
                        "body": json.dumps({"skipped": True, "reason": "recently_scored"}),
                    }
            except (ValueError, TypeError) as e:
                logger.warning(f"Could not parse scored_at for {name}: {e}")
                # Continue with scoring if we can't parse the timestamp

    # Calculate scores
    health_result = calculate_health_score(item)
    abandonment_result = calculate_abandonment_risk(item)

    # Update package with scores (with retry)
    now = datetime.now(timezone.utc).isoformat()

    # Compute queryable with the new health_score
    # item already has latest_version, weekly_downloads, dependents_count, data_status
    item_with_score = {**item, "health_score": health_result["health_score"]}
    queryable = _is_queryable(item_with_score)

    try:
        _retry_sync(
            table.update_item,
            Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"},
            UpdateExpression="""
                SET health_score = :hs,
                    risk_level = :rl,
                    score_components = :sc,
                    confidence = :conf,
                    confidence_interval = :ci,
                    abandonment_risk = :ar,
                    scored_at = :now,
                    queryable = :q
                REMOVE force_rescore
            """,
            ExpressionAttributeValues={
                ":hs": to_decimal(health_result["health_score"]),
                ":rl": health_result["risk_level"],
                ":sc": to_decimal(health_result["components"]),
                ":conf": to_decimal(health_result["confidence"]),
                ":ci": to_decimal(health_result["confidence_interval"]),
                ":ar": to_decimal(abandonment_result),
                ":now": now,
                ":q": queryable,
            },
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        logger.error(
            f"DynamoDB error updating scores for {name}: {error_code}",
            extra={"error_code": error_code, "package": name},
            exc_info=True,
        )
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Failed to save package scores"}),
        }
    except Exception as e:
        logger.error(
            f"Unexpected error updating scores for {name}: {type(e).__name__}",
            exc_info=True,
        )
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Internal server error"}),
        }

    return {
        "statusCode": 200,
        "body": json.dumps({
            "package": name,
            "ecosystem": ecosystem,
            "health_score": health_result["health_score"],
            "risk_level": health_result["risk_level"],
            "components": health_result["components"],
            "confidence": health_result["confidence"],
            "abandonment_risk": abandonment_result,
        }),
    }


def _process_stream_batch(event: dict) -> dict:
    """Process a batch of packages from DynamoDB Streams or SQS.

    Returns batchItemFailures for DynamoDB Streams to enable partial batch retries.
    See: https://docs.aws.amazon.com/lambda/latest/dg/with-ddb.html#services-ddb-batchfailurereporting
    """
    successes = 0
    failures = 0
    skipped = 0
    failed_item_ids = []  # Track failed record IDs for partial batch retry

    for record in event.get("Records", []):
        try:
            # Check if this is a DynamoDB Stream record
            if "dynamodb" in record:
                # DynamoDB Streams format
                event_name = record.get("eventName")

                # Only process INSERT and MODIFY events (not REMOVE)
                if event_name not in ("INSERT", "MODIFY"):
                    skipped += 1
                    continue

                # Get the new image
                new_image = record.get("dynamodb", {}).get("NewImage", {})
                if not new_image:
                    logger.warning("No NewImage in DynamoDB stream record")
                    skipped += 1
                    continue

                # Check if this is a collection event (has collected_at but no scored_at change)
                # This prevents infinite loops - we only score when data is collected
                old_image = record.get("dynamodb", {}).get("OldImage", {})
                new_collected_at = new_image.get("collected_at", {}).get("S")
                old_collected_at = old_image.get("collected_at", {}).get("S") if old_image else None

                # Check for force_rescore flag (allows manual data updates to trigger rescoring)
                force_rescore = new_image.get("force_rescore", {}).get("BOOL", False)

                # Skip if collected_at hasn't changed AND not force_rescore
                # IMPORTANT: Must check new_collected_at is not None to avoid None == None being True
                if event_name == "MODIFY" and not force_rescore:
                    if new_collected_at and new_collected_at == old_collected_at:
                        logger.debug("Skipping - collected_at unchanged (likely score update)")
                        skipped += 1
                        continue

                # Extract ecosystem and name from pk
                pk = new_image.get("pk", {}).get("S", "")
                if "#" not in pk:
                    logger.warning(f"Invalid pk format in stream record: {pk}")
                    failures += 1
                    # Don't add to failed_item_ids - this is a data issue, not transient
                    continue

                ecosystem, name = pk.split("#", 1)
                message = {"ecosystem": ecosystem, "name": name}
            else:
                # SQS format (fallback)
                message = json.loads(record["body"])

            result = _score_single_package(message)

            if result["statusCode"] == 200:
                body = json.loads(result["body"])
                if body.get("skipped"):
                    skipped += 1
                else:
                    successes += 1
            else:
                failures += 1
                # Track for retry if this is a DynamoDB Stream record with transient failure
                if "dynamodb" in record and result["statusCode"] >= 500:
                    event_id = record.get("eventID")
                    if event_id:
                        failed_item_ids.append(event_id)
                logger.warning(f"Failed to score package: {result}")

        except Exception as e:
            logger.error(f"Error processing record: {e}", exc_info=True)
            failures += 1
            # Track for retry - transient errors should be retried
            if "dynamodb" in record:
                event_id = record.get("eventID")
                if event_id:
                    failed_item_ids.append(event_id)

    logger.info(
        f"Stream processing complete: {successes} scored, {skipped} skipped, {failures} failed",
        extra={
            "successes": successes,
            "skipped": skipped,
            "failures": failures,
            "failed_item_count": len(failed_item_ids),
        }
    )

    # Return batchItemFailures for DynamoDB Streams partial batch retry
    # This allows Lambda to retry only the failed records instead of the entire batch
    response = {
        "statusCode": 200,
        "body": json.dumps({
            "processed": successes + failures + skipped,
            "successes": successes,
            "skipped": skipped,
            "failures": failures,
        }),
    }

    # Add batchItemFailures if there are failed items to retry
    if failed_item_ids:
        response["batchItemFailures"] = [
            {"itemIdentifier": item_id} for item_id in failed_item_ids
        ]

    return response


def _recalculate_all() -> dict:
    """
    Recalculate scores for all packages.

    WARNING: This function is disabled in production because it:
    1. Will exceed Lambda's 15-minute timeout for large package counts
    2. Loads all package keys into memory (OOM risk)
    3. Provides no resume capability if interrupted

    For batch recalculation, use a Step Functions workflow or
    dispatch individual scoring messages to SQS.
    """
    logger.warning("_recalculate_all is disabled - use Step Functions for batch operations")
    return {
        "statusCode": 501,
        "body": json.dumps({
            "error": "Batch recalculation is disabled",
            "message": "This operation is not safe for production. Use Step Functions workflow for batch recalculation.",
        }),
    }
