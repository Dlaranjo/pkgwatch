"""
Retry Dispatcher - Finds incomplete packages due for retry.

Triggered by EventBridge every 15 minutes.
Uses GSI query (not scan) for efficient lookups.

Dispatches packages with staggered delays to avoid overwhelming rate limits.
"""

import json
import logging
import os
import random
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Attr, Key

from shared.logging_utils import configure_structured_logging, request_id_var

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
sqs = boto3.client("sqs")

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
PACKAGE_QUEUE_URL = os.environ.get("PACKAGE_QUEUE_URL")
MAX_RETRY_COUNT = 5
# Configurable via env var for gradual rollout (default: 300, was 100)
MAX_DISPATCH_PER_RUN = int(os.environ.get("MAX_DISPATCH_PER_RUN", "300"))


def handler(event, context):
    """Find incomplete packages due for retry and dispatch."""
    configure_structured_logging()
    request_id_var.set(getattr(context, "aws_request_id", "unknown"))

    if not PACKAGE_QUEUE_URL:
        logger.error("PACKAGE_QUEUE_URL not configured")
        return {"statusCode": 500, "error": "PACKAGE_QUEUE_URL not configured"}

    # Check circuit breakers (used for source-aware skip in dispatch loop)
    github_circuit_open = False
    try:
        from shared.circuit_breaker import GITHUB_CIRCUIT

        if not GITHUB_CIRCUIT.can_execute():
            logger.warning("GitHub circuit open - will skip GitHub-only retries")
            github_circuit_open = True
    except ImportError:
        pass  # Circuit breaker not available in test environment

    now = datetime.now(timezone.utc)
    one_hour_ago = (now - timedelta(hours=1)).isoformat()
    table = dynamodb.Table(PACKAGES_TABLE)
    packages = []

    # Query GSI for each incomplete status (more efficient than Scan)
    # Note: We intentionally don't paginate here to limit throughput and prevent
    # overwhelming external APIs. Older incomplete packages will be picked up
    # in subsequent runs as newer ones are processed.
    for status in ["partial", "minimal", "pending"]:
        try:
            # GSI name is "v2" because the original index was replaced in AWS
            # (DynamoDB doesn't support in-place GSI modifications).
            # Note: CDK still has "data-status-index" due to CloudFormation drift.
            response = table.query(
                IndexName="data-status-index-v2",
                KeyConditionExpression=(Key("data_status").eq(status) & Key("next_retry_at").lte(now.isoformat())),
                FilterExpression=(
                    (Attr("retry_count").not_exists() | Attr("retry_count").lt(MAX_RETRY_COUNT))
                    & (Attr("retry_dispatched_at").not_exists() | Attr("retry_dispatched_at").lt(one_hour_ago))
                ),
                Limit=MAX_DISPATCH_PER_RUN // 2,
            )
            packages.extend(response.get("Items", []))
        except Exception as e:
            logger.error(f"Failed to query {status} packages: {e}")

    logger.info(f"Found {len(packages)} incomplete packages due for retry")

    if not packages:
        return {
            "statusCode": 200,
            "body": json.dumps({"found": 0, "dispatched": 0}),
        }

    dispatched = 0
    errors = 0
    github_skipped = 0

    for pkg in packages:
        if dispatched >= MAX_DISPATCH_PER_RUN:
            break

        if context and hasattr(context, "get_remaining_time_in_millis"):
            remaining_ms = context.get_remaining_time_in_millis()
            if remaining_ms < 15000:
                logger.warning(f"Approaching timeout ({remaining_ms}ms remaining), stopping early")
                break

        pk = pkg.get("pk", "")
        if "#" not in pk:
            logger.warning(f"Invalid pk format: {pk}")
            continue

        ecosystem, name = pk.split("#", 1)

        # Skip packages that only need GitHub retries when GitHub circuit is open
        missing_sources = pkg.get("missing_sources", [])
        if github_circuit_open and missing_sources and all(s == "github" for s in missing_sources):
            logger.debug(f"Skipping {ecosystem}/{name} - GitHub-only retry while circuit open")
            github_skipped += 1
            continue

        # Mark as dispatched (prevents duplicate dispatch on Lambda timeout)
        try:
            table.update_item(
                Key={"pk": pk, "sk": "LATEST"},
                UpdateExpression="SET retry_dispatched_at = :now",
                ExpressionAttributeValues={":now": now.isoformat()},
            )
        except Exception as e:
            logger.warning(f"Failed to update retry_dispatched_at for {pk}: {e}")

        # Stagger to spread load (0-5 minutes)
        delay = random.randint(0, 300)

        try:
            sqs.send_message(
                QueueUrl=PACKAGE_QUEUE_URL,
                MessageBody=json.dumps(
                    {
                        "ecosystem": ecosystem,
                        "name": name,
                        "tier": int(pkg.get("tier", 3)),
                        "force_refresh": True,
                        "retry_sources": pkg.get("missing_sources", []),
                        "reason": "incomplete_data_retry",
                    }
                ),
                DelaySeconds=delay,
            )
            dispatched += 1
        except Exception as e:
            logger.error(f"Failed to dispatch {ecosystem}/{name}: {e}")
            errors += 1

    # Emit metrics
    try:
        from shared.metrics import emit_batch_metrics

        emit_batch_metrics(
            [
                {"metric_name": "RetryDispatcherFound", "value": len(packages)},
                {"metric_name": "RetryDispatcherDispatched", "value": dispatched},
                {"metric_name": "RetryDispatcherErrors", "value": errors},
                {"metric_name": "RetryDispatcherGitHubSkipped", "value": github_skipped},
            ]
        )
    except ImportError:
        pass  # Metrics not available in test environment

    logger.info(f"Dispatched {dispatched} packages for retry ({errors} errors, {github_skipped} github-skipped)")

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "found": len(packages),
                "dispatched": dispatched,
                "errors": errors,
                "github_skipped": github_skipped,
            }
        ),
    }
