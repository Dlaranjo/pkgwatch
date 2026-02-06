"""
Pipeline health check endpoint.

Checks:
- SQS queue depth
- DLQ message count
- Recent collection success rate
- GitHub rate limit status
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
cloudwatch = boto3.client("cloudwatch")

# Import shared utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../shared"))
from metrics import emit_metric

QUEUE_URL = os.environ.get("PACKAGE_QUEUE_URL")
DLQ_URL = os.environ.get("DLQ_URL")


def handler(event, context):
    """Return pipeline health status."""
    health = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {},
    }

    logger.info("Starting pipeline health check")

    # Check main queue depth
    try:
        attrs = sqs.get_queue_attributes(
            QueueUrl=QUEUE_URL, AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"]
        )
        queue_depth = int(attrs["Attributes"].get("ApproximateNumberOfMessages", 0))
        in_flight = int(attrs["Attributes"].get("ApproximateNumberOfMessagesNotVisible", 0))

        health["checks"]["main_queue"] = {
            "status": "healthy" if queue_depth < 1000 else "degraded",
            "depth": queue_depth,
            "in_flight": in_flight,
        }

        if queue_depth >= 1000:
            health["status"] = "degraded"
    except Exception as e:
        health["checks"]["main_queue"] = {"status": "error", "error": str(e)}
        health["status"] = "unhealthy"

    # Check DLQ
    try:
        attrs = sqs.get_queue_attributes(QueueUrl=DLQ_URL, AttributeNames=["ApproximateNumberOfMessages"])
        dlq_depth = int(attrs["Attributes"].get("ApproximateNumberOfMessages", 0))

        health["checks"]["dlq"] = {
            "status": "healthy" if dlq_depth < 10 else "degraded" if dlq_depth < 100 else "unhealthy",
            "depth": dlq_depth,
        }

        if dlq_depth >= 100:
            health["status"] = "unhealthy"
        elif dlq_depth >= 10 and health["status"] != "unhealthy":
            health["status"] = "degraded"
    except Exception as e:
        health["checks"]["dlq"] = {"status": "error", "error": str(e)}

    # Check GitHub rate limit
    try:
        # Get current hour's usage across all shards
        from package_collector import GITHUB_HOURLY_LIMIT, _get_rate_limit_window_key, _get_total_github_calls

        window_key = _get_rate_limit_window_key()
        total_calls = _get_total_github_calls(window_key)

        # Calculate status based on usage percentage
        usage_percent = (total_calls / GITHUB_HOURLY_LIMIT) * 100

        if usage_percent < 75:
            status = "healthy"
        elif usage_percent < 90:
            status = "degraded"
        else:
            status = "unhealthy"
            health["status"] = "unhealthy"

        health["checks"]["github_rate_limit"] = {
            "status": status,
            "calls": total_calls,
            "limit": GITHUB_HOURLY_LIMIT,
            "usage_percent": round(usage_percent, 2),
        }
    except Exception as e:
        health["checks"]["github_rate_limit"] = {"status": "error", "error": str(e)}

    # Log health check results
    logger.info(
        "Health check completed",
        extra={
            "status": health["status"],
            "queue_depth": health["checks"].get("main_queue", {}).get("depth"),
            "dlq_depth": health["checks"].get("dlq", {}).get("depth"),
        },
    )

    # Emit metrics
    try:
        queue_depth = health["checks"].get("main_queue", {}).get("depth", 0)
        dlq_depth = health["checks"].get("dlq", {}).get("depth", 0)

        emit_metric("QueueDepth", value=queue_depth)
        emit_metric("DLQDepth", value=dlq_depth)
        emit_metric("HealthStatus", value=1 if health["status"] == "healthy" else 0)
    except Exception as e:
        logger.warning(f"Failed to emit health metrics: {e}")

    return {
        "statusCode": 200 if health["status"] == "healthy" else 503,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(health),
    }
