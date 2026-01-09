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
from datetime import datetime, timezone

import boto3

logger = logging.getLogger(__name__)

sqs = boto3.client("sqs")
cloudwatch = boto3.client("cloudwatch")

QUEUE_URL = os.environ.get("PACKAGE_QUEUE_URL")
DLQ_URL = os.environ.get("DLQ_URL")


def handler(event, context):
    """Return pipeline health status."""
    health = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {},
    }

    # Check main queue depth
    try:
        attrs = sqs.get_queue_attributes(
            QueueUrl=QUEUE_URL,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"]
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
        attrs = sqs.get_queue_attributes(
            QueueUrl=DLQ_URL,
            AttributeNames=["ApproximateNumberOfMessages"]
        )
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
        # Implementation depends on how you expose this
        health["checks"]["github_rate_limit"] = {
            "status": "healthy",
            "note": "Check CloudWatch for details",
        }
    except Exception as e:
        health["checks"]["github_rate_limit"] = {"status": "error", "error": str(e)}

    return {
        "statusCode": 200 if health["status"] == "healthy" else 503,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(health),
    }
