"""Emit CloudWatch metrics for data status distribution.

Triggered daily by EventBridge to track data completeness trends.
Uses GSI queries with pagination to efficiently count packages by status.
"""

import logging
import os

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")


def count_by_status(table, status: str) -> int:
    """Count packages with given data_status, handling pagination."""
    total = 0
    last_key = None

    while True:
        query_params = {
            "IndexName": "data-status-index-v2",
            "KeyConditionExpression": Key("data_status").eq(status),
            "Select": "COUNT",
        }
        if last_key:
            query_params["ExclusiveStartKey"] = last_key

        response = table.query(**query_params)
        total += response.get("Count", 0)

        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            break

    return total


def handler(event, context):
    """Emit data status distribution metrics."""
    table = dynamodb.Table(PACKAGES_TABLE)

    counts = {}
    for status in ["complete", "partial", "minimal", "abandoned_minimal"]:
        try:
            counts[status] = count_by_status(table, status)
        except Exception as e:
            logger.error(f"Failed to count {status} packages: {e}")
            counts[status] = 0

    logger.info(f"Data status counts: {counts}")

    # Use existing metrics utility
    try:
        from shared.metrics import emit_batch_metrics

        emit_batch_metrics(
            [
                {"metric_name": "CompletePackages", "value": counts.get("complete", 0)},
                {"metric_name": "PartialPackages", "value": counts.get("partial", 0)},
                {"metric_name": "MinimalPackages", "value": counts.get("minimal", 0)},
                {
                    "metric_name": "AbandonedPackages",
                    "value": counts.get("abandoned_minimal", 0),
                },
            ]
        )
    except Exception as e:
        logger.warning(f"Failed to emit metrics: {e}")

    return {"statusCode": 200, "counts": counts}
