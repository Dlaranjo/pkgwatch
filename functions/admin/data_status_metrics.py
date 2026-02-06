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
        # GSI "v2" - original index was replaced (DynamoDB doesn't support in-place mods)
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


def count_download_coverage(table) -> dict:
    """Scan LATEST records to compute download coverage by ecosystem.

    Full table scan for ~12K packages takes ~10-30s, well within the 2-minute
    Lambda timeout. Replace with pre-aggregated counters if package count exceeds 50K.
    """
    coverage = {
        "npm_total": 0, "npm_with_downloads": 0,
        "pypi_total": 0, "pypi_with_downloads": 0,
        "pypi_never_fetched": 0,
    }

    scan_kwargs = {
        "FilterExpression": "sk = :sk",
        "ExpressionAttributeValues": {":sk": "LATEST"},
        "ProjectionExpression": "ecosystem, weekly_downloads, downloads_status",
    }

    while True:
        response = table.scan(**scan_kwargs)
        for item in response.get("Items", []):
            eco = item.get("ecosystem", "")
            downloads = int(item.get("weekly_downloads", 0))

            if eco == "npm":
                coverage["npm_total"] += 1
                if downloads > 0:
                    coverage["npm_with_downloads"] += 1
            elif eco == "pypi":
                coverage["pypi_total"] += 1
                if downloads > 0:
                    coverage["pypi_with_downloads"] += 1
                ds = item.get("downloads_status")
                if not ds or ds == "never_fetched":
                    coverage["pypi_never_fetched"] += 1

        if "LastEvaluatedKey" not in response:
            break
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    return coverage


def handler(event, context):
    """Emit data status distribution and download coverage metrics."""
    table = dynamodb.Table(PACKAGES_TABLE)

    counts = {}
    for status in ["complete", "partial", "minimal", "pending", "abandoned_minimal", "abandoned_partial"]:
        try:
            counts[status] = count_by_status(table, status)
        except Exception as e:
            logger.error(f"Failed to count {status} packages: {e}")
            counts[status] = 0

    logger.info(f"Data status counts: {counts}")

    # Download coverage scan
    try:
        coverage = count_download_coverage(table)
        logger.info(f"Download coverage: {coverage}")
    except Exception as e:
        logger.error(f"Failed to compute download coverage: {e}")
        coverage = {}

    # Compute percentages
    pypi_pct = (
        (coverage["pypi_with_downloads"] / coverage["pypi_total"] * 100)
        if coverage.get("pypi_total", 0) > 0
        else 0
    )
    npm_pct = (
        (coverage["npm_with_downloads"] / coverage["npm_total"] * 100)
        if coverage.get("npm_total", 0) > 0
        else 0
    )

    # Use existing metrics utility
    try:
        from shared.metrics import emit_batch_metrics

        emit_batch_metrics(
            [
                {"metric_name": "CompletePackages", "value": counts.get("complete", 0)},
                {"metric_name": "PartialPackages", "value": counts.get("partial", 0)},
                {"metric_name": "MinimalPackages", "value": counts.get("minimal", 0)},
                {"metric_name": "PendingPackages", "value": counts.get("pending", 0)},
                {
                    "metric_name": "AbandonedPackages",
                    "value": counts.get("abandoned_minimal", 0),
                },
                {
                    "metric_name": "AbandonedPartialPackages",
                    "value": counts.get("abandoned_partial", 0),
                },
                {"metric_name": "PypiDownloadCoverage", "value": pypi_pct, "unit": "Percent"},
                {"metric_name": "NpmDownloadCoverage", "value": npm_pct, "unit": "Percent"},
                {"metric_name": "PypiDownloadsNeverFetched", "value": coverage.get("pypi_never_fetched", 0)},
            ]
        )
    except Exception as e:
        logger.warning(f"Failed to emit metrics: {e}")

    return {"statusCode": 200, "counts": counts, "coverage": coverage}
