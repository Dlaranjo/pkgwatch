"""Emit CloudWatch metrics for data status distribution.

Triggered daily by EventBridge to track data completeness trends.
Uses a single table scan to count both status distribution and download coverage.
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
    """Count packages with given data_status using GSI.

    DEPRECATED: GSI excludes packages without next_retry_at (all "complete" and
    "abandoned" packages). Use scan_all_metrics() instead for accurate counts.
    Kept for backward compatibility with existing tests.
    """
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


def scan_all_metrics(table) -> dict:
    """Single-pass scan to collect both status counts and download coverage.

    Replaces the broken GSI query (which missed packages without next_retry_at)
    and the separate download coverage scan, halving total scan time.
    """
    status_counts = {
        "complete": 0,
        "partial": 0,
        "minimal": 0,
        "pending": 0,
        "abandoned_minimal": 0,
        "abandoned_partial": 0,
    }
    coverage = {
        "npm_total": 0,
        "npm_with_downloads": 0,
        "pypi_total": 0,
        "pypi_with_downloads": 0,
        "pypi_never_fetched": 0,
    }

    scan_kwargs = {
        "FilterExpression": "sk = :sk",
        "ExpressionAttributeValues": {":sk": "LATEST"},
        "ProjectionExpression": "data_status, ecosystem, weekly_downloads, downloads_status",
    }

    while True:
        response = table.scan(**scan_kwargs)
        for item in response.get("Items", []):
            # Status counts
            ds = item.get("data_status", "")
            if ds in status_counts:
                status_counts[ds] += 1

            # Download coverage
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
                dl_status = item.get("downloads_status")
                if not dl_status or dl_status == "never_fetched":
                    coverage["pypi_never_fetched"] += 1

        if "LastEvaluatedKey" not in response:
            break
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    return {"status_counts": status_counts, "coverage": coverage}


def handler(event, context):
    """Emit data status distribution and download coverage metrics."""
    table = dynamodb.Table(PACKAGES_TABLE)

    try:
        result = scan_all_metrics(table)
        counts = result["status_counts"]
        coverage = result["coverage"]
        logger.info(f"Data status counts: {counts}")
        logger.info(f"Download coverage: {coverage}")
    except Exception as e:
        logger.error(f"Failed to scan metrics: {e}")
        counts = {s: 0 for s in ["complete", "partial", "minimal", "pending", "abandoned_minimal", "abandoned_partial"]}
        coverage = {}

    # Compute percentages
    pypi_pct = (
        (coverage["pypi_with_downloads"] / coverage["pypi_total"] * 100) if coverage.get("pypi_total", 0) > 0 else 0
    )
    npm_pct = (coverage["npm_with_downloads"] / coverage["npm_total"] * 100) if coverage.get("npm_total", 0) > 0 else 0

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
