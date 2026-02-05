"""
PyPI Downloads BigQuery Collector - Fetch weekly downloads from Google BigQuery.

This collector replaces pypistats.org with direct BigQuery access to the official
PyPI downloads dataset (bigquery-public-data.pypi.file_downloads).

Benefits over pypistats.org:
1. No rate limits (pay-per-query pricing instead)
2. Official data source (same data pypistats uses)
3. Can fetch all packages in a single batch query
4. More reliable and faster

Schedule: Daily at 1:00 AM UTC
Memory: 1024 MB (BigQuery client needs headroom)
Timeout: 10 minutes
Reserved concurrency: 1 (avoid concurrent queries)

GCP credentials are stored in Secrets Manager:
- Secret: pkgwatch/gcp-bigquery-credentials
- Format: JSON service account key

Query uses partition pruning (_PARTITIONTIME) for cost optimization.
Without pruning: ~2-3 TB scanned ($10-15)
With pruning: ~200-400 GB scanned ($1-2)

Event format:
{
    "dry_run": false,      # If true, report what would be done
    "batch_size": 1000,    # DynamoDB batch write size
    "limit": 0             # Limit packages (0 = unlimited, for testing)
}
"""

import json
import logging
import os
import random
import time
from datetime import datetime, timezone
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
GCP_CREDENTIALS_SECRET = os.environ.get(
    "GCP_CREDENTIALS_SECRET", "pkgwatch/gcp-bigquery-credentials"
)

# Batch size for DynamoDB writes
WRITE_BATCH_SIZE = int(os.environ.get("BIGQUERY_WRITE_BATCH_SIZE", "100"))

# Retry configuration for BigQuery queries
MAX_QUERY_RETRIES = 3
QUERY_RETRY_BASE_DELAY = 5  # seconds

# Transient BigQuery errors worth retrying
RETRYABLE_ERRORS = (
    "ServiceUnavailable",
    "InternalServerError",
    "TooManyRequests",
    "BadGateway",
    "Timeout",
    "DeadlineExceeded",
)


def _is_retryable_error(error: Exception) -> bool:
    """Check if a BigQuery error is transient and worth retrying."""
    error_str = str(error)
    return any(err in error_str for err in RETRYABLE_ERRORS)


def _get_gcp_credentials():
    """
    Retrieve GCP service account credentials from Secrets Manager.

    Returns:
        dict: Parsed JSON service account credentials
        None: If credentials not found or error
    """
    try:
        secretsmanager = boto3.client("secretsmanager")
        response = secretsmanager.get_secret_value(SecretId=GCP_CREDENTIALS_SECRET)
        return json.loads(response["SecretString"])
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            logger.warning(
                f"GCP credentials secret not found: {GCP_CREDENTIALS_SECRET}. "
                "BigQuery collector requires GCP service account credentials."
            )
        else:
            logger.error(f"Failed to retrieve GCP credentials: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse GCP credentials JSON: {e}")
        return None


def _get_pypi_packages(table) -> list[str]:
    """
    Get all PyPI package names from DynamoDB.

    Returns:
        List of package names
    """
    packages = []
    scan_kwargs = {
        "FilterExpression": "ecosystem = :eco",
        "ExpressionAttributeValues": {":eco": "pypi"},
        "ProjectionExpression": "#n",
        "ExpressionAttributeNames": {"#n": "name"},
    }

    try:
        paginator = table.meta.client.get_paginator("scan")
        for page in paginator.paginate(TableName=PACKAGES_TABLE, **scan_kwargs):
            for item in page.get("Items", []):
                name = item.get("name", {}).get("S")
                if name:
                    packages.append(name)

        logger.info(f"Found {len(packages)} PyPI packages in DynamoDB")
        return packages

    except ClientError as e:
        logger.error(f"Failed to scan packages table: {e}")
        return []


def _query_bigquery_downloads(credentials: dict, package_names: set, limit: int = 0) -> dict:
    """
    Query BigQuery for weekly download counts.

    Args:
        credentials: GCP service account credentials dict
        package_names: Set of package names to filter results
        limit: Limit results (0 = unlimited)

    Returns:
        Dict mapping package_name -> weekly_downloads
    """
    try:
        from google.cloud import bigquery
        from google.oauth2 import service_account
    except ImportError as e:
        logger.error(
            f"google-cloud-bigquery not installed: {e}. "
            "This Lambda requires google-cloud-bigquery package."
        )
        return {}

    # Create credentials from service account info
    gcp_credentials = service_account.Credentials.from_service_account_info(
        credentials,
        scopes=["https://www.googleapis.com/auth/bigquery.readonly"],
    )

    # Create BigQuery client
    client = bigquery.Client(
        credentials=gcp_credentials,
        project=credentials.get("project_id"),
    )

    # Build query with partition pruning
    # _PARTITIONTIME filter reduces data scanned from ~2TB to ~400GB
    query = """
    SELECT
        file.project AS package_name,
        COUNT(*) AS weekly_downloads
    FROM `bigquery-public-data.pypi.file_downloads`
    WHERE
        timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
        AND _PARTITIONTIME >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 8 DAY)
    GROUP BY file.project
    """

    if limit > 0:
        query += f"\nLIMIT {limit}"

    logger.info("Executing BigQuery query...")
    start_time = datetime.now(timezone.utc)

    # Retry loop for transient BigQuery errors
    for attempt in range(MAX_QUERY_RETRIES):
        try:
            query_job = client.query(query)
            results = query_job.result()

            # Build download map (only for packages we track)
            downloads = {}
            total_rows = 0
            matched_rows = 0

            for row in results:
                total_rows += 1
                package_name = row.package_name
                # Only include packages we're tracking
                if package_name in package_names:
                    downloads[package_name] = row.weekly_downloads
                    matched_rows += 1

            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            bytes_billed = query_job.total_bytes_billed or 0
            gb_billed = bytes_billed / (1024**3)

            logger.info(
                f"BigQuery query complete: {total_rows} total rows, "
                f"{matched_rows} matched packages, "
                f"{gb_billed:.2f} GB billed, "
                f"{elapsed:.1f}s elapsed"
            )

            return downloads

        except Exception as e:
            if not _is_retryable_error(e):
                # Non-retryable error (syntax, permissions, etc.)
                logger.error(f"BigQuery query failed with non-retryable error: {e}")
                return {}

            if attempt < MAX_QUERY_RETRIES - 1:
                # Exponential backoff with jitter
                delay = QUERY_RETRY_BASE_DELAY * (2 ** attempt) + random.uniform(0, 1)
                logger.warning(
                    f"BigQuery query failed (attempt {attempt + 1}/{MAX_QUERY_RETRIES}), "
                    f"retrying in {delay:.1f}s: {e}"
                )
                time.sleep(delay)
            else:
                logger.error(f"BigQuery query failed after {MAX_QUERY_RETRIES} attempts: {e}")
                return {}


def _write_downloads_batch(table, downloads: dict, dry_run: bool = False) -> tuple[int, int]:
    """
    Write download counts to DynamoDB in batches.

    Args:
        table: DynamoDB table resource
        downloads: Dict mapping package_name -> weekly_downloads
        dry_run: If True, don't actually write

    Returns:
        Tuple of (success_count, error_count)
    """
    now = datetime.now(timezone.utc).isoformat()
    success_count = 0
    error_count = 0

    # Process in batches
    items = list(downloads.items())
    total_batches = (len(items) + WRITE_BATCH_SIZE - 1) // WRITE_BATCH_SIZE

    for batch_num, i in enumerate(range(0, len(items), WRITE_BATCH_SIZE)):
        batch = items[i : i + WRITE_BATCH_SIZE]

        if dry_run:
            success_count += len(batch)
            continue

        for package_name, count in batch:
            try:
                table.update_item(
                    Key={"pk": f"pypi#{package_name}", "sk": "LATEST"},
                    UpdateExpression=(
                        "SET weekly_downloads = :d, "
                        "downloads_source = :s, "
                        "downloads_status = :ds, "
                        "downloads_fetched_at = :t"
                    ),
                    ExpressionAttributeValues={
                        ":d": count,
                        ":s": "bigquery",
                        ":ds": "collected",
                        ":t": now,
                    },
                )
                success_count += 1
            except ClientError as e:
                logger.warning(f"Failed to update {package_name}: {e}")
                error_count += 1

        if (batch_num + 1) % 10 == 0 or batch_num == total_batches - 1:
            logger.info(
                f"Progress: batch {batch_num + 1}/{total_batches}, "
                f"{success_count} updated, {error_count} errors"
            )

    return success_count, error_count


def _mark_packages_not_found(table, package_names: set, dry_run: bool = False) -> tuple[int, int]:
    """
    Mark packages not found in BigQuery with 0 downloads.

    These could be new packages with no downloads yet or name normalization mismatches.
    Uses distinct downloads_source to distinguish from confirmed downloads.

    Args:
        table: DynamoDB table resource
        package_names: Set of package names not found in BigQuery
        dry_run: If True, don't actually write

    Returns:
        Tuple of (success_count, error_count)
    """
    now = datetime.now(timezone.utc).isoformat()
    success_count = 0
    error_count = 0

    for package_name in package_names:
        if dry_run:
            success_count += 1
            continue

        try:
            table.update_item(
                Key={"pk": f"pypi#{package_name}", "sk": "LATEST"},
                UpdateExpression=(
                    "SET weekly_downloads = :d, "
                    "downloads_source = :s, "
                    "downloads_status = :ds, "
                    "downloads_fetched_at = :t"
                ),
                ExpressionAttributeValues={
                    ":d": 0,
                    ":s": "bigquery_not_found",  # Distinct from "bigquery"
                    ":ds": "collected",
                    ":t": now,
                },
            )
            success_count += 1
        except ClientError as e:
            logger.warning(f"Failed to mark {package_name} as not found: {e}")
            error_count += 1

    return success_count, error_count


def handler(event, context):
    """
    Lambda handler for BigQuery PyPI downloads collector.

    Fetches weekly download counts from BigQuery and updates DynamoDB.
    """
    dry_run = event.get("dry_run", False)
    limit = event.get("limit", 0)

    logger.info(
        f"Starting BigQuery PyPI downloads collector: dry_run={dry_run}, limit={limit}"
    )

    # Get GCP credentials
    credentials = _get_gcp_credentials()
    if not credentials:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "GCP credentials not available",
                "message": f"Configure {GCP_CREDENTIALS_SECRET} in Secrets Manager",
            }),
        }

    # Get DynamoDB table
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(PACKAGES_TABLE)

    # Get list of PyPI packages we're tracking
    package_names = set(_get_pypi_packages(table))
    if not package_names:
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "No PyPI packages found in database",
                "packages_updated": 0,
            }),
        }

    # Query BigQuery for download counts
    downloads = _query_bigquery_downloads(credentials, package_names, limit)
    if not downloads:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "BigQuery query returned no results",
                "message": "Check GCP credentials and BigQuery access",
            }),
        }

    # Write to DynamoDB
    success_count, error_count = _write_downloads_batch(table, downloads, dry_run)

    # Mark packages not found in BigQuery as having 0 downloads
    # These could be new packages with no downloads yet or name normalization mismatches
    packages_not_found = package_names - set(downloads.keys())
    not_found_count = len(packages_not_found)
    if packages_not_found:
        logger.info(f"Marking {not_found_count} packages not found in BigQuery")
        not_found_success, not_found_errors = _mark_packages_not_found(
            table, packages_not_found, dry_run
        )
        success_count += not_found_success
        error_count += not_found_errors

    # Calculate coverage
    packages_with_downloads = len([d for d in downloads.values() if d > 0])
    total_tracked = len(package_names)
    coverage = (len(downloads) / total_tracked * 100) if total_tracked > 0 else 0

    result = {
        "statusCode": 200,
        "body": json.dumps({
            "dry_run": dry_run,
            "packages_tracked": total_tracked,
            "packages_found_in_bigquery": len(downloads),
            "packages_not_found": not_found_count,
            "packages_with_downloads": packages_with_downloads,
            "coverage_percent": round(coverage, 1),
            "packages_updated": success_count,
            "errors": error_count,
        }),
    }

    logger.info(
        f"BigQuery collector complete: {success_count} updated, "
        f"{error_count} errors, {coverage:.1f}% coverage"
    )

    return result
