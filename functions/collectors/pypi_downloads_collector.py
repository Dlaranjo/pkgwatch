"""
PyPI Downloads Collector - Batch fetch weekly downloads from pypistats.org.

Runs every 6 hours via EventBridge, fetches packages per invocation.
Stores results directly in DynamoDB packages table.

Rate limit: pypistats.org allows ~30 req/min
With 2.5s delay: 24 req/min (safe margin below 30)
Batch: 150 packages × 2.5s = 6.25 min (fits in 10-min Lambda timeout)
Rate: 150 packages/6hr = 600/day
Full refresh: 5,350 packages / 600 per day = ~9 days

This collector is separate from the main package_collector to:
1. Avoid hitting pypistats.org rate limits during normal collection
2. Allow downloads to be updated independently from other metadata
3. Prioritize packages with 0 downloads (data quality fix)
"""

import logging
import os
import time
from datetime import datetime, timezone

import boto3
import httpx
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

PYPISTATS_API = "https://pypistats.org/api"
BATCH_SIZE = 150  # Packages per invocation
REQUEST_DELAY = 2.5  # Seconds between requests (24 req/min, under pypistats 30 req/min limit)
WRITE_BATCH_SIZE = 10  # Write to DynamoDB every N packages


def handler(event, context):
    """Fetch PyPI download stats and update DynamoDB directly."""
    dynamodb = boto3.resource("dynamodb")
    packages_table = dynamodb.Table(os.environ["PACKAGES_TABLE"])

    # 1. Get PyPI packages needing refresh (prioritize unfetched, then oldest)
    packages_to_fetch = _get_packages_needing_refresh(packages_table, BATCH_SIZE, context)

    if not packages_to_fetch:
        logger.info("No packages need download refresh")
        return {"packages_updated": 0, "total_processed": 0}

    logger.info(f"Fetching downloads for {len(packages_to_fetch)} packages")

    # 2. Fetch downloads from pypistats.org with incremental writes
    updated = 0
    processed = 0
    pending_updates = []

    with httpx.Client(timeout=30.0) as client:
        for pkg_name in packages_to_fetch:
            try:
                # pypistats.org accepts the original name and normalizes internally
                url = f"{PYPISTATS_API}/packages/{pkg_name}/recent?period=week"
                resp = client.get(url)

                if resp.status_code == 404:
                    # Package doesn't exist in pypistats - mark as checked with 0
                    pending_updates.append({
                        "name": pkg_name,
                        "weekly_downloads": 0,
                        "downloads_source": "pypistats_404"
                    })
                    processed += 1
                elif resp.status_code == 429:
                    # Rate limited - stop the batch
                    logger.warning("pypistats.org rate limited (429), stopping batch")
                    break
                else:
                    resp.raise_for_status()
                    data = resp.json()
                    downloads = data.get("data", {}).get("last_week", 0)

                    pending_updates.append({
                        "name": pkg_name,
                        "weekly_downloads": downloads,
                        "downloads_source": "pypistats"
                    })
                    if downloads > 0:
                        updated += 1
                    processed += 1

                time.sleep(REQUEST_DELAY)

            except httpx.HTTPStatusError as e:
                logger.warning(f"HTTP error for {pkg_name}: {e.response.status_code}")
                processed += 1
            except Exception as e:
                logger.warning(f"Failed to fetch downloads for {pkg_name}: {e}")
                processed += 1

            # Incremental write every WRITE_BATCH_SIZE packages
            if len(pending_updates) >= WRITE_BATCH_SIZE:
                _write_updates(packages_table, pending_updates)
                pending_updates = []

    # Write any remaining updates
    if pending_updates:
        _write_updates(packages_table, pending_updates)

    logger.info(f"Updated {updated} package download stats (processed {processed})")
    return {"packages_updated": updated, "total_processed": processed}


def _get_packages_needing_refresh(table, limit: int, context=None) -> list:
    """Get PyPI packages needing download refresh with proper pagination.

    Priority 1: Packages missing downloads_fetched_at (never fetched from pypistats)
    Priority 2: Packages with stale data (oldest downloads_fetched_at)

    Note: We do NOT filter on weekly_downloads=0 because pypistats confirmed
    those packages have 0 downloads - refetching would waste API calls.
    """
    MAX_PAGES = 50  # Safety valve (50 pages × ~1MB = covers 12K items)
    MIN_REMAINING_MS = 120_000  # 2 minutes buffer for HTTP calls

    packages = []
    pages_scanned = 0

    # Phase 1: Get packages that have NEVER been fetched from pypistats
    # (missing downloads_fetched_at attribute)
    scan_kwargs = {
        "FilterExpression": "ecosystem = :eco AND attribute_not_exists(downloads_fetched_at)",
        "ExpressionAttributeValues": {":eco": "pypi"},
        "ProjectionExpression": "#n",
        "ExpressionAttributeNames": {"#n": "name"},
    }

    try:
        while len(packages) < limit and pages_scanned < MAX_PAGES:
            # Check Lambda timeout if context provided
            if context:
                remaining_time = context.get_remaining_time_in_millis()
                if remaining_time < MIN_REMAINING_MS:
                    logger.warning(f"Stopping scan early ({remaining_time}ms remaining)")
                    break

            response = table.scan(**scan_kwargs)
            items = response.get("Items", [])
            pages_scanned += 1

            for item in items:
                if len(packages) >= limit:
                    break
                packages.append(item["name"])

            if "LastEvaluatedKey" not in response:
                break
            scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

        # Phase 2: If not enough unfetched packages, get packages with OLDEST data
        if len(packages) < limit:
            remaining = limit - len(packages)
            already_fetched = set(packages)

            logger.info(f"Phase 1 found {len(packages)}, fetching {remaining} oldest for Phase 2")

            oldest_scan_kwargs = {
                "FilterExpression": "ecosystem = :eco AND attribute_exists(downloads_fetched_at)",
                "ExpressionAttributeValues": {":eco": "pypi"},
                "ProjectionExpression": "#n, downloads_fetched_at",
                "ExpressionAttributeNames": {"#n": "name"},
            }

            oldest_packages = []
            oldest_pages = 0

            # Proper pagination for Phase 2
            while oldest_pages < MAX_PAGES:
                if context and context.get_remaining_time_in_millis() < MIN_REMAINING_MS:
                    logger.warning("Stopping Phase 2 scan early due to timeout")
                    break

                response = table.scan(**oldest_scan_kwargs)
                oldest_pages += 1

                for item in response.get("Items", []):
                    if item["name"] not in already_fetched:
                        oldest_packages.append(item)

                if "LastEvaluatedKey" not in response:
                    break
                oldest_scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

            # Sort by oldest downloads_fetched_at first
            oldest_packages.sort(key=lambda x: x.get("downloads_fetched_at", ""))
            packages.extend([item["name"] for item in oldest_packages[:remaining]])

        logger.info(f"Found {len(packages)} packages after {pages_scanned} pages")
        return packages

    except ClientError as e:
        logger.error(f"Failed to get packages needing refresh: {e}")
        return []


def _write_updates(table, updates: list):
    """Write download updates to DynamoDB."""
    now = datetime.now(timezone.utc).isoformat()

    for update in updates:
        try:
            table.update_item(
                Key={"pk": f"pypi#{update['name']}", "sk": "LATEST"},
                UpdateExpression="SET weekly_downloads = :d, downloads_source = :s, downloads_fetched_at = :t",
                ExpressionAttributeValues={
                    ":d": update["weekly_downloads"],
                    ":s": update["downloads_source"],
                    ":t": now
                }
            )
        except ClientError as e:
            logger.warning(f"Failed to update {update['name']}: {e}")

    logger.debug(f"Wrote {len(updates)} updates to DynamoDB")
