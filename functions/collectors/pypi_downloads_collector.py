"""
PyPI Downloads Collector - Batch fetch weekly downloads from pypistats.org.

Runs every 6 hours via EventBridge, fetches 100 packages per invocation.
Stores results directly in DynamoDB packages table.

Rate: 100 packages/6hr = 400/day
Full refresh: 5,350 packages / 400 per day = ~14 days

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
BATCH_SIZE = 100  # Packages per invocation
REQUEST_DELAY = 0.5  # Seconds between requests (be nice to pypistats.org)
WRITE_BATCH_SIZE = 10  # Write to DynamoDB every N packages


def handler(event, context):
    """Fetch PyPI download stats and update DynamoDB directly."""
    dynamodb = boto3.resource("dynamodb")
    packages_table = dynamodb.Table(os.environ["PACKAGES_TABLE"])

    # 1. Get PyPI packages needing refresh (prioritize 0 downloads)
    packages_to_fetch = _get_packages_needing_refresh(packages_table, BATCH_SIZE)

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


def _get_packages_needing_refresh(table, limit: int) -> list:
    """Get PyPI packages that need download refresh, prioritizing 0 downloads."""
    # Prioritize packages with 0 downloads or missing downloads_fetched_at
    # This ensures we fix the data quality issue first
    try:
        response = table.scan(
            FilterExpression="ecosystem = :eco AND (weekly_downloads = :zero OR attribute_not_exists(downloads_fetched_at))",
            ExpressionAttributeValues={
                ":eco": "pypi",
                ":zero": 0
            },
            ProjectionExpression="#n",
            ExpressionAttributeNames={"#n": "name"},
            Limit=limit * 3  # Over-scan to account for filtering
        )

        packages = [item["name"] for item in response.get("Items", [])[:limit]]

        # If we don't have enough packages with 0 downloads, get older ones
        if len(packages) < limit:
            remaining = limit - len(packages)
            already_fetched = set(packages)

            # Get packages with oldest downloads_fetched_at
            response = table.scan(
                FilterExpression="ecosystem = :eco AND attribute_exists(downloads_fetched_at)",
                ExpressionAttributeValues={":eco": "pypi"},
                ProjectionExpression="#n, downloads_fetched_at",
                ExpressionAttributeNames={"#n": "name"},
                Limit=remaining * 2
            )

            # Sort by oldest first and filter out already selected
            items = [
                item for item in response.get("Items", [])
                if item["name"] not in already_fetched
            ]
            items.sort(key=lambda x: x.get("downloads_fetched_at", ""))

            packages.extend([item["name"] for item in items[:remaining]])

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
