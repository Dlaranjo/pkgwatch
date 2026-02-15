"""
PyPI Downloads Collector - Batch fetch weekly downloads from pypistats.org.

Runs every 3 hours via EventBridge, fetches packages per invocation.
Stores results directly in DynamoDB packages table.

Rate limit: pypistats.org allows ~30 req/min
With 2.5s base delay: 24 req/min (safe margin below 30)
Batch: 75 packages × ~3s avg = ~4 min (fits in 10-min Lambda timeout)
Rate: 75 packages/3hr = 600/day
Full refresh: 5,350 packages / 600 per day = ~9 days

Adaptive backoff: On 429 rate limit, doubles delay and retries instead of
aborting the batch. Only aborts after 3 consecutive 429s.

This collector is separate from the main package_collector to:
1. Avoid hitting pypistats.org rate limits during normal collection
2. Allow downloads to be updated independently from other metadata
3. Prioritize packages with 0 downloads (data quality fix)
"""

import logging
import os
import re
import time
from datetime import datetime, timezone

import boto3
import httpx
from botocore.exceptions import ClientError

from shared.circuit_breaker import PYPISTATS_CIRCUIT

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

PYPISTATS_API = "https://pypistats.org/api"
BATCH_SIZE = 75  # Packages per invocation (smaller batches hit rate limits less)
REQUEST_DELAY = 2.5  # Base delay between requests (24 req/min, under pypistats 30 req/min limit)
MAX_DELAY = 10.0  # Cap for adaptive delay increase
WRITE_BATCH_SIZE = 10  # Write to DynamoDB every N packages
CONSECUTIVE_429_ABORT = 3  # Abort batch after this many consecutive 429s
MIN_REMAINING_MS = 45_000  # Break from loop when Lambda has < 45s left


def handler(event, context):
    """Fetch PyPI download stats and update DynamoDB directly."""
    # Check circuit breaker before starting batch
    if not PYPISTATS_CIRCUIT.can_execute():
        logger.warning("pypistats circuit breaker is open, skipping batch")
        return {"packages_updated": 0, "total_processed": 0, "circuit_open": True}

    dynamodb = boto3.resource("dynamodb")
    packages_table = dynamodb.Table(os.environ["PACKAGES_TABLE"])

    # 1. Get PyPI packages needing refresh (prioritize unfetched, then oldest)
    packages_to_fetch = _get_packages_needing_refresh(packages_table, BATCH_SIZE, context)

    if not packages_to_fetch:
        logger.info("No packages need download refresh")
        return {"packages_updated": 0, "total_processed": 0}

    logger.info(f"Fetching downloads for {len(packages_to_fetch)} packages")

    # 2. Fetch downloads from pypistats.org with adaptive backoff
    updated = 0
    processed = 0
    rate_limited_count = 0
    pending_updates = []
    current_delay = REQUEST_DELAY
    consecutive_429s = 0

    with httpx.Client(timeout=30.0) as client:
        for pkg_name in packages_to_fetch:
            # Lambda timeout guard — break before we run out of time
            if context and context.get_remaining_time_in_millis() < MIN_REMAINING_MS:
                logger.warning(
                    f"Breaking from loop — {context.get_remaining_time_in_millis()}ms remaining "
                    f"(processed {processed} packages)"
                )
                # Flush pending updates before breaking (defensive — the post-loop
                # flush at line 227 would also catch these, but this protects against
                # future refactoring that might skip it)
                if pending_updates:
                    _write_updates(packages_table, pending_updates)
                    pending_updates = []
                break

            try:
                # pypistats.org accepts the original name and normalizes internally
                url = f"{PYPISTATS_API}/packages/{pkg_name}/recent?period=week"
                resp = client.get(url)

                if resp.status_code == 404:
                    # Package doesn't exist in pypistats - mark as unavailable
                    # 404 is not a failure of pypistats.org, record success
                    PYPISTATS_CIRCUIT.record_success()
                    consecutive_429s = 0
                    pending_updates.append(
                        {
                            "name": pkg_name,
                            "weekly_downloads": 0,
                            "downloads_source": "pypistats_404",
                            "downloads_status": "unavailable",
                        }
                    )
                    processed += 1
                    # Reduce delay on success (fast recovery)
                    current_delay = max(REQUEST_DELAY, current_delay * 0.5)

                elif resp.status_code == 429:
                    consecutive_429s += 1
                    rate_limited_count += 1
                    logger.warning(
                        f"pypistats.org rate limited (429) for {pkg_name}, "
                        f"consecutive: {consecutive_429s}/{CONSECUTIVE_429_ABORT}"
                    )

                    if consecutive_429s >= CONSECUTIVE_429_ABORT:
                        # Too many consecutive 429s — abort batch
                        PYPISTATS_CIRCUIT.record_failure()
                        logger.warning(
                            f"Aborting batch after {consecutive_429s} consecutive 429s (processed {processed} packages)"
                        )
                        pending_updates.append(
                            {
                                "name": pkg_name,
                                "downloads_status": "rate_limited",
                                "downloads_source": "pypistats_429",
                            }
                        )
                        processed += 1
                        break

                    # Adaptive backoff: double delay, respect Retry-After header
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after:
                        try:
                            current_delay = min(float(retry_after), MAX_DELAY)
                        except (ValueError, TypeError):
                            current_delay = min(current_delay * 2, MAX_DELAY)
                    else:
                        current_delay = min(current_delay * 2, MAX_DELAY)

                    logger.info(f"Backing off {current_delay:.1f}s, retrying {pkg_name}")
                    time.sleep(current_delay)

                    # Retry this specific package once
                    retry_resp = client.get(url)
                    if retry_resp.status_code == 200:
                        # Retry succeeded
                        consecutive_429s = 0
                        PYPISTATS_CIRCUIT.record_success()
                        data = retry_resp.json()
                        downloads = data.get("data", {}).get("last_week", 0)
                        pending_updates.append(
                            {
                                "name": pkg_name,
                                "weekly_downloads": downloads,
                                "downloads_source": "pypistats",
                                "downloads_status": "collected",
                            }
                        )
                        if downloads > 0:
                            updated += 1
                        processed += 1
                    else:
                        # Retry failed — skip this package, continue batch
                        pending_updates.append(
                            {
                                "name": pkg_name,
                                "downloads_status": "rate_limited",
                                "downloads_source": "pypistats_429",
                            }
                        )
                        processed += 1

                    time.sleep(current_delay)
                    continue

                else:
                    resp.raise_for_status()
                    PYPISTATS_CIRCUIT.record_success()
                    consecutive_429s = 0
                    data = resp.json()
                    downloads = data.get("data", {}).get("last_week", 0)

                    pending_updates.append(
                        {
                            "name": pkg_name,
                            "weekly_downloads": downloads,
                            "downloads_source": "pypistats",
                            "downloads_status": "collected",
                        }
                    )
                    if downloads > 0:
                        updated += 1
                    processed += 1
                    # Reduce delay on success (fast recovery)
                    current_delay = max(REQUEST_DELAY, current_delay * 0.5)

                time.sleep(current_delay)

            except httpx.HTTPStatusError as e:
                PYPISTATS_CIRCUIT.record_failure()
                logger.warning(f"HTTP error for {pkg_name}: {e.response.status_code}")
                pending_updates.append(
                    {
                        "name": pkg_name,
                        "downloads_status": "error",
                        "downloads_source": f"pypistats_http_{e.response.status_code}",
                    }
                )
                processed += 1
            except Exception as e:
                PYPISTATS_CIRCUIT.record_failure()
                logger.warning(f"Failed to fetch downloads for {pkg_name}: {e}")
                pending_updates.append(
                    {
                        "name": pkg_name,
                        "downloads_status": "error",
                        "downloads_source": f"pypistats_{type(e).__name__}",
                    }
                )
                processed += 1

            # Incremental write every WRITE_BATCH_SIZE packages
            if len(pending_updates) >= WRITE_BATCH_SIZE:
                _write_updates(packages_table, pending_updates)
                pending_updates = []

    # Write any remaining updates
    if pending_updates:
        _write_updates(packages_table, pending_updates)

    logger.info(f"Updated {updated} package download stats (processed {processed}, rate_limited {rate_limited_count})")

    # Emit CloudWatch metrics for monitoring
    try:
        from shared.metrics import emit_batch_metrics

        emit_batch_metrics(
            [
                {"metric_name": "PyPIDownloadsProcessed", "value": processed},
                {"metric_name": "PyPIDownloadsRateLimited", "value": rate_limited_count},
            ]
        )
    except Exception as e:
        logger.warning(f"Failed to emit metrics: {e}")

    return {
        "packages_updated": updated,
        "total_processed": processed,
        "rate_limited_count": rate_limited_count,
    }


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
                # Normalize per PEP 503 to match canonical DynamoDB keys
                packages.append(re.sub(r"[-_.]+", "-", item["name"].lower()))

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
            packages.extend([re.sub(r"[-_.]+", "-", item["name"].lower()) for item in oldest_packages[:remaining]])

        logger.info(f"Found {len(packages)} packages after {pages_scanned} pages")
        return packages

    except ClientError as e:
        logger.error(f"Failed to get packages needing refresh: {e}")
        return []


def _write_updates(table, updates: list):
    """Write download updates to DynamoDB.

    Handles different update types:
    - collected/unavailable: Updates weekly_downloads, downloads_status, and timestamp
    - rate_limited/error: Only updates downloads_status (preserves existing weekly_downloads)
    """
    now = datetime.now(timezone.utc).isoformat()

    for update in updates:
        try:
            downloads_status = update.get("downloads_status", "collected")
            # Normalize name per PEP 503 to match canonical DynamoDB keys
            normalized_name = re.sub(r"[-_.]+", "-", update["name"].lower())

            # For rate_limited: only update status (preserve downloads AND fetched_at so package stays in queue)
            if downloads_status == "rate_limited":
                table.update_item(
                    Key={"pk": f"pypi#{normalized_name}", "sk": "LATEST"},
                    UpdateExpression="SET downloads_status = :ds, downloads_source = :s",
                    ExpressionAttributeValues={
                        ":ds": downloads_status,
                        ":s": update.get("downloads_source", "unknown"),
                    },
                )
            # For error: update status and fetched_at (prevent rapid retry loops)
            elif downloads_status == "error":
                table.update_item(
                    Key={"pk": f"pypi#{normalized_name}", "sk": "LATEST"},
                    UpdateExpression="SET downloads_status = :ds, downloads_source = :s, downloads_fetched_at = :t",
                    ExpressionAttributeValues={
                        ":ds": downloads_status,
                        ":s": update.get("downloads_source", "unknown"),
                        ":t": now,
                    },
                )
            else:
                # Full update for collected/unavailable status
                table.update_item(
                    Key={"pk": f"pypi#{normalized_name}", "sk": "LATEST"},
                    UpdateExpression="SET weekly_downloads = :d, downloads_source = :s, downloads_status = :ds, downloads_fetched_at = :t",
                    ExpressionAttributeValues={
                        ":d": update["weekly_downloads"],
                        ":s": update["downloads_source"],
                        ":ds": downloads_status,
                        ":t": now,
                    },
                )
        except ClientError as e:
            logger.warning(f"Failed to update {update['name']}: {e}")

    logger.debug(f"Wrote {len(updates)} updates to DynamoDB")
