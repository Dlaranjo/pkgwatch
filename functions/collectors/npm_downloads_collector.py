"""
npm Downloads Collector - Batch fetch weekly downloads from npm API.

Runs every 3 hours via EventBridge (1 hour during backlog clearance).
Stores results directly in DynamoDB packages table.

npm downloads API: api.npmjs.org/downloads/point/last-week/{name}
Bulk endpoint: up to 128 unscoped packages per request (comma-separated).
Scoped packages (@scope/name) must be fetched individually.

Rate limit: ~1000 req/hr (undocumented, conservative estimate)
Batch: 200 packages, bulk fetch reduces actual API calls to ~80-90
Full refresh: ~6,953 npm packages / 1,600 per day = ~4.3 days

This collector is separate from the main package_collector to:
1. Provide a backstop when inline npm download collection fails
2. Allow downloads to be updated independently from other metadata
3. Prioritize packages with missing download data
"""

import logging
import os
import time
from datetime import datetime, timezone

import boto3
import httpx
from botocore.exceptions import ClientError

from shared.circuit_breaker import NPM_DOWNLOADS_CIRCUIT

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

NPM_API = "https://api.npmjs.org"
BATCH_SIZE = 200  # Packages per invocation (bulk endpoint makes this efficient)
BULK_MAX = 128  # npm API limit for bulk downloads endpoint
REQUEST_DELAY = 0.5  # Base delay between individual requests
MAX_DELAY = 10.0  # Cap for adaptive delay increase
WRITE_BATCH_SIZE = 10  # Write to DynamoDB every N packages
CONSECUTIVE_429_ABORT = 3  # Abort batch after this many consecutive 429s
MIN_REMAINING_MS = 45_000  # Break from loop when Lambda has < 45s left


def _encode_scoped_package(name: str) -> str:
    """URL-encode scoped npm package names (@scope/name -> @scope%2Fname)."""
    if name.startswith("@") and "/" in name:
        scope, package_name = name.split("/", 1)
        return f"{scope}%2F{package_name}"
    return name


def handler(event, context):
    """Fetch npm download stats and update DynamoDB directly."""
    # Check circuit breaker before starting batch
    if not NPM_DOWNLOADS_CIRCUIT.can_execute():
        logger.warning("npm downloads circuit breaker is open, skipping batch")
        return {"packages_updated": 0, "total_processed": 0, "circuit_open": True}

    dynamodb = boto3.resource("dynamodb")
    packages_table = dynamodb.Table(os.environ["PACKAGES_TABLE"])

    # 1. Get npm packages needing refresh (prioritize unfetched, then oldest)
    packages_to_fetch = _get_packages_needing_refresh(packages_table, BATCH_SIZE, context)

    if not packages_to_fetch:
        logger.info("No npm packages need download refresh")
        return {"packages_updated": 0, "total_processed": 0}

    logger.info(f"Fetching downloads for {len(packages_to_fetch)} npm packages")

    # 2. Split into scoped and unscoped
    scoped = [p for p in packages_to_fetch if p.startswith("@")]
    unscoped = [p for p in packages_to_fetch if not p.startswith("@")]

    updated = 0
    processed = 0
    rate_limited_count = 0
    pending_updates = []
    consecutive_429s = 0
    current_delay = REQUEST_DELAY

    with httpx.Client(timeout=30.0) as client:
        # 3a. Bulk fetch unscoped packages (up to 128 per request)
        for i in range(0, len(unscoped), BULK_MAX):
            if context and context.get_remaining_time_in_millis() < MIN_REMAINING_MS:
                logger.warning(f"Breaking from bulk loop — {context.get_remaining_time_in_millis()}ms remaining")
                if pending_updates:
                    _write_updates(packages_table, pending_updates)
                    pending_updates = []
                break

            batch = unscoped[i : i + BULK_MAX]
            try:
                packages_str = ",".join(batch)
                url = f"{NPM_API}/downloads/point/last-week/{packages_str}"
                resp = client.get(url)

                if resp.status_code == 429:
                    consecutive_429s += 1
                    rate_limited_count += len(batch)
                    logger.warning(f"npm API rate limited (429) on bulk request, consecutive: {consecutive_429s}")

                    if consecutive_429s >= CONSECUTIVE_429_ABORT:
                        NPM_DOWNLOADS_CIRCUIT.record_failure()
                        for pkg in batch:
                            pending_updates.append(
                                {
                                    "name": pkg,
                                    "downloads_status": "rate_limited",
                                    "downloads_source": "npm_429",
                                }
                            )
                            processed += 1
                        break

                    # Adaptive backoff
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after:
                        try:
                            current_delay = min(float(retry_after), MAX_DELAY)
                        except (ValueError, TypeError):
                            current_delay = min(current_delay * 2, MAX_DELAY)
                    else:
                        current_delay = min(current_delay * 2, MAX_DELAY)

                    time.sleep(current_delay)

                    # Mark batch as rate_limited
                    for pkg in batch:
                        pending_updates.append(
                            {
                                "name": pkg,
                                "downloads_status": "rate_limited",
                                "downloads_source": "npm_429",
                            }
                        )
                        processed += 1
                    continue

                resp.raise_for_status()
                NPM_DOWNLOADS_CIRCUIT.record_success()
                consecutive_429s = 0
                data = resp.json()

                # Handle dual response format
                if len(batch) == 1 and "package" in data:
                    # Single package response: {"downloads": N, "package": "name"}
                    downloads = data.get("downloads", 0)
                    pending_updates.append(
                        {
                            "name": batch[0],
                            "weekly_downloads": downloads,
                            "downloads_source": "npm",
                            "downloads_status": "collected",
                        }
                    )
                    if downloads > 0:
                        updated += 1
                    processed += 1
                else:
                    # Multiple packages: {"pkg1": {"downloads": N}, ...}
                    for pkg in batch:
                        pkg_data = data.get(pkg)
                        if pkg_data and isinstance(pkg_data, dict):
                            downloads = pkg_data.get("downloads", 0)
                            pending_updates.append(
                                {
                                    "name": pkg,
                                    "weekly_downloads": downloads,
                                    "downloads_source": "npm",
                                    "downloads_status": "collected",
                                }
                            )
                            if downloads > 0:
                                updated += 1
                        else:
                            # Package not in bulk response (may not exist)
                            pending_updates.append(
                                {
                                    "name": pkg,
                                    "weekly_downloads": 0,
                                    "downloads_source": "npm_not_found",
                                    "downloads_status": "unavailable",
                                }
                            )
                        processed += 1

                # Reduce delay on success
                current_delay = max(REQUEST_DELAY, current_delay * 0.5)
                time.sleep(current_delay)

            except httpx.HTTPStatusError as e:
                NPM_DOWNLOADS_CIRCUIT.record_failure()
                logger.warning(f"HTTP error on bulk request: {e.response.status_code}")
                # Fall back: mark all packages in batch as error
                for pkg in batch:
                    pending_updates.append(
                        {
                            "name": pkg,
                            "downloads_status": "error",
                            "downloads_source": f"npm_http_{e.response.status_code}",
                        }
                    )
                    processed += 1
            except Exception as e:
                NPM_DOWNLOADS_CIRCUIT.record_failure()
                logger.warning(f"Failed to fetch bulk downloads: {e}")
                for pkg in batch:
                    pending_updates.append(
                        {
                            "name": pkg,
                            "downloads_status": "error",
                            "downloads_source": f"npm_{type(e).__name__}",
                        }
                    )
                    processed += 1

            # Incremental write
            if len(pending_updates) >= WRITE_BATCH_SIZE:
                _write_updates(packages_table, pending_updates)
                pending_updates = []

        # 3b. Individual fetch for scoped packages
        for pkg_name in scoped:
            if context and context.get_remaining_time_in_millis() < MIN_REMAINING_MS:
                logger.warning(f"Breaking from scoped loop — {context.get_remaining_time_in_millis()}ms remaining")
                if pending_updates:
                    _write_updates(packages_table, pending_updates)
                    pending_updates = []
                break

            if consecutive_429s >= CONSECUTIVE_429_ABORT:
                # Already hit abort threshold from bulk phase
                pending_updates.append(
                    {
                        "name": pkg_name,
                        "downloads_status": "rate_limited",
                        "downloads_source": "npm_429",
                    }
                )
                processed += 1
                continue

            try:
                encoded = _encode_scoped_package(pkg_name)
                url = f"{NPM_API}/downloads/point/last-week/{encoded}"
                resp = client.get(url)

                if resp.status_code == 404:
                    NPM_DOWNLOADS_CIRCUIT.record_success()
                    consecutive_429s = 0
                    pending_updates.append(
                        {
                            "name": pkg_name,
                            "weekly_downloads": 0,
                            "downloads_source": "npm_404",
                            "downloads_status": "unavailable",
                        }
                    )
                    processed += 1
                elif resp.status_code == 429:
                    consecutive_429s += 1
                    rate_limited_count += 1
                    logger.warning(f"npm rate limited for {pkg_name}, consecutive: {consecutive_429s}")

                    if consecutive_429s >= CONSECUTIVE_429_ABORT:
                        NPM_DOWNLOADS_CIRCUIT.record_failure()
                        pending_updates.append(
                            {
                                "name": pkg_name,
                                "downloads_status": "rate_limited",
                                "downloads_source": "npm_429",
                            }
                        )
                        processed += 1
                        break

                    # Adaptive backoff
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after:
                        try:
                            current_delay = min(float(retry_after), MAX_DELAY)
                        except (ValueError, TypeError):
                            current_delay = min(current_delay * 2, MAX_DELAY)
                    else:
                        current_delay = min(current_delay * 2, MAX_DELAY)

                    pending_updates.append(
                        {
                            "name": pkg_name,
                            "downloads_status": "rate_limited",
                            "downloads_source": "npm_429",
                        }
                    )
                    processed += 1
                    time.sleep(current_delay)
                else:
                    resp.raise_for_status()
                    NPM_DOWNLOADS_CIRCUIT.record_success()
                    consecutive_429s = 0
                    data = resp.json()
                    downloads = data.get("downloads", 0)

                    pending_updates.append(
                        {
                            "name": pkg_name,
                            "weekly_downloads": downloads,
                            "downloads_source": "npm",
                            "downloads_status": "collected",
                        }
                    )
                    if downloads > 0:
                        updated += 1
                    processed += 1
                    current_delay = max(REQUEST_DELAY, current_delay * 0.5)

                time.sleep(current_delay)

            except httpx.HTTPStatusError as e:
                NPM_DOWNLOADS_CIRCUIT.record_failure()
                logger.warning(f"HTTP error for {pkg_name}: {e.response.status_code}")
                pending_updates.append(
                    {
                        "name": pkg_name,
                        "downloads_status": "error",
                        "downloads_source": f"npm_http_{e.response.status_code}",
                    }
                )
                processed += 1
            except Exception as e:
                NPM_DOWNLOADS_CIRCUIT.record_failure()
                logger.warning(f"Failed to fetch downloads for {pkg_name}: {e}")
                pending_updates.append(
                    {
                        "name": pkg_name,
                        "downloads_status": "error",
                        "downloads_source": f"npm_{type(e).__name__}",
                    }
                )
                processed += 1

            # Incremental write
            if len(pending_updates) >= WRITE_BATCH_SIZE:
                _write_updates(packages_table, pending_updates)
                pending_updates = []

    # Write any remaining updates
    if pending_updates:
        _write_updates(packages_table, pending_updates)

    logger.info(
        f"Updated {updated} npm package download stats (processed {processed}, rate_limited {rate_limited_count})"
    )

    # Emit CloudWatch metrics
    try:
        from shared.metrics import emit_batch_metrics

        emit_batch_metrics(
            [
                {"metric_name": "NpmDownloadsProcessed", "value": processed},
                {"metric_name": "NpmDownloadsRateLimited", "value": rate_limited_count},
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
    """Get npm packages needing download refresh.

    Priority 1: Packages missing downloads_fetched_at (never fetched)
    Priority 2: Packages with oldest downloads_fetched_at (stale data)
    """
    MAX_PAGES = 50  # Safety valve
    MIN_REMAINING_MS = 120_000  # 2 minutes buffer

    packages = []
    pages_scanned = 0

    # Phase 1: Packages that have NEVER been fetched
    scan_kwargs = {
        "FilterExpression": "ecosystem = :eco AND attribute_not_exists(downloads_fetched_at)",
        "ExpressionAttributeValues": {":eco": "npm"},
        "ProjectionExpression": "#n",
        "ExpressionAttributeNames": {"#n": "name"},
    }

    try:
        while len(packages) < limit and pages_scanned < MAX_PAGES:
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
                # npm names used as-is (no PEP 503 normalization)
                packages.append(item["name"])

            if "LastEvaluatedKey" not in response:
                break
            scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

        # Phase 2: If not enough unfetched packages, get oldest
        if len(packages) < limit:
            remaining = limit - len(packages)
            already_fetched = set(packages)

            logger.info(f"Phase 1 found {len(packages)}, fetching {remaining} oldest for Phase 2")

            oldest_scan_kwargs = {
                "FilterExpression": "ecosystem = :eco AND attribute_exists(downloads_fetched_at)",
                "ExpressionAttributeValues": {":eco": "npm"},
                "ProjectionExpression": "#n, downloads_fetched_at",
                "ExpressionAttributeNames": {"#n": "name"},
            }

            oldest_packages = []
            oldest_pages = 0

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

        logger.info(f"Found {len(packages)} npm packages after {pages_scanned} pages")
        return packages

    except ClientError as e:
        logger.error(f"Failed to get npm packages needing refresh: {e}")
        return []


def _write_updates(table, updates: list):
    """Write download updates to DynamoDB.

    Handles different update types:
    - collected/unavailable: Updates weekly_downloads, downloads_status, and timestamp
    - rate_limited: Only updates downloads_status (preserves fetched_at so package stays in queue)
    - error: Updates downloads_status and fetched_at (prevent rapid retry loops)
    """
    now = datetime.now(timezone.utc).isoformat()

    for update in updates:
        try:
            downloads_status = update.get("downloads_status", "collected")
            name = update["name"]

            # rate_limited: preserve downloads AND fetched_at so package stays near front of queue
            if downloads_status == "rate_limited":
                table.update_item(
                    Key={"pk": f"npm#{name}", "sk": "LATEST"},
                    UpdateExpression="SET downloads_status = :ds, downloads_source = :s",
                    ExpressionAttributeValues={
                        ":ds": downloads_status,
                        ":s": update.get("downloads_source", "unknown"),
                    },
                )
            # error: update fetched_at to prevent rapid retry loops
            elif downloads_status == "error":
                table.update_item(
                    Key={"pk": f"npm#{name}", "sk": "LATEST"},
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
                    Key={"pk": f"npm#{name}", "sk": "LATEST"},
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
