"""
OpenSSF Batch Collector - Fetches scorecards with tier prioritization.

Runs every 2 hours via EventBridge.
Prioritizes: Tier 1 > Tier 2 > Tier 3 > Stale refresh.

This collector is separate from the main package_collector to:
1. Ensure high-priority packages get OpenSSF data first
2. Avoid competing with regular collection for rate limits
3. Handle deps.dev lacking OpenSSF data for some packages
"""

import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3
import httpx
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(__file__))  # Add collectors directory
from github_collector import parse_github_url

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

OPENSSF_API = "https://api.securityscorecards.dev"
BATCH_SIZE = 200  # Packages per invocation
REQUEST_DELAY = 0.5  # Seconds between requests (be nice to OpenSSF)
WRITE_BATCH_SIZE = 10  # Write to DynamoDB every N packages
OPENSSF_STALE_DAYS = 7  # Refresh if older than this


def handler(event, context):
    """Fetch OpenSSF scorecards prioritized by tier."""
    dynamodb = boto3.resource("dynamodb")
    packages_table = dynamodb.Table(os.environ["PACKAGES_TABLE"])

    packages = _get_packages_needing_openssf(packages_table, BATCH_SIZE)

    if not packages:
        logger.info("No packages need OpenSSF refresh")
        return {"packages_updated": 0, "total_processed": 0}

    logger.info(f"Fetching OpenSSF for {len(packages)} packages")

    updated = 0
    processed = 0
    pending_updates = []

    with httpx.Client(timeout=30.0) as client:
        for pkg in packages:
            repo_url = pkg.get("repository_url")
            if not repo_url:
                continue

            parsed = parse_github_url(repo_url)
            if not parsed:
                continue

            owner, repo = parsed

            try:
                url = f"{OPENSSF_API}/projects/github.com/{owner}/{repo}"
                resp = client.get(url)

                if resp.status_code == 200:
                    data = resp.json()
                    pending_updates.append(
                        {
                            "pk": pkg["pk"],
                            "openssf_score": data.get("score"),
                            "openssf_checks": data.get("checks", []),
                            "openssf_source": "direct_batch",
                        }
                    )
                    updated += 1
                    processed += 1
                elif resp.status_code == 404:
                    # Package not in OpenSSF - mark date only (don't set score to None)
                    # This allows retry later while preventing immediate re-fetch
                    pending_updates.append(
                        {
                            "pk": pkg["pk"],
                            "openssf_score": None,  # Will be skipped in write
                            "openssf_checks": None,
                            "openssf_source": "not_found",
                        }
                    )
                    processed += 1
                elif resp.status_code == 429:
                    # Rate limited - stop batch
                    logger.warning("OpenSSF API rate limited (429), stopping batch")
                    break

                time.sleep(REQUEST_DELAY)

            except httpx.HTTPStatusError as e:
                logger.warning(f"HTTP error for {owner}/{repo}: {e.response.status_code}")
                processed += 1
            except Exception as e:
                logger.warning(f"Failed to fetch OpenSSF for {owner}/{repo}: {e}")
                processed += 1

            # Incremental write every WRITE_BATCH_SIZE packages
            if len(pending_updates) >= WRITE_BATCH_SIZE:
                _write_openssf_updates(packages_table, pending_updates)
                pending_updates = []

    # Write any remaining updates
    if pending_updates:
        _write_openssf_updates(packages_table, pending_updates)

    logger.info(f"Updated OpenSSF for {updated} packages (processed {processed})")
    return {"packages_updated": updated, "total_processed": processed}


def _get_packages_needing_openssf(table, limit: int) -> list:
    """Get packages needing OpenSSF, prioritized by tier (uses scan, not broken GSI).

    Note: tier-index GSI has KEYS_ONLY projection, can't use it for repository_url.
    """
    packages = []

    # Scan for packages missing openssf_score with repository_url
    response = table.scan(
        FilterExpression="attribute_not_exists(openssf_score) AND attribute_exists(repository_url)",
        ProjectionExpression="pk, repository_url, tier",
        Limit=limit * 3,  # Over-scan to allow tier sorting
    )

    items = response.get("Items", [])

    # Sort by tier (1 first, then 2, then 3, then None)
    def tier_sort_key(item):
        tier = item.get("tier")
        if tier is None:
            return 999
        return tier

    items.sort(key=tier_sort_key)
    packages = items[:limit]

    # If we don't have enough, get stale entries
    if len(packages) < limit:
        stale_threshold = (datetime.now(timezone.utc) - timedelta(days=OPENSSF_STALE_DAYS)).isoformat()
        remaining = limit - len(packages)
        already_fetched = {p["pk"] for p in packages}

        response = table.scan(
            FilterExpression="attribute_exists(openssf_date) AND openssf_date < :threshold AND attribute_exists(repository_url)",
            ExpressionAttributeValues={":threshold": stale_threshold},
            ProjectionExpression="pk, repository_url, tier",
            Limit=remaining * 2,
        )

        for item in response.get("Items", []):
            if item["pk"] not in already_fetched and len(packages) < limit:
                packages.append(item)

    return packages


def _convert_floats_to_decimal(obj):
    """Recursively convert floats to Decimals for DynamoDB compatibility."""
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: _convert_floats_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_convert_floats_to_decimal(item) for item in obj]
    return obj


def _write_openssf_updates(table, updates: list):
    """Write OpenSSF updates to DynamoDB."""
    now = datetime.now(timezone.utc).isoformat()

    for update in updates:
        try:
            # Only update score/checks if we got actual data
            if update["openssf_score"] is not None:
                # Convert floats to Decimals for DynamoDB
                score = Decimal(str(update["openssf_score"]))
                checks = _convert_floats_to_decimal(update["openssf_checks"])

                table.update_item(
                    Key={"pk": update["pk"], "sk": "LATEST"},
                    UpdateExpression="SET openssf_score = :s, openssf_checks = :c, openssf_source = :src, openssf_date = :d",
                    ExpressionAttributeValues={":s": score, ":c": checks, ":src": update["openssf_source"], ":d": now},
                )
            else:
                # For not_found, only update date and source (don't set score to None)
                table.update_item(
                    Key={"pk": update["pk"], "sk": "LATEST"},
                    UpdateExpression="SET openssf_source = :src, openssf_date = :d",
                    ExpressionAttributeValues={":src": update["openssf_source"], ":d": now},
                )
        except ClientError as e:
            logger.warning(f"Failed to update {update['pk']}: {e}")

    logger.debug(f"Wrote {len(updates)} OpenSSF updates to DynamoDB")
