"""
Backfill Dependents - One-time script to recover dependents_count for packages stuck at 0.

deps.dev returns 404 for dependents on newly published versions (indexing lag).
A preservation fix prevents future zero-overwrites, but ~844 packages already had
their counts set to 0 before the fix. This script fetches dependents from deps.dev
using version fallback (try up to 3 older versions) and updates DynamoDB directly.

Usage (run locally — no Lambda needed):
    PYTHONPATH=functions:. python functions/admin/backfill_dependents.py --dry-run
    PYTHONPATH=functions:. python functions/admin/backfill_dependents.py
    PYTHONPATH=functions:. python functions/admin/backfill_dependents.py --limit 10
"""

import argparse
import asyncio
import json
import logging
import os
from urllib.parse import quote

import boto3
import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
DEPSDEV_API = "https://api.deps.dev/v3"
DEPSDEV_API_ALPHA = "https://api.deps.dev/v3alpha"
MAX_FALLBACK_VERSIONS = 3
CONCURRENCY = 20


async def fetch_dependents_for_package(client: httpx.AsyncClient, ecosystem: str, name: str) -> tuple[int, str]:
    """Fetch dependents_count using version fallback. Returns (count, version_used)."""
    encoded_name = quote(name, safe="")

    # Get package versions
    pkg_url = f"{DEPSDEV_API}/systems/{ecosystem}/packages/{encoded_name}"
    try:
        resp = await client.get(pkg_url)
        if resp.status_code == 404:
            return 0, ""
        resp.raise_for_status()
    except (httpx.HTTPStatusError, httpx.RequestError) as e:
        logger.warning(f"Failed to fetch package info for {ecosystem}/{name}: {e}")
        return 0, ""

    pkg_data = resp.json()

    # Determine latest version
    latest_version = pkg_data.get("defaultVersion", "")
    if not latest_version:
        versions = pkg_data.get("versions", [])
        for v in versions:
            if v.get("isDefault"):
                latest_version = v.get("versionKey", {}).get("version", "")
                break
        if not latest_version and versions:
            latest_version = versions[-1].get("versionKey", {}).get("version", "")

    if not latest_version:
        return 0, ""

    # Build fallback candidates
    versions_list = pkg_data.get("versions", [])
    non_deprecated = [
        v.get("versionKey", {}).get("version", "")
        for v in versions_list
        if v.get("versionKey", {}).get("version") and not v.get("isDeprecated")
    ]

    candidates = [latest_version]
    if latest_version in non_deprecated:
        idx = non_deprecated.index(latest_version)
        for i in range(idx - 1, max(idx - MAX_FALLBACK_VERSIONS, -1), -1):
            candidates.append(non_deprecated[i])

    # Try each candidate
    for ver in candidates:
        try:
            encoded_ver = quote(ver, safe="")
            dep_url = (
                f"{DEPSDEV_API_ALPHA}/systems/{ecosystem}/packages/{encoded_name}/versions/{encoded_ver}:dependents"
            )
            dep_resp = await client.get(dep_url)
            if dep_resp.status_code == 404:
                continue
            dep_resp.raise_for_status()
            data = dep_resp.json()
            count_value = data.get("dependentCount")
            if isinstance(count_value, int) and count_value > 0:
                return count_value, ver
            elif isinstance(count_value, list) and len(count_value) > 0:
                return len(count_value), ver
        except (httpx.HTTPStatusError, httpx.RequestError):
            continue

    return 0, ""


async def backfill(dry_run: bool = True, limit: int = 0):
    """Scan for affected packages and backfill dependents_count."""
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(PACKAGES_TABLE)

    # Scan for packages with 0 or missing dependents_count
    logger.info("Scanning for packages with dependents_count=0 or missing...")
    affected = []
    scan_kwargs = {
        "FilterExpression": "sk = :sk AND (attribute_not_exists(dependents_count) OR dependents_count = :zero)",
        "ExpressionAttributeValues": {":sk": "LATEST", ":zero": 0},
        "ProjectionExpression": "pk, sk, ecosystem, #n, dependents_count, weekly_downloads",
        "ExpressionAttributeNames": {"#n": "name"},
    }

    while True:
        response = table.scan(**scan_kwargs)
        affected.extend(response.get("Items", []))
        if "LastEvaluatedKey" not in response:
            break
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    logger.info(f"Found {len(affected)} packages with 0/missing dependents")

    if limit > 0:
        affected = affected[:limit]
        logger.info(f"Limited to {limit} packages")

    # Process with concurrency control
    semaphore = asyncio.Semaphore(CONCURRENCY)
    updated = 0
    skipped = 0
    failed = 0

    async with httpx.AsyncClient(timeout=30.0) as client:

        async def process_one(item):
            nonlocal updated, skipped, failed
            ecosystem = item.get("ecosystem", "")
            name = item.get("name", "")
            pk = item["pk"]
            downloads = item.get("weekly_downloads", 0)

            async with semaphore:
                try:
                    count, ver = await fetch_dependents_for_package(client, ecosystem, name)

                    if count > 0:
                        if dry_run:
                            logger.info(
                                f"[DRY RUN] {ecosystem}/{name} (downloads={downloads}): "
                                f"would set dependents_count={count} (from {ver})"
                            )
                        else:
                            table.update_item(
                                Key={"pk": pk, "sk": "LATEST"},
                                UpdateExpression="SET dependents_count = :count",
                                ExpressionAttributeValues={":count": count},
                            )
                            logger.info(f"Updated {ecosystem}/{name}: dependents_count={count} (from {ver})")
                        updated += 1
                    else:
                        skipped += 1
                except Exception as e:
                    failed += 1
                    logger.error(f"Failed {ecosystem}/{name}: {e}")

        tasks = [process_one(item) for item in affected]
        await asyncio.gather(*tasks)

    logger.info(f"Backfill complete: {updated} updated, {skipped} skipped, {failed} failed")
    return {"updated": updated, "skipped": skipped, "failed": failed, "total_scanned": len(affected)}


def main():
    parser = argparse.ArgumentParser(description="Backfill dependents_count from deps.dev")
    parser.add_argument("--dry-run", action="store_true", help="Report without updating")
    parser.add_argument("--limit", type=int, default=0, help="Max packages to process (0=all)")
    args = parser.parse_args()

    result = asyncio.run(backfill(dry_run=args.dry_run, limit=args.limit))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
