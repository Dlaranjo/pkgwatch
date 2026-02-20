"""
Backfill Advisories - One-time script to enrich advisory data for all packages.

Advisory data was never collected correctly during initial pipeline runs, so all
~12,060 packages are missing enriched advisory information (cvss3Score, title,
aliases, url). This script fetches version data from deps.dev to read advisoryKeys,
then fetches each advisory's details and updates DynamoDB directly with enriched
advisory records plus a force_rescore flag.

Usage (run locally -- no Lambda needed):
    PYTHONPATH=functions:. python3 functions/admin/backfill_advisories.py --dry-run
    PYTHONPATH=functions:. python3 functions/admin/backfill_advisories.py
    PYTHONPATH=functions:. python3 functions/admin/backfill_advisories.py --limit 100
"""

import argparse
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
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
CONCURRENCY = 20


def cvss_to_severity(score) -> str:
    """Map a CVSS v3 score to a severity string."""
    if score is None:
        return "UNKNOWN"
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if score <= 0:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


async def fetch_advisories_for_package(
    client: httpx.AsyncClient, ecosystem: str, name: str, latest_version: str
) -> list[dict]:
    """Fetch advisory details for a package version from deps.dev."""
    encoded_name = quote(name, safe="")
    encoded_version = quote(latest_version, safe="")

    # Get version data to read advisoryKeys
    version_url = f"{DEPSDEV_API}/systems/{ecosystem}/packages/{encoded_name}/versions/{encoded_version}"
    try:
        resp = await client.get(version_url)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
    except (httpx.HTTPStatusError, httpx.RequestError) as e:
        logger.warning(f"Failed to fetch version info for {ecosystem}/{name}@{latest_version}: {e}")
        return []

    version_data = resp.json()
    advisory_keys = version_data.get("advisoryKeys", [])

    if not advisory_keys:
        return []

    # Fetch each advisory's details
    advisories = []
    for key_obj in advisory_keys:
        advisory_id = key_obj.get("id", "")
        if not advisory_id:
            continue

        encoded_id = quote(advisory_id, safe="")
        advisory_url = f"{DEPSDEV_API}/advisories/{encoded_id}"
        try:
            adv_resp = await client.get(advisory_url)
            if adv_resp.status_code == 404:
                advisories.append(
                    {
                        "id": advisory_id,
                        "severity": "UNKNOWN",
                    }
                )
                continue
            adv_resp.raise_for_status()
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            logger.warning(f"Failed to fetch advisory {advisory_id}: {e}")
            advisories.append(
                {
                    "id": advisory_id,
                    "severity": "UNKNOWN",
                }
            )
            continue

        adv_data = adv_resp.json()
        cvss_score = adv_data.get("cvss3Score")
        severity = cvss_to_severity(cvss_score)

        advisory_record = {
            "id": advisory_id,
            "severity": severity,
        }
        if cvss_score is not None:
            try:
                advisory_record["cvss3Score"] = float(cvss_score)
            except (TypeError, ValueError):
                pass
        if adv_data.get("title"):
            advisory_record["title"] = adv_data["title"]
        if adv_data.get("aliases"):
            advisory_record["aliases"] = adv_data["aliases"]
        if adv_data.get("url"):
            advisory_record["url"] = adv_data["url"]

        advisories.append(advisory_record)

    return advisories


async def backfill(dry_run: bool = True, limit: int = 0):
    """Scan for all packages and backfill advisory data."""
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(PACKAGES_TABLE)

    # Scan for all LATEST packages
    logger.info("Scanning for all packages with sk=LATEST...")
    packages = []
    scan_kwargs = {
        "FilterExpression": "sk = :sk",
        "ExpressionAttributeValues": {":sk": "LATEST"},
        "ProjectionExpression": "pk, sk, ecosystem, #n, latest_version",
        "ExpressionAttributeNames": {"#n": "name"},
    }

    while True:
        response = table.scan(**scan_kwargs)
        packages.extend(response.get("Items", []))
        if "LastEvaluatedKey" not in response:
            break
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    logger.info(f"Found {len(packages)} packages")

    if limit > 0:
        packages = packages[:limit]
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
            latest_version = item.get("latest_version", "")

            if not latest_version:
                skipped += 1
                logger.debug(f"Skipping {ecosystem}/{name}: no latest_version")
                return

            async with semaphore:
                try:
                    advisories = await fetch_advisories_for_package(client, ecosystem, name, latest_version)

                    if advisories:
                        if dry_run:
                            logger.info(
                                f"[DRY RUN] {ecosystem}/{name}@{latest_version}: would set {len(advisories)} advisories"
                            )
                        else:
                            now = datetime.now(timezone.utc).isoformat()
                            table.update_item(
                                Key={"pk": pk, "sk": "LATEST"},
                                UpdateExpression=(
                                    "SET advisories = :adv, "
                                    "force_rescore = :rescore, "
                                    "rescore_requested_at = :ts, "
                                    "rescore_reason = :reason"
                                ),
                                ExpressionAttributeValues={
                                    ":adv": advisories,
                                    ":rescore": True,
                                    ":ts": now,
                                    ":reason": "advisory_backfill",
                                },
                            )
                            logger.info(f"Updated {ecosystem}/{name}: {len(advisories)} advisories")
                        updated += 1
                    else:
                        skipped += 1
                except Exception as e:
                    failed += 1
                    logger.error(f"Failed {ecosystem}/{name}: {e}")

        tasks = [process_one(item) for item in packages]
        await asyncio.gather(*tasks)

    logger.info(f"Backfill complete: {updated} updated, {skipped} skipped, {failed} failed")
    return {"updated": updated, "skipped": skipped, "failed": failed, "total_scanned": len(packages)}


def main():
    parser = argparse.ArgumentParser(description="Backfill advisory data from deps.dev")
    parser.add_argument("--dry-run", action="store_true", help="Report without updating")
    parser.add_argument("--limit", type=int, default=0, help="Max packages to process (0=all)")
    args = parser.parse_args()

    result = asyncio.run(backfill(dry_run=args.dry_run, limit=args.limit))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
