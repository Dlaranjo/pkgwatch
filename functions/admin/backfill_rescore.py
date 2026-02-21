"""
Backfill Rescore - One-time script to trigger rescoring for all packages.

After scoring formula changes, all packages need rescoring. This script sets
force_rescore=True on every LATEST item, which triggers DynamoDB Streams →
score_package.py to recalculate with the new formula.

Usage (run locally -- no Lambda needed):
    PYTHONPATH=functions:. python3 functions/admin/backfill_rescore.py --dry-run
    PYTHONPATH=functions:. python3 functions/admin/backfill_rescore.py
    PYTHONPATH=functions:. python3 functions/admin/backfill_rescore.py --limit 100
"""

import argparse
import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import boto3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
CONCURRENCY = 50


async def backfill(dry_run: bool = True, limit: int = 0):
    """Scan all packages and set force_rescore flag."""
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(PACKAGES_TABLE)

    # Scan for all LATEST packages
    logger.info("Scanning for all packages with sk=LATEST...")
    packages = []
    scan_kwargs = {
        "FilterExpression": "sk = :sk",
        "ExpressionAttributeValues": {":sk": "LATEST"},
        "ProjectionExpression": "pk, sk, ecosystem, #n",
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
    failed = 0

    async def process_one(item):
        nonlocal updated, failed
        ecosystem = item.get("ecosystem", "")
        name = item.get("name", "")
        pk = item["pk"]

        async with semaphore:
            try:
                if dry_run:
                    logger.info(f"[DRY RUN] {ecosystem}/{name}: would set force_rescore=True")
                else:
                    now = datetime.now(timezone.utc).isoformat()
                    table.update_item(
                        Key={"pk": pk, "sk": "LATEST"},
                        UpdateExpression=(
                            "SET force_rescore = :rescore, rescore_requested_at = :ts, rescore_reason = :reason"
                        ),
                        ExpressionAttributeValues={
                            ":rescore": True,
                            ":ts": now,
                            ":reason": "scoring_recalibration",
                        },
                    )
                    logger.info(f"Flagged {ecosystem}/{name} for rescore")
                updated += 1
            except Exception as e:
                failed += 1
                logger.error(f"Failed {ecosystem}/{name}: {e}")

    tasks = [process_one(item) for item in packages]
    await asyncio.gather(*tasks)

    logger.info(f"Rescore backfill complete: {updated} flagged, {failed} failed")
    return {"flagged": updated, "failed": failed, "total_scanned": len(packages)}


def main():
    parser = argparse.ArgumentParser(description="Trigger rescoring for all packages")
    parser.add_argument("--dry-run", action="store_true", help="Report without updating")
    parser.add_argument("--limit", type=int, default=0, help="Max packages to process (0=all)")
    args = parser.parse_args()

    result = asyncio.run(backfill(dry_run=args.dry_run, limit=args.limit))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
