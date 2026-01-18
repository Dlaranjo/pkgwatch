#!/usr/bin/env python3
"""Re-dispatch packages that failed validation due to overly strict regex.

Safety features (per opus review):
- Pagination for large result sets
- Rate limiting (max 500/run, 0-15min jitter)
- Idempotency (skip recently updated packages)
- Error handling with failure tracking

Usage:
    # Dry run (default) - shows what would be done
    PYTHONPATH=functions python scripts/redispatch_validation_fixed_packages.py

    # Execute with small batch
    PYTHONPATH=functions python scripts/redispatch_validation_fixed_packages.py \
        --execute --queue-url "$PACKAGE_QUEUE_URL" --max-dispatch 100

    # Execute full migration
    PYTHONPATH=functions python scripts/redispatch_validation_fixed_packages.py \
        --execute --queue-url "$PACKAGE_QUEUE_URL" --max-dispatch 500
"""

import json
import logging
import random
import sys
from datetime import datetime, timedelta, timezone

import boto3

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

sys.path.insert(0, "functions")
from shared.package_validation import validate_npm_package_name

MAX_DISPATCH_PER_RUN = 500
SQS_BATCH_SIZE = 10
SKIP_IF_UPDATED_WITHIN_HOURS = 1


def query_stuck_packages(table, status: str) -> list:
    """Query with pagination (handles >1MB results)."""
    packages = []
    last_key = None

    while True:
        params = {
            "IndexName": "data-status-index-v2",
            "KeyConditionExpression": "data_status = :s",
            "ExpressionAttributeValues": {":s": status},
        }
        if last_key:
            params["ExclusiveStartKey"] = last_key

        response = table.query(**params)
        packages.extend(response.get("Items", []))
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            break

    return packages


def should_redispatch(item: dict) -> bool:
    """Idempotency: skip recently updated or dispatched packages."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=SKIP_IF_UPDATED_WITHIN_HOURS)

    for field in ["last_updated", "retry_dispatched_at"]:
        ts = item.get(field)
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt > cutoff:
                    return False
            except ValueError:
                pass
    return True


def main(dry_run=True, queue_url=None, max_dispatch=MAX_DISPATCH_PER_RUN):
    dynamodb = boto3.resource("dynamodb")
    sqs = boto3.client("sqs")
    table = dynamodb.Table("pkgwatch-packages")

    # Find stuck packages with pagination
    stuck = []
    for status in ["minimal", "abandoned_minimal"]:
        logger.info(f"Querying {status} packages...")
        for item in query_stuck_packages(table, status):
            pk = item.get("pk", "")
            if pk.startswith("npm#") and "#" in pk:
                stuck.append(
                    {
                        "pk": pk,
                        "name": pk.split("#", 1)[1],
                        "last_updated": item.get("last_updated"),
                        "retry_dispatched_at": item.get("retry_dispatched_at"),
                    }
                )

    logger.info(f"Found {len(stuck)} stuck npm packages")

    # Filter: idempotency + validation
    to_redispatch = []
    skipped, invalid = 0, 0
    for pkg in stuck:
        if not should_redispatch(pkg):
            skipped += 1
            continue
        is_valid, _, normalized = validate_npm_package_name(pkg["name"])
        if not is_valid:
            invalid += 1
            continue
        pkg["normalized"] = normalized
        to_redispatch.append(pkg)

    logger.info(f"To dispatch: {len(to_redispatch)}, Skipped (idempotent): {skipped}, Invalid: {invalid}")

    if dry_run:
        logger.info("DRY RUN - no changes will be made")
        for pkg in to_redispatch[:20]:
            print(f"  Would redispatch: {pkg['name']} -> {pkg['normalized']}")
        if len(to_redispatch) > 20:
            print(f"  ... and {len(to_redispatch) - 20} more")
        return

    # Dispatch with rate limiting and batching
    # IMPORTANT: Send to SQS FIRST, then update DynamoDB on success
    # This prevents race condition where DB is updated but SQS send fails
    dispatched, failures = 0, []
    now = datetime.now(timezone.utc)

    for i in range(0, len(to_redispatch), SQS_BATCH_SIZE):
        if dispatched >= max_dispatch:
            logger.info(f"Reached limit ({max_dispatch}), stopping")
            break

        batch = to_redispatch[i : i + SQS_BATCH_SIZE]

        # Build entries for SQS (with index mapping back to batch)
        entries = []
        for j, pkg in enumerate(batch):
            entries.append(
                {
                    "Id": str(j),
                    "MessageBody": json.dumps(
                        {
                            "ecosystem": "npm",
                            "name": pkg["normalized"],
                            "tier": 3,
                            "force_refresh": True,
                            "reason": "validation_fix_migration",
                        }
                    ),
                    "DelaySeconds": random.randint(0, 900),  # 0-15 min jitter
                }
            )

        if not queue_url or not entries:
            continue

        # Send to SQS first
        try:
            resp = sqs.send_message_batch(QueueUrl=queue_url, Entries=entries)
            successful_ids = {msg["Id"] for msg in resp.get("Successful", [])}
            dispatched += len(successful_ids)

            # Update DynamoDB ONLY for successfully queued packages
            for j, pkg in enumerate(batch):
                if str(j) in successful_ids:
                    try:
                        table.update_item(
                            Key={"pk": pkg["pk"], "sk": "LATEST"},
                            UpdateExpression="SET retry_count = :z, data_status = :s, next_retry_at = :now, retry_dispatched_at = :dispatched",
                            ExpressionAttributeValues={
                                ":z": 0,
                                ":s": "minimal",
                                ":now": now.isoformat(),
                                ":dispatched": now.isoformat(),
                            },
                        )
                    except Exception as e:
                        logger.error(f"Failed to update {pkg['pk']} after SQS success: {e}")
                        # Message was sent, so this is not critical - just log it

            for failed in resp.get("Failed", []):
                failures.append({"id": failed["Id"], "error": failed.get("Message", "Unknown")})
        except Exception as e:
            logger.error(f"SQS batch send failed: {e}")
            failures.append({"batch": i, "error": str(e)})

    logger.info(f"Dispatched: {dispatched}, Failures: {len(failures)}")
    if failures:
        print("\nFailures:")
        for f in failures[:10]:
            print(f"  {f}")
        if len(failures) > 10:
            print(f"  ... and {len(failures) - 10} more")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Re-dispatch stuck packages after validation fix")
    parser.add_argument("--execute", action="store_true", help="Actually make changes (default is dry run)")
    parser.add_argument("--queue-url", type=str, help="SQS queue URL (required for execute)")
    parser.add_argument("--max-dispatch", type=int, default=500, help="Maximum packages to dispatch")
    args = parser.parse_args()

    if args.execute and not args.queue_url:
        print("Error: --queue-url is required when using --execute")
        sys.exit(1)

    main(dry_run=not args.execute, queue_url=args.queue_url, max_dispatch=args.max_dispatch)
