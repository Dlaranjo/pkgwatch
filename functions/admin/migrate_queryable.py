"""
Migrate Queryable - One-time Lambda to backfill queryable, downloads_status, and data_status.

Backfills:
1. queryable - computed from is_queryable() logic
2. downloads_status (PyPI only) - "collected" if downloads_fetched_at exists, else "never_fetched"
3. data_status - "complete", "partial", or "minimal" based on available data

Only sets fields that are currently missing/None. Never overwrites existing values.

Event format:
{
    "dry_run": false,      # If true, report changes without applying them
    "batch_size": 100,     # Items per write batch
    "max_items": 0         # Max items to process (0 = unlimited)
}

Run manually via Lambda console or AWS CLI:
aws lambda invoke --function-name pkgwatch-migrate-queryable \
    --payload '{"dry_run": true}' response.json
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# Import from shared module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../shared"))
from data_quality import is_queryable

# Backward compatibility alias for tests
_is_queryable = is_queryable

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")


def handler(event, context):
    """
    Lambda handler for queryable field migration.

    Scans all packages and updates the queryable field based on current data.
    """
    dry_run = event.get("dry_run", False)
    batch_size = event.get("batch_size", 100)
    max_items = event.get("max_items", 0)

    logger.info(f"Starting queryable migration: dry_run={dry_run}, batch_size={batch_size}, max_items={max_items}")

    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(PACKAGES_TABLE)

    # Track statistics
    stats = {
        "scanned": 0,
        "updated": 0,
        "already_correct": 0,
        "errors": 0,
        "missing_data_status": 0,
        "set_to_true": 0,
        "set_to_false": 0,
        "downloads_status_set": 0,
        "data_status_set": 0,
    }

    # Collect items to update
    updates_pending = []

    # Scan all packages using high-level resource API
    scan_kwargs = {
        "ProjectionExpression": "pk, sk, latest_version, health_score, "
        "weekly_downloads, dependents_count, data_status, queryable, "
        "downloads_fetched_at, downloads_status, ecosystem, missing_sources",
    }

    try:
        done = False
        while not done:
            response = table.scan(**scan_kwargs)

            for item in response.get("Items", []):
                stats["scanned"] += 1

                # Only process LATEST records
                if item.get("sk") != "LATEST":
                    continue

                pk = item.get("pk", "")
                current_queryable = item.get("queryable")
                data_status = item.get("data_status")

                # Track packages missing data_status
                if data_status is None:
                    stats["missing_data_status"] += 1

                # Build simplified dict for _is_queryable
                simple_item = {
                    "latest_version": item.get("latest_version"),
                    "health_score": item.get("health_score"),
                    "weekly_downloads": int(item.get("weekly_downloads", 0)),
                    "dependents_count": int(item.get("dependents_count", 0)),
                    "data_status": data_status,
                }

                # Convert health_score to float if present (DynamoDB stores as Decimal)
                if simple_item["health_score"] is not None:
                    simple_item["health_score"] = float(simple_item["health_score"])

                computed_queryable = _is_queryable(simple_item)

                # Compute downloads_status backfill (PyPI only)
                ecosystem = item.get("ecosystem", "")
                if not ecosystem:
                    # Infer from pk
                    ecosystem = pk.split("#")[0] if "#" in pk else ""
                computed_downloads_status = None
                if ecosystem == "pypi" and not item.get("downloads_status"):
                    if item.get("downloads_fetched_at"):
                        computed_downloads_status = "collected"
                    else:
                        computed_downloads_status = "never_fetched"

                # Compute data_status backfill
                computed_data_status = None
                if not data_status:
                    has_version = item.get("latest_version") is not None
                    has_score = item.get("health_score") is not None
                    has_usage = int(item.get("weekly_downloads", 0)) > 0 or int(item.get("dependents_count", 0)) > 0
                    has_missing = bool(item.get("missing_sources"))

                    if has_version and has_score and has_usage:
                        computed_data_status = "complete"
                    elif has_version and has_score and not has_usage and not has_missing:
                        computed_data_status = "complete"
                    elif has_version and has_score and has_missing:
                        computed_data_status = "partial"
                    else:
                        computed_data_status = "minimal"

                # Build update dict with only changed fields
                update_fields = {}
                if current_queryable != computed_queryable:
                    update_fields["queryable"] = computed_queryable
                    if computed_queryable:
                        stats["set_to_true"] += 1
                    else:
                        stats["set_to_false"] += 1
                else:
                    stats["already_correct"] += 1

                if computed_downloads_status:
                    update_fields["downloads_status"] = computed_downloads_status
                    stats["downloads_status_set"] += 1

                if computed_data_status:
                    update_fields["data_status"] = computed_data_status
                    stats["data_status_set"] += 1

                if update_fields:
                    update_fields["pk"] = pk
                    updates_pending.append(update_fields)

                    # Write in batches
                    if not dry_run and len(updates_pending) >= batch_size:
                        _write_batch(table, updates_pending, stats)
                        updates_pending = []

                # Check max_items limit
                if max_items > 0 and stats["scanned"] >= max_items:
                    logger.info(f"Reached max_items limit ({max_items})")
                    break

            # Check max_items limit or if no more pages
            if max_items > 0 and stats["scanned"] >= max_items:
                break

            # Handle pagination
            last_evaluated_key = response.get("LastEvaluatedKey")
            if last_evaluated_key:
                scan_kwargs["ExclusiveStartKey"] = last_evaluated_key
            else:
                done = True

        # Write remaining updates
        if not dry_run and updates_pending:
            _write_batch(table, updates_pending, stats)

    except ClientError as e:
        logger.error(f"DynamoDB error during scan: {e}")
        stats["errors"] += 1

    # Summary
    logger.info(
        f"Migration complete: scanned={stats['scanned']}, "
        f"updated={stats['updated']}, already_correct={stats['already_correct']}, "
        f"errors={stats['errors']}"
    )

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "dry_run": dry_run,
                "stats": stats,
                "message": "Migration complete" if not dry_run else "Dry run complete - no changes made",
            },
            indent=2,
        ),
    }


def _write_batch(table, updates: list, stats: dict):
    """Write a batch of updates to DynamoDB with dynamic field sets."""
    now = datetime.now(timezone.utc).isoformat()

    for update in updates:
        try:
            set_parts = ["migrated_at = :t"]
            expr_values = {":t": now}

            if "queryable" in update:
                set_parts.append("queryable = :q")
                expr_values[":q"] = update["queryable"]
            if "downloads_status" in update:
                set_parts.append("downloads_status = :ds")
                expr_values[":ds"] = update["downloads_status"]
            if "data_status" in update:
                set_parts.append("data_status = :dst")
                expr_values[":dst"] = update["data_status"]

            table.update_item(
                Key={"pk": update["pk"], "sk": "LATEST"},
                UpdateExpression="SET " + ", ".join(set_parts),
                ExpressionAttributeValues=expr_values,
            )
            stats["updated"] += 1
        except Exception as e:
            logger.warning(f"Failed to update {update['pk']}: {e}")
            stats["errors"] += 1

    logger.info(f"Wrote batch of {len(updates)} updates")
