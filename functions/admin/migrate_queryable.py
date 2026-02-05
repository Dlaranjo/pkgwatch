"""
Migrate Queryable - One-time Lambda to backfill queryable field for existing packages.

This migration scans all packages and computes the queryable field based on:
- latest_version is not None
- health_score is not None
- weekly_downloads > 0 OR dependents_count > 0 OR data_status == "complete"

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

    logger.info(
        f"Starting queryable migration: dry_run={dry_run}, "
        f"batch_size={batch_size}, max_items={max_items}"
    )

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
    }

    # Collect items to update
    updates_pending = []

    # Scan all packages
    scan_kwargs = {
        "ProjectionExpression": "pk, sk, latest_version, health_score, "
        "weekly_downloads, dependents_count, data_status, queryable",
    }

    try:
        paginator = table.meta.client.get_paginator("scan")
        page_iterator = paginator.paginate(TableName=PACKAGES_TABLE, **scan_kwargs)

        for page in page_iterator:
            for item in page.get("Items", []):
                stats["scanned"] += 1

                # Only process LATEST records
                if item.get("sk", {}).get("S") != "LATEST":
                    continue

                # Convert DynamoDB format to regular dict
                pk = item.get("pk", {}).get("S", "")
                current_queryable = item.get("queryable", {}).get("BOOL")
                data_status = item.get("data_status", {}).get("S")

                # Track packages missing data_status
                if data_status is None:
                    stats["missing_data_status"] += 1

                # Build simplified dict for _is_queryable
                simple_item = {
                    "latest_version": item.get("latest_version", {}).get("S"),
                    "health_score": item.get("health_score", {}).get("N"),
                    "weekly_downloads": int(
                        item.get("weekly_downloads", {}).get("N", 0)
                    ),
                    "dependents_count": int(
                        item.get("dependents_count", {}).get("N", 0)
                    ),
                    "data_status": data_status,
                }

                # Convert health_score from string to float if present
                if simple_item["health_score"]:
                    simple_item["health_score"] = float(simple_item["health_score"])

                computed_queryable = _is_queryable(simple_item)

                # Check if update needed
                if current_queryable == computed_queryable:
                    stats["already_correct"] += 1
                else:
                    if computed_queryable:
                        stats["set_to_true"] += 1
                    else:
                        stats["set_to_false"] += 1

                    updates_pending.append(
                        {
                            "pk": pk,
                            "queryable": computed_queryable,
                        }
                    )

                    # Write in batches
                    if not dry_run and len(updates_pending) >= batch_size:
                        _write_batch(table, updates_pending, stats)
                        updates_pending = []

                # Check max_items limit
                if max_items > 0 and stats["scanned"] >= max_items:
                    logger.info(f"Reached max_items limit ({max_items})")
                    break

            # Check max_items limit (outer loop)
            if max_items > 0 and stats["scanned"] >= max_items:
                break

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
                "message": "Migration complete"
                if not dry_run
                else "Dry run complete - no changes made",
            },
            indent=2,
        ),
    }


def _write_batch(table, updates: list, stats: dict):
    """Write a batch of queryable updates to DynamoDB."""
    now = datetime.now(timezone.utc).isoformat()

    for update in updates:
        try:
            table.update_item(
                Key={"pk": update["pk"], "sk": "LATEST"},
                UpdateExpression="SET queryable = :q, queryable_migrated_at = :t",
                ExpressionAttributeValues={
                    ":q": update["queryable"],
                    ":t": now,
                },
            )
            stats["updated"] += 1
        except ClientError as e:
            logger.warning(f"Failed to update {update['pk']}: {e}")
            stats["errors"] += 1

    logger.info(f"Wrote batch of {len(updates)} updates")
