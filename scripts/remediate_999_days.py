#!/usr/bin/env python3
"""
Remediation script to re-queue packages with days_since_last_commit: 999.

After deploying the pushed_at fallback fix, existing packages with 999 days
still have stale data. This script finds and re-queues them for collection.

Usage:
    python scripts/remediate_999_days.py --dry-run          # Show what would be queued
    python scripts/remediate_999_days.py --limit 100        # Queue up to 100 packages
    python scripts/remediate_999_days.py --ecosystem pypi   # Only PyPI packages
"""

import argparse
import json
import os
import sys

import boto3
from boto3.dynamodb.conditions import Attr

# Configuration
PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
PACKAGE_QUEUE_URL = os.environ.get("PACKAGE_QUEUE_URL")


def get_packages_with_999_days(ecosystem: str = None, limit: int = 100) -> list[dict]:
    """Find packages with days_since_last_commit = 999."""
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(PACKAGES_TABLE)

    filter_expr = Attr("days_since_last_commit").eq(999)
    if ecosystem:
        filter_expr = filter_expr & Attr("pk").begins_with(f"{ecosystem}#")

    packages = []
    scan_kwargs = {
        "FilterExpression": filter_expr,
        "ProjectionExpression": "pk, days_since_last_commit, repository_url, data_status, last_updated",
        "Limit": min(limit * 10, 1000),  # Scan more to account for filter
    }

    while len(packages) < limit:
        response = table.scan(**scan_kwargs)
        items = response.get("Items", [])

        for item in items:
            if len(packages) >= limit:
                break
            packages.append(item)

        # Check for more pages
        if "LastEvaluatedKey" not in response or len(items) == 0:
            break
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    return packages


def queue_for_recollection(packages: list[dict], dry_run: bool = True) -> int:
    """Queue packages for re-collection."""
    if dry_run:
        print(f"\n[DRY RUN] Would queue {len(packages)} packages:\n")
        for pkg in packages[:20]:
            pk = pkg["pk"]
            repo = pkg.get("repository_url", "no repo")
            last_updated = pkg.get("last_updated", "unknown")
            print(f"  - {pk}")
            print(f"    repo: {repo}")
            print(f"    last_updated: {last_updated}")
        if len(packages) > 20:
            print(f"  ... and {len(packages) - 20} more")
        return 0

    if not PACKAGE_QUEUE_URL:
        print("ERROR: PACKAGE_QUEUE_URL environment variable not set")
        print("Set it to the SQS queue URL for package collection")
        sys.exit(1)

    sqs = boto3.client("sqs")
    queued = 0

    for i in range(0, len(packages), 10):
        batch = packages[i:i + 10]
        entries = []

        for j, pkg in enumerate(batch):
            pk = pkg["pk"]
            ecosystem, name = pk.split("#", 1)
            entries.append({
                "Id": str(j),
                "MessageBody": json.dumps({
                    "ecosystem": ecosystem,
                    "name": name,
                    "tier": 2,  # Medium priority
                    "force_refresh": True,
                    "reason": "remediate_999_days",
                }),
                "DelaySeconds": (i // 10) % 60,  # Stagger by 1 second per batch
            })

        try:
            sqs.send_message_batch(QueueUrl=PACKAGE_QUEUE_URL, Entries=entries)
            queued += len(batch)
            print(f"Queued {queued}/{len(packages)}...")
        except Exception as e:
            print(f"ERROR queuing batch: {e}")

    return queued


def main():
    parser = argparse.ArgumentParser(
        description="Re-queue packages with days_since_last_commit: 999"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be queued without actually queuing",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number of packages to process (default: 100)",
    )
    parser.add_argument(
        "--ecosystem",
        choices=["npm", "pypi"],
        help="Only process packages from this ecosystem",
    )
    args = parser.parse_args()

    print("Searching for packages with days_since_last_commit = 999...")
    if args.ecosystem:
        print(f"Filtering by ecosystem: {args.ecosystem}")

    packages = get_packages_with_999_days(
        ecosystem=args.ecosystem,
        limit=args.limit,
    )

    print(f"Found {len(packages)} packages with 999 days")

    if not packages:
        print("No packages to remediate!")
        return

    queued = queue_for_recollection(packages, dry_run=args.dry_run)

    if not args.dry_run:
        print(f"\nSuccessfully queued {queued} packages for re-collection")
        print("Packages will be processed by the collector Lambda")


if __name__ == "__main__":
    main()
