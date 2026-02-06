#!/usr/bin/env python3
"""
Backfill data_status for packages collected before the retry system was deployed.

Scans all packages, identifies incomplete data, and sets:
- data_status: "complete", "partial", or "minimal"
- missing_sources: list of failed sources
- next_retry_at: staggered over 6 hours to prevent thundering herd
"""

import random
from datetime import datetime, timedelta, timezone

import boto3

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("pkgwatch-packages")


def determine_data_status(item: dict) -> tuple[str, list]:
    """Determine data completeness based on current values."""
    missing = []
    ecosystem = item.get("pk", "").split("#")[0] if "#" in item.get("pk", "") else "npm"
    sources = [s for s in item.get("sources", [])]

    # Check deps.dev
    if "deps.dev" not in sources:
        missing.append("deps.dev")

    # Check GitHub - only if package has a repository URL
    repo_url = item.get("repository_url", "")
    if repo_url and "github.com" in repo_url:
        stars = int(item.get("stars", 0) or 0)
        if stars == 0 and "github" not in sources:
            missing.append("github")

    # Check npm/pypi registry data
    weekly_downloads = int(item.get("weekly_downloads", 0) or 0)
    if ecosystem == "npm":
        if weekly_downloads == 0 and "npm" not in sources:
            missing.append("npm")
    elif ecosystem == "pypi":
        if weekly_downloads == 0 and "pypi" not in sources:
            missing.append("pypi")

    # Determine status
    if not missing:
        return ("complete", [])
    elif "deps.dev" in missing:
        return ("minimal", missing)
    return ("partial", missing)


def calculate_next_retry_at(index: int, total: int) -> str:
    """Stagger retries over 6 hours to prevent thundering herd."""
    now = datetime.now(timezone.utc)
    # Spread over 6 hours (21600 seconds)
    offset_seconds = int((index / max(total, 1)) * 21600)
    # Add some jitter (0-5 minutes)
    jitter = random.randint(0, 300)
    return (now + timedelta(seconds=offset_seconds + jitter)).isoformat()


def main():
    print("Scanning packages table...")

    # Scan all packages
    packages = []
    scan_kwargs = {
        "FilterExpression": "sk = :latest AND attribute_not_exists(data_status)",
        "ExpressionAttributeValues": {":latest": "LATEST"},
        "ProjectionExpression": "pk, sk, sources, stars, weekly_downloads, repository_url",
    }

    while True:
        response = table.scan(**scan_kwargs)
        packages.extend(response.get("Items", []))

        if "LastEvaluatedKey" not in response:
            break
        scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
        print(f"  Scanned {len(packages)} packages so far...")

    print(f"\nFound {len(packages)} packages without data_status")

    # Analyze and categorize
    complete = []
    incomplete = []

    for item in packages:
        status, missing = determine_data_status(item)
        if status == "complete":
            complete.append((item, status, missing))
        else:
            incomplete.append((item, status, missing))

    print(f"  Complete: {len(complete)}")
    print(f"  Incomplete: {len(incomplete)}")

    if not packages:
        print("\nNo packages to backfill!")
        return

    # Show sample of incomplete packages
    if incomplete:
        print("\nSample incomplete packages:")
        for item, status, missing in incomplete[:5]:
            pk = item.get("pk", "")
            print(f"  {pk}: {status} - missing {missing}")

    # Confirm before proceeding
    confirm = input(f"\nBackfill {len(packages)} packages? [y/N]: ")
    if confirm.lower() != "y":
        print("Aborted.")
        return

    # Update packages
    updated = 0
    errors = 0

    # Process incomplete packages first (they need next_retry_at)
    for i, (item, status, missing) in enumerate(incomplete):
        pk = item.get("pk")
        try:
            next_retry = calculate_next_retry_at(i, len(incomplete))
            table.update_item(
                Key={"pk": pk, "sk": "LATEST"},
                UpdateExpression="SET data_status = :status, missing_sources = :missing, next_retry_at = :retry, retry_count = :zero",
                ExpressionAttributeValues={
                    ":status": status,
                    ":missing": missing,
                    ":retry": next_retry,
                    ":zero": 0,
                },
            )
            updated += 1
            if updated % 10 == 0:
                print(f"  Updated {updated}/{len(packages)}...")
        except Exception as e:
            print(f"  Error updating {pk}: {e}")
            errors += 1

    # Process complete packages (just set data_status)
    for item, status, missing in complete:
        pk = item.get("pk")
        try:
            table.update_item(
                Key={"pk": pk, "sk": "LATEST"},
                UpdateExpression="SET data_status = :status",
                ExpressionAttributeValues={":status": status},
            )
            updated += 1
            if updated % 10 == 0:
                print(f"  Updated {updated}/{len(packages)}...")
        except Exception as e:
            print(f"  Error updating {pk}: {e}")
            errors += 1

    print(f"\nDone! Updated {updated} packages ({errors} errors)")
    print("Incomplete packages will be retried over the next 6 hours.")


if __name__ == "__main__":
    main()
