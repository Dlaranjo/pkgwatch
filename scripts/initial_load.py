#!/usr/bin/env python3
"""
Initial Load Script

Loads selected packages into DynamoDB and triggers initial data collection.
Used for bootstrapping the MVP with the first 2,500 packages.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

import boto3

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "functions"))

from collectors.depsdev_collector import get_package_info
from collectors.npm_collector import get_npm_metadata
from collectors.github_collector import GitHubCollector, parse_github_url
from scoring.health_score import calculate_health_score
from scoring.abandonment_risk import calculate_abandonment_risk

dynamodb = boto3.resource("dynamodb")
sqs = boto3.client("sqs")


async def collect_and_score_package(
    name: str,
    ecosystem: str = "npm",
    github_collector: GitHubCollector = None,
) -> dict:
    """
    Collect all data for a package and calculate scores.
    """
    data = {
        "ecosystem": ecosystem,
        "name": name,
        "sources": [],
    }

    # 1. deps.dev
    try:
        depsdev = await get_package_info(name, ecosystem)
        data.update({
            "latest_version": depsdev.get("latest_version"),
            "published_at": depsdev.get("published_at"),
            "licenses": depsdev.get("licenses"),
            "dependencies_direct": depsdev.get("dependencies_direct"),
            "advisories": depsdev.get("advisories", []),
            "openssf_score": depsdev.get("openssf_score"),
            "dependents_count": depsdev.get("dependents_count", 0),
            "repository_url": depsdev.get("repository_url"),
            "stars": depsdev.get("stars"),
            "forks": depsdev.get("forks"),
        })
        data["sources"].append("deps.dev")
    except Exception as e:
        print(f"  deps.dev error: {e}")

    # 2. npm
    if ecosystem == "npm":
        try:
            npm = await get_npm_metadata(name)
            data.update({
                "weekly_downloads": npm.get("weekly_downloads", 0),
                "maintainers": npm.get("maintainers", []),
                "maintainer_count": npm.get("maintainer_count", 0),
                "is_deprecated": npm.get("is_deprecated", False),
                "deprecation_message": npm.get("deprecation_message"),
                "created_at": npm.get("created_at"),
                "last_published": npm.get("last_published"),
            })
            if not data.get("repository_url"):
                data["repository_url"] = npm.get("repository_url")
            data["sources"].append("npm")
        except Exception as e:
            print(f"  npm error: {e}")

    # 3. GitHub (if we have a repo URL and collector)
    repo_url = data.get("repository_url")
    if repo_url and github_collector:
        parsed = parse_github_url(repo_url)
        if parsed:
            owner, repo = parsed
            try:
                github = await github_collector.get_repo_metrics(owner, repo)
                if "error" not in github:
                    data.update({
                        "stars": github.get("stars", 0),
                        "forks": github.get("forks", 0),
                        "open_issues": github.get("open_issues", 0),
                        "days_since_last_commit": github.get("days_since_last_commit"),
                        "commits_90d": github.get("commits_90d", 0),
                        "active_contributors_90d": github.get("active_contributors_90d", 0),
                        "total_contributors": github.get("total_contributors", 0),
                        "archived": github.get("archived", False),
                    })
                    data["sources"].append("github")
            except Exception as e:
                print(f"  github error: {e}")

    # Calculate scores
    health = calculate_health_score(data)
    abandonment = calculate_abandonment_risk(data)

    data.update({
        "health_score": health["health_score"],
        "risk_level": health["risk_level"],
        "score_components": health["components"],
        "confidence": health["confidence"],
        "abandonment_risk": abandonment,
    })

    return data


def convert_floats_to_decimal(obj):
    """Recursively convert floats to Decimals for DynamoDB."""
    from decimal import Decimal

    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: convert_floats_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_floats_to_decimal(item) for item in obj]
    return obj


def store_package(table_name: str, data: dict, tier: int):
    """Store package in DynamoDB."""
    from datetime import datetime, timezone

    table = dynamodb.Table(table_name)

    item = {
        "pk": f"{data['ecosystem']}#{data['name']}",
        "sk": "LATEST",
        "tier": tier,
        "last_updated": datetime.now(timezone.utc).isoformat(),
        **{k: v for k, v in data.items() if v is not None},
    }

    # Convert floats to Decimals for DynamoDB
    item = convert_floats_to_decimal(item)

    table.put_item(Item=item)


async def load_packages(
    packages_file: str,
    table_name: str,
    github_token: str = None,
    limit: int = None,
    skip: int = 0,
):
    """
    Load packages from JSON file into DynamoDB.
    """
    # Load package list
    with open(packages_file) as f:
        data = json.load(f)

    packages = data.get("packages", data)
    if isinstance(packages, dict):
        packages = list(packages.values())

    # Apply skip and limit
    packages = packages[skip:]
    if limit:
        packages = packages[:limit]

    print(f"Loading {len(packages)} packages...")

    # Initialize GitHub collector if token provided
    github_collector = GitHubCollector(token=github_token) if github_token else None

    success = 0
    errors = 0

    for i, pkg in enumerate(packages):
        name = pkg.get("name") if isinstance(pkg, dict) else pkg
        tier = pkg.get("tier", 3) if isinstance(pkg, dict) else 3

        print(f"[{i+1}/{len(packages)}] {name}...", end=" ", flush=True)

        try:
            data = await collect_and_score_package(
                name,
                ecosystem="npm",
                github_collector=github_collector,
            )
            store_package(table_name, data, tier)
            print(f"score={data.get('health_score', 'N/A')}")
            success += 1

        except Exception as e:
            print(f"ERROR: {e}")
            errors += 1

        # Rate limiting pause
        if github_collector and (i + 1) % 10 == 0:
            remaining = github_collector.rate_limit_remaining
            if remaining < 100:
                print(f"  Rate limit low ({remaining}), pausing...")
                await asyncio.sleep(60)

    print(f"\nCompleted: {success} success, {errors} errors")


async def main():
    import argparse

    parser = argparse.ArgumentParser(description="Load packages into DynamoDB")
    parser.add_argument(
        "--packages",
        type=str,
        default="packages.json",
        help="Package list JSON file",
    )
    parser.add_argument(
        "--table",
        type=str,
        default="pkgwatch-packages",
        help="DynamoDB table name",
    )
    parser.add_argument(
        "--github-token",
        type=str,
        default=os.environ.get("GITHUB_TOKEN"),
        help="GitHub personal access token",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of packages to load",
    )
    parser.add_argument(
        "--skip",
        type=int,
        default=0,
        help="Skip first N packages",
    )
    args = parser.parse_args()

    await load_packages(
        packages_file=args.packages,
        table_name=args.table,
        github_token=args.github_token,
        limit=args.limit,
        skip=args.skip,
    )


if __name__ == "__main__":
    asyncio.run(main())
