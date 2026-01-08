"""
Package Collector - Collects data from all sources and stores in DynamoDB.

Triggered by SQS messages from refresh dispatcher.
Orchestrates data collection from:
1. deps.dev (primary - no rate limits)
2. npm registry (supplementary)
3. GitHub (secondary - rate limited)
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import collectors (these will be bundled with the Lambda)
from depsdev_collector import get_package_info as get_depsdev_info
from npm_collector import get_npm_metadata
from github_collector import GitHubCollector, parse_github_url
from bundlephobia_collector import get_bundle_size

dynamodb = boto3.resource("dynamodb")
s3 = boto3.client("s3")
secretsmanager = boto3.client("secretsmanager")

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "dephealth-packages")
RAW_DATA_BUCKET = os.environ.get("RAW_DATA_BUCKET", "dephealth-raw-data")
GITHUB_TOKEN_SECRET_ARN = os.environ.get("GITHUB_TOKEN_SECRET_ARN")


def get_github_token() -> Optional[str]:
    """Retrieve GitHub token from Secrets Manager."""
    if not GITHUB_TOKEN_SECRET_ARN:
        logger.warning("GITHUB_TOKEN_SECRET_ARN not configured")
        return None

    try:
        response = secretsmanager.get_secret_value(SecretId=GITHUB_TOKEN_SECRET_ARN)
        secret_string = response["SecretString"]

        # Try to parse as JSON (e.g., {"token": "ghp_..."})
        try:
            secret = json.loads(secret_string)
            return secret.get("token") or secret_string
        except json.JSONDecodeError:
            # Plain string token (e.g., "ghp_...")
            return secret_string

    except ClientError as e:
        logger.error(f"Failed to retrieve GitHub token: {e}")
        return None


async def collect_package_data(ecosystem: str, name: str) -> dict:
    """
    Collect comprehensive package data from all sources.

    Order of operations:
    1. deps.dev (primary) - always fetch
    2. npm (supplementary) - always fetch for npm packages
    3. GitHub (secondary) - only if we have a repo URL and rate limit allows

    Returns:
        Combined package data dictionary
    """
    combined_data = {
        "ecosystem": ecosystem,
        "name": name,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "sources": [],
    }

    # 1. deps.dev data (primary source)
    try:
        depsdev_data = await get_depsdev_info(name, ecosystem)
        combined_data["depsdev"] = depsdev_data
        combined_data["sources"].append("deps.dev")

        # Copy primary fields
        combined_data["latest_version"] = depsdev_data.get("latest_version")
        combined_data["published_at"] = depsdev_data.get("published_at")
        combined_data["licenses"] = depsdev_data.get("licenses")
        combined_data["dependencies_direct"] = depsdev_data.get("dependencies_direct")
        combined_data["advisories"] = depsdev_data.get("advisories", [])
        combined_data["openssf_score"] = depsdev_data.get("openssf_score")
        combined_data["openssf_checks"] = depsdev_data.get("openssf_checks", [])
        combined_data["dependents_count"] = depsdev_data.get("dependents_count", 0)
        combined_data["repository_url"] = depsdev_data.get("repository_url")

    except Exception as e:
        logger.error(f"Failed to fetch deps.dev data for {ecosystem}/{name}: {e}")
        combined_data["depsdev_error"] = str(e)

    # 2. npm data (supplementary for npm packages)
    if ecosystem == "npm":
        try:
            npm_data = await get_npm_metadata(name)
            combined_data["npm"] = npm_data
            combined_data["sources"].append("npm")

            # Supplement with npm-specific data
            combined_data["weekly_downloads"] = npm_data.get("weekly_downloads", 0)
            combined_data["maintainers"] = npm_data.get("maintainers", [])
            combined_data["maintainer_count"] = npm_data.get("maintainer_count", 0)
            combined_data["is_deprecated"] = npm_data.get("is_deprecated", False)
            combined_data["deprecation_message"] = npm_data.get("deprecation_message")
            combined_data["created_at"] = npm_data.get("created_at")
            combined_data["last_published"] = npm_data.get("last_published")
            # TypeScript and module system
            combined_data["has_types"] = npm_data.get("has_types", False)
            combined_data["module_type"] = npm_data.get("module_type", "commonjs")
            combined_data["has_exports"] = npm_data.get("has_exports", False)
            combined_data["engines"] = npm_data.get("engines")

            # Use npm repo URL as fallback
            if not combined_data.get("repository_url"):
                combined_data["repository_url"] = npm_data.get("repository_url")

        except Exception as e:
            logger.error(f"Failed to fetch npm data for {name}: {e}")
            combined_data["npm_error"] = str(e)

    # 3. GitHub data (secondary - rate limited)
    repo_url = combined_data.get("repository_url")
    if repo_url:
        parsed = parse_github_url(repo_url)
        if parsed:
            owner, repo = parsed
            try:
                github_token = get_github_token()
                github_collector = GitHubCollector(token=github_token)
                github_data = await github_collector.get_repo_metrics(owner, repo)

                if "error" not in github_data:
                    combined_data["github"] = github_data
                    combined_data["sources"].append("github")

                    # Supplement with GitHub-specific data
                    combined_data["stars"] = github_data.get("stars", 0)
                    combined_data["forks"] = github_data.get("forks", 0)
                    combined_data["open_issues"] = github_data.get("open_issues", 0)
                    combined_data["days_since_last_commit"] = github_data.get(
                        "days_since_last_commit"
                    )
                    combined_data["commits_90d"] = github_data.get("commits_90d", 0)
                    combined_data["active_contributors_90d"] = github_data.get(
                        "active_contributors_90d", 0
                    )
                    combined_data["total_contributors"] = github_data.get(
                        "total_contributors", 0
                    )
                    combined_data["archived"] = github_data.get("archived", False)
                else:
                    combined_data["github_error"] = github_data["error"]

            except Exception as e:
                logger.error(f"Failed to fetch GitHub data for {owner}/{repo}: {e}")
                combined_data["github_error"] = str(e)

    # 4. Bundlephobia data (bundle size - for npm packages only)
    if ecosystem == "npm":
        try:
            bundle_data = await get_bundle_size(name)
            if "error" not in bundle_data:
                combined_data["bundlephobia"] = bundle_data
                combined_data["sources"].append("bundlephobia")
                # Copy key bundle size fields
                combined_data["bundle_size"] = bundle_data.get("size", 0)
                combined_data["bundle_size_gzip"] = bundle_data.get("gzip", 0)
                combined_data["bundle_size_category"] = bundle_data.get("size_category")
                combined_data["bundle_dependency_count"] = bundle_data.get(
                    "dependency_count", 0
                )
            else:
                combined_data["bundlephobia_error"] = bundle_data.get("error")
        except Exception as e:
            logger.warning(f"Failed to fetch bundle size for {name}: {e}")
            combined_data["bundlephobia_error"] = str(e)

    return combined_data


def store_raw_data(ecosystem: str, name: str, data: dict):
    """Store raw collected data in S3 for debugging."""
    try:
        key = f"{ecosystem}/{name}/{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.json"
        s3.put_object(
            Bucket=RAW_DATA_BUCKET,
            Key=key,
            Body=json.dumps(data, indent=2, default=str),
            ContentType="application/json",
        )
        logger.debug(f"Stored raw data: s3://{RAW_DATA_BUCKET}/{key}")
    except Exception as e:
        logger.warning(f"Failed to store raw data: {e}")


def store_package_data(ecosystem: str, name: str, data: dict, tier: int):
    """Store processed package data in DynamoDB."""
    table = dynamodb.Table(PACKAGES_TABLE)

    now = datetime.now(timezone.utc).isoformat()

    item = {
        "pk": f"{ecosystem}#{name}",
        "sk": "LATEST",
        "ecosystem": ecosystem,
        "name": name,
        "tier": tier,
        "last_updated": now,
        # Core data
        "latest_version": data.get("latest_version"),
        "created_at": data.get("created_at"),
        "last_published": data.get("last_published"),
        # Health signals
        "weekly_downloads": data.get("weekly_downloads", 0),
        "dependents_count": data.get("dependents_count", 0),
        "stars": data.get("stars", 0),
        "forks": data.get("forks", 0),
        "open_issues": data.get("open_issues", 0),
        "maintainer_count": data.get("maintainer_count", 0),
        "days_since_last_commit": data.get("days_since_last_commit"),
        "commits_90d": data.get("commits_90d", 0),
        "active_contributors_90d": data.get("active_contributors_90d", 0),
        "total_contributors": data.get("total_contributors", 0),
        # Security
        "advisories": data.get("advisories", []),
        "openssf_score": data.get("openssf_score"),
        # Status flags
        "is_deprecated": data.get("is_deprecated", False),
        "archived": data.get("archived", False),
        # TypeScript and module system (DX signals)
        "has_types": data.get("has_types", False),
        "module_type": data.get("module_type", "commonjs"),
        "has_exports": data.get("has_exports", False),
        "engines": data.get("engines"),
        # Bundle size (DX signals)
        "bundle_size": data.get("bundle_size"),
        "bundle_size_gzip": data.get("bundle_size_gzip"),
        "bundle_size_category": data.get("bundle_size_category"),
        "bundle_dependency_count": data.get("bundle_dependency_count"),
        # Metadata
        "repository_url": data.get("repository_url"),
        "licenses": data.get("licenses", []),
        "sources": data.get("sources", []),
    }

    # Remove None values (DynamoDB doesn't like them)
    item = {k: v for k, v in item.items() if v is not None}

    try:
        table.put_item(Item=item)
        logger.info(f"Stored package data: {ecosystem}/{name}")
    except Exception as e:
        logger.error(f"Failed to store package data: {e}")
        raise


def handler(event, context):
    """
    Lambda handler for package collector.

    Triggered by SQS messages with format:
    {
        "ecosystem": "npm",
        "name": "lodash",
        "tier": 1,
        "reason": "daily_refresh"
    }
    """
    logger.info(f"Processing {len(event.get('Records', []))} messages")

    successes = 0
    failures = 0

    for record in event.get("Records", []):
        try:
            message = json.loads(record["body"])
            ecosystem = message["ecosystem"]
            name = message["name"]
            tier = message.get("tier", 3)

            logger.info(f"Collecting data for {ecosystem}/{name} (tier {tier})")

            # Collect data from all sources
            # Use asyncio.run() which is the recommended pattern for Python 3.7+
            # and works correctly in Python 3.12+
            data = asyncio.run(collect_package_data(ecosystem, name))

            # Store raw data in S3 for debugging
            store_raw_data(ecosystem, name, data)

            # Store processed data in DynamoDB
            store_package_data(ecosystem, name, data, tier)

            successes += 1

        except Exception as e:
            logger.error(f"Failed to process message: {e}")
            failures += 1
            # Don't raise - let SQS handle retries via DLQ

    logger.info(f"Completed: {successes} successes, {failures} failures")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "processed": successes + failures,
            "successes": successes,
            "failures": failures,
        }),
    }
