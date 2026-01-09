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
import random
import re
import time
from datetime import datetime, timezone
from typing import Optional, Tuple

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import collectors (these will be bundled with the Lambda)
from depsdev_collector import get_package_info as get_depsdev_info
from npm_collector import get_npm_metadata
from github_collector import GitHubCollector, parse_github_url
from bundlephobia_collector import get_bundle_size

# Import shared utilities
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../shared"))
from metrics import emit_metric, emit_batch_metrics

dynamodb = boto3.resource("dynamodb")
s3 = boto3.client("s3")
secretsmanager = boto3.client("secretsmanager")

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "dephealth-packages")
RAW_DATA_BUCKET = os.environ.get("RAW_DATA_BUCKET", "dephealth-raw-data")
GITHUB_TOKEN_SECRET_ARN = os.environ.get("GITHUB_TOKEN_SECRET_ARN")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "dephealth-api-keys")

# Configurable thresholds
STALE_DATA_MAX_AGE_DAYS = int(os.environ.get("STALE_DATA_MAX_AGE_DAYS", "7"))
DEDUP_WINDOW_MINUTES = int(os.environ.get("DEDUP_WINDOW_MINUTES", "30"))

# Semaphore to limit concurrent GitHub API calls per Lambda instance
# With maxConcurrency=10 Lambdas * 5 = max 50 concurrent GitHub calls
# GitHub allows 5000/hour = ~83/minute, so this keeps us well under the limit
GITHUB_SEMAPHORE = asyncio.Semaphore(5)

# Global rate limiting with sharded counters
# Distributes writes across 10 partitions to avoid hot partition issues
RATE_LIMIT_SHARDS = 10
GITHUB_HOURLY_LIMIT = 4000  # Leave buffer from 5000/hour limit

# Valid npm package name pattern
# Scoped: @scope/package-name
# Unscoped: package-name
NPM_PACKAGE_PATTERN = re.compile(
    r'^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$'
)

# Maximum package name length per npm
MAX_PACKAGE_NAME_LENGTH = 214


def validate_message(body: dict) -> Tuple[bool, Optional[str]]:
    """
    Validate SQS message body.

    Args:
        body: Parsed message body

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check required fields
    ecosystem = body.get("ecosystem")
    name = body.get("name")

    if not ecosystem:
        return False, "Missing 'ecosystem' field"

    if not name:
        return False, "Missing 'name' field"

    # Validate ecosystem
    if ecosystem not in ["npm"]:  # Add more as supported
        return False, f"Unsupported ecosystem: {ecosystem}"

    # Validate package name
    if len(name) > MAX_PACKAGE_NAME_LENGTH:
        return False, f"Package name too long: {len(name)} > {MAX_PACKAGE_NAME_LENGTH}"

    # Check for path traversal attempts first (security check)
    if ".." in name or name.startswith("/"):
        return False, "Invalid package name (path traversal detected)"

    if not NPM_PACKAGE_PATTERN.match(name):
        return False, "Invalid package name format"

    return True, None


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


def _get_rate_limit_window_key() -> str:
    """Get the current hourly window key for rate limiting."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d-%H")


def _get_total_github_calls(window_key: str) -> int:
    """Sum calls across all shards for the window."""
    table = dynamodb.Table(API_KEYS_TABLE)
    total = 0

    for shard_id in range(RATE_LIMIT_SHARDS):
        try:
            response = table.get_item(
                Key={"pk": f"github_rate_limit#{shard_id}", "sk": window_key},
                ProjectionExpression="calls",
            )
            total += response.get("Item", {}).get("calls", 0)
        except ClientError as e:
            logger.debug(f"Shard {shard_id} not found or error: {e}")
            pass  # Shard doesn't exist yet

    return total


def _check_and_increment_github_rate_limit() -> bool:
    """
    Atomically check and increment GitHub rate limit.

    Uses conditional expression to prevent race conditions.
    Each shard has its own limit to distribute load.

    Returns:
        True if request is allowed, False if rate limit exceeded.
    """
    table = dynamodb.Table(API_KEYS_TABLE)
    now = datetime.now(timezone.utc)
    window_key = _get_rate_limit_window_key()
    shard_id = random.randint(0, RATE_LIMIT_SHARDS - 1)

    # Per-shard limit with buffer for edge cases
    per_shard_limit = (GITHUB_HOURLY_LIMIT // RATE_LIMIT_SHARDS) + 50

    ttl = int(now.timestamp()) + 7200  # 2 hour TTL

    try:
        # Atomic increment with conditional check
        table.update_item(
            Key={
                "pk": f"github_rate_limit#{shard_id}",
                "sk": window_key,
            },
            UpdateExpression="SET calls = if_not_exists(calls, :zero) + :one, #ttl = :ttl",
            ConditionExpression="attribute_not_exists(calls) OR calls < :limit",
            ExpressionAttributeNames={"#ttl": "ttl"},
            ExpressionAttributeValues={
                ":zero": 0,
                ":one": 1,
                ":limit": per_shard_limit,
                ":ttl": ttl,
            },
        )
        return True

    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Rate limit exceeded for this shard
            logger.warning(
                f"GitHub rate limit exceeded",
                extra={
                    "shard_id": shard_id,
                    "window_key": window_key,
                    "per_shard_limit": per_shard_limit,
                }
            )
            return False

        logger.error(f"DynamoDB error in rate limit check: {e}")
        # Fail closed for safety
        return False


async def _get_existing_package_data(ecosystem: str, name: str) -> Optional[dict]:
    """Get existing package data from DynamoDB."""
    table = dynamodb.Table(PACKAGES_TABLE)
    try:
        response = table.get_item(Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"})
        return response.get("Item")
    except Exception as e:
        logger.error(f"Failed to get existing data: {e}")
        return None


def _is_data_acceptable(data: dict, max_age_days: int) -> bool:
    """Check if existing data is fresh enough to use as fallback."""
    if not data:
        return False

    last_updated = data.get("last_updated")
    if not last_updated:
        return False

    try:
        updated_dt = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
        age = datetime.now(timezone.utc) - updated_dt
        return age.days <= max_age_days
    except Exception:
        return False


def _extract_cached_fields(existing: dict) -> dict:
    """Extract fields from cached data for fallback."""
    return {
        "latest_version": existing.get("latest_version"),
        "published_at": existing.get("published_at"),
        "licenses": existing.get("licenses"),
        "dependencies_direct": existing.get("dependencies_direct"),
        "advisories": existing.get("advisories", []),
        "openssf_score": existing.get("openssf_score"),
        "openssf_checks": existing.get("openssf_checks", []),
        "dependents_count": existing.get("dependents_count", 0),
        "repository_url": existing.get("repository_url"),
    }


async def collect_package_data(ecosystem: str, name: str) -> dict:
    """
    Collect comprehensive package data from all sources with graceful degradation.

    Order of operations:
    1. deps.dev (primary) - always fetch, fallback to stale data if fails
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
        "data_freshness": "fresh",
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

        # Try to use stale data as fallback
        existing = await _get_existing_package_data(ecosystem, name)
        if existing and _is_data_acceptable(existing, max_age_days=STALE_DATA_MAX_AGE_DAYS):
            logger.info(f"Using stale data for {ecosystem}/{name}")
            combined_data.update(_extract_cached_fields(existing))
            combined_data["data_freshness"] = "stale"
            combined_data["stale_reason"] = "deps.dev_unavailable"

    # 2. npm and bundlephobia data (run in parallel - they don't depend on each other)
    if ecosystem == "npm":
        # Start both requests concurrently
        npm_task = get_npm_metadata(name)
        bundle_task = get_bundle_size(name)
        npm_result, bundle_result = await asyncio.gather(
            npm_task, bundle_task, return_exceptions=True
        )

        # Process npm result
        if isinstance(npm_result, Exception):
            logger.error(f"Failed to fetch npm data for {name}: {npm_result}")
            combined_data["npm_error"] = str(npm_result)
        else:
            npm_data = npm_result
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

        # Process bundlephobia result
        if isinstance(bundle_result, Exception):
            logger.warning(f"Failed to fetch bundle size for {name}: {bundle_result}")
            combined_data["bundlephobia_error"] = str(bundle_result)
        else:
            bundle_data = bundle_result
            if "error" not in bundle_data:
                combined_data["bundlephobia"] = bundle_data
                combined_data["sources"].append("bundlephobia")
                combined_data["bundle_size"] = bundle_data.get("size", 0)
                combined_data["bundle_size_gzip"] = bundle_data.get("gzip", 0)
                combined_data["bundle_size_category"] = bundle_data.get("size_category")
                combined_data["bundle_dependency_count"] = bundle_data.get(
                    "dependency_count", 0
                )
            else:
                combined_data["bundlephobia_error"] = bundle_data.get("error")

    # 3. GitHub data (secondary - rate limited)
    repo_url = combined_data.get("repository_url")
    if repo_url:
        parsed = parse_github_url(repo_url)
        if parsed:
            owner, repo = parsed
            try:
                # Use semaphore to limit concurrent GitHub API calls per Lambda instance
                # AND global rate limiter to coordinate across all Lambda instances
                async with GITHUB_SEMAPHORE:
                    # Check global rate limit before making GitHub API call
                    if not _check_and_increment_github_rate_limit():
                        logger.warning(
                            f"Skipping GitHub for {ecosystem}/{name} - global rate limit"
                        )
                        combined_data["github_error"] = "rate_limit_exceeded"
                    else:
                        github_token = get_github_token()
                        github_collector = GitHubCollector(token=github_token)
                        github_data = await github_collector.get_repo_metrics(
                            owner, repo
                        )

                        if "error" not in github_data:
                            combined_data["github"] = github_data
                            combined_data["sources"].append("github")

                            # Supplement with GitHub-specific data
                            combined_data["stars"] = github_data.get("stars", 0)
                            combined_data["forks"] = github_data.get("forks", 0)
                            combined_data["open_issues"] = github_data.get(
                                "open_issues", 0
                            )
                            combined_data["days_since_last_commit"] = github_data.get(
                                "days_since_last_commit"
                            )
                            combined_data["commits_90d"] = github_data.get(
                                "commits_90d", 0
                            )
                            combined_data["active_contributors_90d"] = github_data.get(
                                "active_contributors_90d", 0
                            )
                            combined_data["total_contributors"] = github_data.get(
                                "total_contributors", 0
                            )
                            # True bus factor (contribution distribution analysis)
                            combined_data["true_bus_factor"] = github_data.get(
                                "true_bus_factor", 1
                            )
                            combined_data["bus_factor_confidence"] = github_data.get(
                                "bus_factor_confidence", "LOW"
                            )
                            combined_data[
                                "contribution_distribution"
                            ] = github_data.get("contribution_distribution", [])
                            combined_data["archived"] = github_data.get(
                                "archived", False
                            )
                        else:
                            combined_data["github_error"] = github_data["error"]

            except Exception as e:
                logger.error(f"Failed to fetch GitHub data for {owner}/{repo}: {e}")
                combined_data["github_error"] = str(e)

    # Note: Bundlephobia is now fetched in parallel with npm data in section 2

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
        # True bus factor (contribution distribution analysis)
        "true_bus_factor": data.get("true_bus_factor"),
        "bus_factor_confidence": data.get("bus_factor_confidence"),
        "contribution_distribution": data.get("contribution_distribution", []),
        # Security
        "advisories": data.get("advisories", []),
        "openssf_score": data.get("openssf_score"),
        "openssf_checks": data.get("openssf_checks", []),
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
        "data_freshness": data.get("data_freshness", "fresh"),
        "stale_reason": data.get("stale_reason"),
    }

    # Remove None values (DynamoDB doesn't like them)
    item = {k: v for k, v in item.items() if v is not None}

    try:
        table.put_item(Item=item)
        logger.info(f"Stored package data: {ecosystem}/{name}")
    except Exception as e:
        logger.error(f"Failed to store package data: {e}")
        raise


async def process_single_package(message: dict) -> tuple[bool, str, Optional[str]]:
    """Process a single package message with deduplication.

    Returns:
        Tuple of (success: bool, package_name: str, error_reason: Optional[str])
    """
    # Validate input
    is_valid, error = validate_message(message)
    if not is_valid:
        logger.warning(f"Invalid message: {error}", extra={"body": message})
        return (False, f"validation_error: {error}", "validation_error")

    ecosystem = message["ecosystem"]
    name = message["name"]
    tier = message.get("tier", 3)

    # Check if recently collected (deduplication)
    existing = await _get_existing_package_data(ecosystem, name)
    if existing:
        last_updated = existing.get("last_updated")
        if last_updated:
            try:
                updated_dt = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
                age_minutes = (datetime.now(timezone.utc) - updated_dt).total_seconds() / 60

                if age_minutes < DEDUP_WINDOW_MINUTES:
                    logger.info(f"Skipping {ecosystem}/{name} - recently updated ({age_minutes:.0f}m ago)")
                    return (True, f"{ecosystem}/{name}", None)  # Success - no action needed
            except Exception as e:
                logger.debug(f"Failed to parse last_updated: {e}")

    logger.info(f"Collecting data for {ecosystem}/{name} (tier {tier})")

    try:
        # Collect data from all sources
        data = await collect_package_data(ecosystem, name)

        # Store raw data in S3 for debugging
        store_raw_data(ecosystem, name, data)

        # Store processed data in DynamoDB
        store_package_data(ecosystem, name, data, tier)

        return (True, f"{ecosystem}/{name}", None)
    except Exception as e:
        logger.error(f"Failed to process {ecosystem}/{name}: {e}")
        error_type = type(e).__name__
        return (False, f"{ecosystem}/{name}", error_type)


async def process_batch(records: list) -> tuple[int, int]:
    """Process a batch of SQS records in parallel with metrics.

    Returns:
        Tuple of (successes, failures)
    """
    start_time = time.time()
    tasks = []
    messages = []

    for record in records:
        try:
            message = json.loads(record["body"])
            messages.append(message)
            tasks.append(process_single_package(message))
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse message: {e}")
            emit_metric("MessageParseError")

    # Process all packages in parallel with return_exceptions=True
    # to prevent one failure from canceling others
    results = await asyncio.gather(*tasks, return_exceptions=True)

    successes = 0
    failures = 0
    failure_reasons = {}

    for i, result in enumerate(results):
        message = messages[i] if i < len(messages) else {}
        ecosystem = message.get("ecosystem", "unknown")

        if isinstance(result, Exception):
            logger.error(f"Task failed with exception: {result}")
            failures += 1
            error_type = type(result).__name__
            failure_reasons[error_type] = failure_reasons.get(error_type, 0) + 1

            emit_metric(
                "CollectionFailures",
                dimensions={
                    "Ecosystem": ecosystem,
                    "Reason": error_type[:50],
                }
            )
        elif isinstance(result, tuple) and len(result) >= 3:
            success, pkg_name, error_reason = result[0], result[1], result[2]
            if success:
                successes += 1
                emit_metric(
                    "PackagesCollected",
                    dimensions={"Ecosystem": ecosystem}
                )
            else:
                failures += 1
                reason = error_reason or "unknown"
                failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
                emit_metric(
                    "CollectionFailures",
                    dimensions={
                        "Ecosystem": ecosystem,
                        "Reason": reason[:50],
                    }
                )
        else:
            failures += 1
            failure_reasons["unknown"] = failure_reasons.get("unknown", 0) + 1

    # Emit batch metrics
    batch_duration = time.time() - start_time
    emit_batch_metrics([
        {"metric_name": "BatchProcessingTime", "value": batch_duration, "unit": "Seconds"},
        {"metric_name": "BatchSize", "value": len(records)},
        {"metric_name": "BatchSuccesses", "value": successes},
        {"metric_name": "BatchFailures", "value": failures},
    ])

    return successes, failures


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

    Uses asyncio.gather for parallel processing of batch messages.
    """
    records = event.get("Records", [])
    logger.info(f"Processing {len(records)} messages")

    # Create event loop and process batch
    loop = asyncio.new_event_loop()
    try:
        successes, failures = loop.run_until_complete(process_batch(records))
    finally:
        loop.close()

    logger.info(f"Completed: {successes} successes, {failures} failures")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "processed": successes + failures,
            "successes": successes,
            "failures": failures,
        }),
    }
