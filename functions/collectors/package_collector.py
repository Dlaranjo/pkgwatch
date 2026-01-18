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
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import collectors (these will be bundled with the Lambda)
from depsdev_collector import get_package_info as get_depsdev_info
from npm_collector import get_npm_metadata
from pypi_collector import get_pypi_metadata, PYPI_PACKAGE_PATTERN as PYPI_NAME_PATTERN
from github_collector import GitHubCollector, parse_github_url
from bundlephobia_collector import get_bundle_size

# Import shared utilities
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../shared"))
from metrics import emit_metric, emit_batch_metrics
from circuit_breaker import CircuitOpenError, GITHUB_CIRCUIT
from rate_limit_utils import check_and_increment_external_rate_limit
from package_validation import validate_npm_package_name, validate_pypi_package_name

# Lazy initialization for boto3 clients (reduces cold start time)
_dynamodb = None
_s3 = None
_secretsmanager = None


def _get_dynamodb():
    """Get DynamoDB resource with lazy initialization."""
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb


def _get_s3():
    """Get S3 client with lazy initialization."""
    global _s3
    if _s3 is None:
        _s3 = boto3.client("s3")
    return _s3


def _get_secretsmanager():
    """Get Secrets Manager client with lazy initialization."""
    global _secretsmanager
    if _secretsmanager is None:
        _secretsmanager = boto3.client("secretsmanager")
    return _secretsmanager

PACKAGES_TABLE = os.environ.get("PACKAGES_TABLE", "pkgwatch-packages")
RAW_DATA_BUCKET = os.environ.get("RAW_DATA_BUCKET", "pkgwatch-raw-data")
GITHUB_TOKEN_SECRET_ARN = os.environ.get("GITHUB_TOKEN_SECRET_ARN")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")

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

# NOTE: npm/PyPI package validation moved to shared/package_validation.py

# Patterns to redact from error messages (security)
_SENSITIVE_PATTERNS = [
    (re.compile(r'arn:aws:[^:]*:[^:]*:\d{12}:[^\s]*', re.IGNORECASE), 'arn:aws:***:***:***:***'),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}', re.IGNORECASE), 'ghp_***'),
    (re.compile(r'gho_[a-zA-Z0-9]{36}', re.IGNORECASE), 'gho_***'),
    (re.compile(r'github_pat_[a-zA-Z0-9_]{22,}', re.IGNORECASE), 'github_pat_***'),
    (re.compile(r'sk-[a-zA-Z0-9]{32,}', re.IGNORECASE), 'sk-***'),
    (re.compile(r'Bearer\s+[a-zA-Z0-9._-]+', re.IGNORECASE), 'Bearer ***'),
    (re.compile(r'\d{12}'), '***'),  # AWS account IDs
]


def _sanitize_error(error_str: str) -> str:
    """
    Sanitize error strings to remove sensitive information.

    Redacts AWS ARNs, account IDs, API tokens, and other sensitive patterns
    that might leak through exception messages.
    """
    result = error_str
    for pattern, replacement in _SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)

    # Truncate to prevent very long error strings
    max_length = 500
    if len(result) > max_length:
        result = result[:max_length] + "...[truncated]"

    return result


def validate_message(body: dict) -> Tuple[bool, Optional[str]]:
    """
    Validate SQS message body.

    Uses shared validation from package_validation module which:
    - Accepts uppercase npm names (legacy packages like Server, JSONStream)
    - Accepts underscores in npm scopes (e.g., @_ndk/motion)
    - Normalizes npm names to lowercase (npm is case-insensitive)

    Args:
        body: Parsed message body

    Returns:
        Tuple of (is_valid, error_message)
    """
    ecosystem = body.get("ecosystem")
    name = body.get("name")

    if not ecosystem:
        return False, "Missing 'ecosystem' field"

    if not name:
        return False, "Missing 'name' field"

    if ecosystem not in ["npm", "pypi"]:
        return False, f"Unsupported ecosystem: {ecosystem}"

    # Validate and normalize using shared validation
    if ecosystem == "npm":
        is_valid, error, normalized = validate_npm_package_name(name)
    else:
        is_valid, error, normalized = validate_pypi_package_name(name)

    if not is_valid:
        return False, error

    # Update message with normalized name
    body["name"] = normalized
    body["_original_name"] = name  # Preserve for logging

    return True, None


def get_github_token() -> Optional[str]:
    """Retrieve GitHub token from Secrets Manager."""
    if not GITHUB_TOKEN_SECRET_ARN:
        logger.warning("GITHUB_TOKEN_SECRET_ARN not configured")
        return None

    try:
        response = _get_secretsmanager().get_secret_value(SecretId=GITHUB_TOKEN_SECRET_ARN)
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
    table = _get_dynamodb().Table(API_KEYS_TABLE)
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
    table = _get_dynamodb().Table(API_KEYS_TABLE)
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
    table = _get_dynamodb().Table(PACKAGES_TABLE)
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
        if depsdev_data:
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
        else:
            logger.warning(f"Package {ecosystem}/{name} not found in deps.dev")

    except CircuitOpenError as e:
        logger.warning(f"deps.dev circuit open for {ecosystem}/{name}: {e}")
        combined_data["depsdev_error"] = "circuit_open"

        # Try to use stale data as fallback
        existing = await _get_existing_package_data(ecosystem, name)
        if existing and _is_data_acceptable(existing, max_age_days=STALE_DATA_MAX_AGE_DAYS):
            logger.info(f"Using stale data for {ecosystem}/{name}")
            combined_data.update(_extract_cached_fields(existing))
            combined_data["data_freshness"] = "stale"
            combined_data["stale_reason"] = "deps.dev_circuit_open"

    except Exception as e:
        logger.error(f"Failed to fetch deps.dev data for {ecosystem}/{name}: {e}")
        combined_data["depsdev_error"] = _sanitize_error(str(e))

        # Try to use stale data as fallback
        existing = await _get_existing_package_data(ecosystem, name)
        if existing and _is_data_acceptable(existing, max_age_days=STALE_DATA_MAX_AGE_DAYS):
            logger.info(f"Using stale data for {ecosystem}/{name}")
            combined_data.update(_extract_cached_fields(existing))
            combined_data["data_freshness"] = "stale"
            combined_data["stale_reason"] = "deps.dev_unavailable"

    # 2. npm and bundlephobia data (run in parallel - they don't depend on each other)
    if ecosystem == "npm":
        # Check rate limits before starting requests
        npm_allowed = check_and_increment_external_rate_limit("npm", 800)  # 80% of 1000
        bundle_allowed = check_and_increment_external_rate_limit("bundlephobia", 80)  # 80% of 100

        # Only create tasks for allowed services
        tasks = []
        if npm_allowed:
            tasks.append(get_npm_metadata(name))
        if bundle_allowed:
            tasks.append(get_bundle_size(name))

        # Gather results (may be empty if both rate limited)
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            results = []

        # Map results back to services
        result_idx = 0
        if npm_allowed:
            npm_result = results[result_idx] if result_idx < len(results) else None
            result_idx += 1
        else:
            npm_result = None
            logger.warning(f"npm rate limit reached, skipping for {name}")
            combined_data["npm_error"] = "rate_limit_exceeded"

        if bundle_allowed:
            bundle_result = results[result_idx] if result_idx < len(results) else None
        else:
            bundle_result = None
            logger.warning(f"Bundlephobia rate limit reached, skipping for {name}")
            combined_data["bundlephobia_error"] = "rate_limit_exceeded"

        # Process npm result (if we tried to fetch it)
        if npm_allowed and npm_result is not None:
            if isinstance(npm_result, CircuitOpenError):
                logger.warning(f"npm circuit open for {name}")
                combined_data["npm_error"] = "circuit_open"
            elif isinstance(npm_result, Exception):
                logger.error(f"Failed to fetch npm data for {name}: {npm_result}")
                combined_data["npm_error"] = _sanitize_error(str(npm_result))
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

        # Process bundlephobia result (if we tried to fetch it)
        if bundle_allowed and bundle_result is not None:
            if isinstance(bundle_result, CircuitOpenError):
                logger.warning(f"Bundlephobia circuit open for {name}")
                combined_data["bundlephobia_error"] = "circuit_open"
            elif isinstance(bundle_result, Exception):
                logger.warning(f"Failed to fetch bundle size for {name}: {bundle_result}")
                combined_data["bundlephobia_error"] = _sanitize_error(str(bundle_result))
            elif "error" not in bundle_result:
                combined_data["bundlephobia"] = bundle_result
                combined_data["sources"].append("bundlephobia")
                combined_data["bundle_size"] = bundle_result.get("size", 0)
                combined_data["bundle_size_gzip"] = bundle_result.get("gzip", 0)
                combined_data["bundle_size_category"] = bundle_result.get("size_category")
                combined_data["bundle_dependency_count"] = bundle_result.get(
                    "dependency_count", 0
                )
            else:
                combined_data["bundlephobia_error"] = bundle_result.get("error")

    # 2b. PyPI data (for pypi ecosystem)
    elif ecosystem == "pypi":
        pypi_allowed = check_and_increment_external_rate_limit("pypi", 400)  # 80% of 500

        if pypi_allowed:
            try:
                pypi_data = await get_pypi_metadata(name)
                if "error" not in pypi_data:
                    combined_data["pypi"] = pypi_data
                    combined_data["sources"].append("pypi")

                    # Map PyPI data to common fields
                    combined_data["weekly_downloads"] = pypi_data.get("weekly_downloads", 0)
                    combined_data["maintainers"] = pypi_data.get("maintainers", [])
                    combined_data["maintainer_count"] = pypi_data.get("maintainer_count", 0)
                    combined_data["is_deprecated"] = pypi_data.get("is_deprecated", False)
                    combined_data["created_at"] = pypi_data.get("created_at")
                    combined_data["last_published"] = pypi_data.get("last_published")

                    # PyPI-specific fields
                    combined_data["requires_python"] = pypi_data.get("requires_python")
                    combined_data["development_status"] = pypi_data.get("development_status")
                    combined_data["python_versions"] = pypi_data.get("python_versions", [])

                    # Use PyPI repo URL as fallback
                    if not combined_data.get("repository_url"):
                        combined_data["repository_url"] = pypi_data.get("repository_url")
                else:
                    combined_data["pypi_error"] = pypi_data.get("error")
            except CircuitOpenError:
                logger.warning(f"PyPI circuit open for {name}")
                combined_data["pypi_error"] = "circuit_open"
            except Exception as e:
                logger.error(f"Failed to fetch PyPI data for {name}: {e}")
                combined_data["pypi_error"] = _sanitize_error(str(e))
        else:
            logger.warning(f"PyPI rate limit reached, skipping for {name}")
            combined_data["pypi_error"] = "rate_limit_exceeded"

    # 3. GitHub data (secondary - rate limited, with circuit breaker)
    repo_url = combined_data.get("repository_url")
    if repo_url:
        parsed = parse_github_url(repo_url)
        if parsed:
            owner, repo = parsed

            # Check circuit breaker FIRST (before rate limiting check)
            # Use async method to prevent race conditions
            if not await GITHUB_CIRCUIT.can_execute_async():
                logger.warning(f"GitHub circuit open, skipping for {ecosystem}/{name}")
                combined_data["github_error"] = "circuit_open"
            else:
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
                                # Record success for circuit breaker (thread-safe)
                                await GITHUB_CIRCUIT.record_success_async()

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
                                # Record failure for circuit breaker (API returned error, thread-safe)
                                await GITHUB_CIRCUIT.record_failure_async()
                                combined_data["github_error"] = github_data["error"]

                except Exception as e:
                    # Record failure for circuit breaker (thread-safe)
                    await GITHUB_CIRCUIT.record_failure_async(e)
                    logger.error(f"Failed to fetch GitHub data for {owner}/{repo}: {e}")
                    combined_data["github_error"] = _sanitize_error(str(e))

    # Note: Bundlephobia is now fetched in parallel with npm data in section 2

    return combined_data


def store_raw_data(ecosystem: str, name: str, data: dict):
    """Store raw collected data in S3 for debugging."""
    try:
        key = f"{ecosystem}/{name}/{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.json"
        _get_s3().put_object(
            Bucket=RAW_DATA_BUCKET,
            Key=key,
            Body=json.dumps(data, indent=2, default=str),
            ContentType="application/json",
        )
        logger.debug(f"Stored raw data: s3://{RAW_DATA_BUCKET}/{key}")
    except Exception as e:
        logger.warning(f"Failed to store raw data: {e}")


# Maximum retry count for incomplete data collection
MAX_RETRY_COUNT = 5


def _calculate_data_status(data: dict, ecosystem: str) -> tuple[str, list]:
    """
    Calculate data completeness status based on which sources succeeded or failed.

    Returns:
        Tuple of (status, missing_sources) where:
        - status is "complete", "partial", or "minimal"
        - missing_sources is a list of sources that failed
    """
    missing = []

    if data.get("depsdev_error"):
        missing.append("deps.dev")

    if ecosystem == "npm":
        if data.get("npm_error"):
            missing.append("npm")
        if data.get("bundlephobia_error"):
            missing.append("bundlephobia")
    elif ecosystem == "pypi":
        if data.get("pypi_error"):
            missing.append("pypi")

    # GitHub is only expected if we have a repository_url
    if data.get("repository_url") and data.get("github_error"):
        missing.append("github")

    if not missing:
        return ("complete", [])
    elif "deps.dev" in missing:
        return ("minimal", missing)
    return ("partial", missing)


def _calculate_next_retry_at(retry_count: int) -> str | None:
    """
    Calculate next retry time with exponential backoff.

    Backoff schedule: 1hr, 2hr, 4hr, 8hr, 24hr
    Returns None if retry_count >= MAX_RETRY_COUNT.
    """
    if retry_count >= MAX_RETRY_COUNT:
        return None

    delays_hours = [1, 2, 4, 8, 24]
    delay = delays_hours[min(retry_count, len(delays_hours) - 1)]
    return (datetime.now(timezone.utc) + timedelta(hours=delay)).isoformat()


def store_package_data(ecosystem: str, name: str, data: dict, tier: int):
    """Store processed package data in DynamoDB."""
    table = _get_dynamodb().Table(PACKAGES_TABLE)

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
        # Bundle size (DX signals - npm only)
        "bundle_size": data.get("bundle_size"),
        "bundle_size_gzip": data.get("bundle_size_gzip"),
        "bundle_size_category": data.get("bundle_size_category"),
        "bundle_dependency_count": data.get("bundle_dependency_count"),
        # PyPI-specific fields
        "requires_python": data.get("requires_python"),
        "development_status": data.get("development_status"),
        "python_versions": data.get("python_versions", []),
        # Metadata
        "repository_url": data.get("repository_url"),
        "licenses": data.get("licenses", []),
        "sources": data.get("sources", []),
        "data_freshness": data.get("data_freshness", "fresh"),
        "stale_reason": data.get("stale_reason"),
        # Collection timestamp (used by score_package.py for loop prevention)
        "collected_at": data.get("collected_at"),
    }

    # Calculate data completeness status for retry tracking
    data_status, missing_sources = _calculate_data_status(data, ecosystem)

    # Upgrade minimal to abandoned_minimal if max retries reached
    existing_retry = data.get("_existing_retry_count", 0)
    if data_status == "minimal" and existing_retry >= MAX_RETRY_COUNT:
        data_status = "abandoned_minimal"
        logger.info(
            f"Package {ecosystem}/{name} marked as abandoned_minimal "
            f"after {existing_retry} retries"
        )

    item["data_status"] = data_status
    item["missing_sources"] = missing_sources

    # Handle retry tracking based on data completeness
    if data_status == "complete":
        # Reset retry tracking on successful complete collection
        item["retry_count"] = 0
        # Don't set next_retry_at - will be removed by None filter below
    elif data_status == "abandoned_minimal":
        # Keep retry_count but don't schedule more retries
        item["retry_count"] = existing_retry
        # next_retry_at intentionally not set - package has exhausted retries
    else:
        # Partial or minimal status - schedule retry with exponential backoff
        item["retry_count"] = existing_retry
        item["next_retry_at"] = _calculate_next_retry_at(existing_retry)

    # Remove None values and empty strings (DynamoDB rejects both by default)
    item = {k: v for k, v in item.items() if v is not None and v != ""}

    try:
        table.put_item(Item=item)
        logger.info(f"Stored package data: {ecosystem}/{name} (status: {data_status})")
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
    force_refresh = message.get("force_refresh", False)
    is_retry = message.get("reason") == "incomplete_data_retry"

    # Get existing package data
    existing = await _get_existing_package_data(ecosystem, name)

    # For incomplete data retries, increment retry_count BEFORE collection
    # This prevents infinite loops if the Lambda crashes before storing
    if is_retry and existing:
        table = _get_dynamodb().Table(PACKAGES_TABLE)
        try:
            table.update_item(
                Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"},
                UpdateExpression="SET retry_count = if_not_exists(retry_count, :zero) + :one",
                ExpressionAttributeValues={":zero": 0, ":one": 1},
            )
            logger.debug(f"Incremented retry_count for {ecosystem}/{name}")
        except Exception as e:
            logger.warning(f"Failed to increment retry_count: {e}")

    # Check if recently collected (deduplication) - skip if force_refresh
    if not force_refresh and existing:
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

    logger.info(f"Collecting data for {ecosystem}/{name} (tier {tier}, force={force_refresh})")

    try:
        # Collect data from all sources
        data = await collect_package_data(ecosystem, name)

        # Pass existing retry_count to store_package_data for retry tracking
        # (used to calculate next_retry_at if collection is still incomplete)
        # Note: If this is a retry, we already incremented retry_count in DynamoDB above,
        # so we need to pass the incremented value to avoid overwriting it
        if existing:
            base_retry_count = existing.get("retry_count", 0)
            # If this is a retry, the count was already incremented in DynamoDB
            data["_existing_retry_count"] = base_retry_count + 1 if is_retry else base_retry_count

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
