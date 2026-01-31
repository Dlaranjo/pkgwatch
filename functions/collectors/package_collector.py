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
from npm_collector import get_npm_metadata, get_bulk_download_stats
from pypi_collector import get_pypi_metadata, PYPI_PACKAGE_PATTERN as PYPI_NAME_PATTERN
from github_collector import GitHubCollector, parse_github_url
from bundlephobia_collector import get_bundle_size
from openssf_collector import get_openssf_scorecard

# Import shared utilities
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../shared"))
from metrics import emit_metric, emit_batch_metrics
from circuit_breaker import CircuitOpenError, GITHUB_CIRCUIT, OPENSSF_CIRCUIT
from rate_limit_utils import check_and_increment_external_rate_limit
from package_validation import validate_npm_package_name, validate_pypi_package_name
from error_classification import classify_error as _classify_error

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
STALE_DATA_MAX_AGE_DAYS = int(os.environ.get("STALE_DATA_MAX_AGE_DAYS", "14"))
DEDUP_WINDOW_MINUTES = int(os.environ.get("DEDUP_WINDOW_MINUTES", "30"))

# Reason-based stale data thresholds
# Circuit breaker errors indicate service outages that may take longer to recover
# Rate limit errors typically resolve within an hour
STALE_DATA_THRESHOLDS = {
    "circuit_open": 14,       # Circuit breaker - service likely recovering, accept 2-week old data
    "rate_limit_exceeded": 7, # Rate limit - will resolve within the hour
    "default": 7,             # Other errors - be conservative
}

# Semaphore to limit concurrent GitHub API calls per Lambda instance
# With maxConcurrency=10 Lambdas * 5 = max 50 concurrent GitHub calls
# GitHub allows 5000/hour = ~83/minute, so this keeps us well under the limit
# NOTE: Lazy initialization to handle Lambda event loop changes
_github_semaphore: Optional[asyncio.Semaphore] = None
_github_semaphore_loop_id: Optional[int] = None


def get_github_semaphore() -> asyncio.Semaphore:
    """
    Get GitHub semaphore, recreating if event loop changed.

    Lambda can reuse containers but create new event loops. An asyncio.Semaphore
    bound to an old event loop causes "attached to different loop" errors.
    """
    global _github_semaphore, _github_semaphore_loop_id

    try:
        current_loop_id = id(asyncio.get_running_loop())
    except RuntimeError:
        current_loop_id = None

    if _github_semaphore is not None and _github_semaphore_loop_id != current_loop_id:
        logger.debug("Event loop changed, recreating GitHub semaphore")
        _github_semaphore = None

    if _github_semaphore is None:
        _github_semaphore = asyncio.Semaphore(5)
        _github_semaphore_loop_id = current_loop_id

    return _github_semaphore

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


def _store_collection_error(ecosystem: str, name: str, error_msg: str) -> None:
    """
    Store collection error in package record for DLQ processor.

    This allows the DLQ processor to classify errors and make intelligent
    retry decisions. The error is stored with a timestamp so we can track
    when failures occurred.
    """
    table = _get_dynamodb().Table(PACKAGES_TABLE)
    now = datetime.now(timezone.utc).isoformat()

    error_class = _classify_error(error_msg)

    try:
        table.update_item(
            Key={"pk": f"{ecosystem}#{name}", "sk": "LATEST"},
            UpdateExpression=(
                "SET collection_error = :error, "
                "collection_error_class = :error_class, "
                "collection_error_at = :now"
            ),
            ExpressionAttributeValues={
                ":error": error_msg,
                ":error_class": error_class,
                ":now": now,
            },
        )
        logger.debug(f"Stored collection error for {ecosystem}/{name}: {error_class}")
    except Exception as e:
        # Don't fail the whole operation if we can't store the error
        logger.warning(f"Failed to store collection error for {ecosystem}/{name}: {e}")


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


def _extract_cached_github_fields(existing: dict) -> dict:
    """Extract cached GitHub fields from existing data for stale data fallback."""
    return {
        "stars": existing.get("stars"),
        "forks": existing.get("forks"),
        "open_issues": existing.get("open_issues"),
        "days_since_last_commit": existing.get("days_since_last_commit"),
        "commits_90d": existing.get("commits_90d"),
        "active_contributors_90d": existing.get("active_contributors_90d"),
        "total_contributors": existing.get("total_contributors"),
        "true_bus_factor": existing.get("true_bus_factor"),
        "bus_factor_confidence": existing.get("bus_factor_confidence"),
        "contribution_distribution": existing.get("contribution_distribution", []),
        "archived": existing.get("archived"),
    }


def _has_github_data(data: dict) -> bool:
    """Check if data has valid GitHub fields (not just zeros)."""
    return (
        data.get("stars") is not None or
        data.get("days_since_last_commit") is not None or
        data.get("commits_90d") is not None
    )


def _has_openssf_data(data: dict) -> bool:
    """Check if data has valid OpenSSF fields (score is not None)."""
    return data.get("openssf_score") is not None


def _get_stale_threshold_days(error_reason: str) -> int:
    """
    Get appropriate stale data threshold based on error type.

    Circuit breaker errors indicate service outages that may take longer to recover,
    so we accept older cached data. Rate limit errors typically resolve within an hour.
    """
    if not error_reason:
        return STALE_DATA_THRESHOLDS["default"]
    error_lower = error_reason.lower()
    if "circuit" in error_lower:
        return STALE_DATA_THRESHOLDS["circuit_open"]
    if "rate_limit" in error_lower:
        return STALE_DATA_THRESHOLDS["rate_limit_exceeded"]
    return STALE_DATA_THRESHOLDS["default"]


async def _try_github_stale_fallback(
    combined_data: dict,
    ecosystem: str,
    name: str,
    error_reason: str
) -> None:
    """
    Try to use stale GitHub data as fallback when GitHub collection fails.

    Uses reason-based thresholds: circuit breaker errors allow older data (14 days)
    since service outages may take longer to recover.

    Modifies combined_data in place to add cached GitHub fields if available.
    """
    existing = await _get_existing_package_data(ecosystem, name)
    if existing and _has_github_data(existing):
        # Use reason-based threshold instead of fixed STALE_DATA_MAX_AGE_DAYS
        max_age = _get_stale_threshold_days(error_reason)
        if _is_data_acceptable(existing, max_age_days=max_age):
            logger.info(
                f"Using stale GitHub data for {ecosystem}/{name} "
                f"(max_age={max_age} days, reason={error_reason})"
            )
            cached_fields = _extract_cached_github_fields(existing)
            # Only add non-None fields
            for key, value in cached_fields.items():
                if value is not None:
                    combined_data[key] = value
            combined_data["github_freshness"] = "stale"
            combined_data["github_stale_reason"] = error_reason
            if "github" not in combined_data.get("sources", []):
                combined_data.setdefault("sources", []).append("github_stale")


def _extract_cached_npm_fields(existing: dict) -> dict:
    """Extract cached npm fields from existing data for selective retry."""
    return {
        "weekly_downloads": existing.get("weekly_downloads", 0),
        "maintainers": existing.get("maintainers", []),
        "maintainer_count": existing.get("maintainer_count", 0),
        "is_deprecated": existing.get("is_deprecated", False),
        "deprecation_message": existing.get("deprecation_message"),
        "created_at": existing.get("created_at"),
        "last_published": existing.get("last_published"),
        "has_types": existing.get("has_types", False),
        "module_type": existing.get("module_type", "commonjs"),
        "has_exports": existing.get("has_exports", False),
        "engines": existing.get("engines"),
    }


def _extract_cached_pypi_fields(existing: dict) -> dict:
    """Extract cached PyPI fields from existing data for selective retry."""
    return {
        "weekly_downloads": existing.get("weekly_downloads", 0),
        "maintainers": existing.get("maintainers", []),
        "maintainer_count": existing.get("maintainer_count", 0),
        "is_deprecated": existing.get("is_deprecated", False),
        "created_at": existing.get("created_at"),
        "last_published": existing.get("last_published"),
        "requires_python": existing.get("requires_python"),
        "development_status": existing.get("development_status"),
        "python_versions": existing.get("python_versions", []),
    }


def _extract_cached_bundlephobia_fields(existing: dict) -> dict:
    """Extract cached bundlephobia fields from existing data for selective retry."""
    return {
        "bundle_size": existing.get("bundle_size"),
        "bundle_size_gzip": existing.get("bundle_size_gzip"),
        "bundle_size_category": existing.get("bundle_size_category"),
        "bundle_dependency_count": existing.get("bundle_dependency_count"),
    }


def _extract_cached_openssf_fields(existing: dict) -> dict:
    """Extract cached OpenSSF fields for stale data fallback."""
    return {
        "openssf_score": existing.get("openssf_score"),
        "openssf_checks": existing.get("openssf_checks", []),
        "openssf_date": existing.get("openssf_date"),
    }


def _should_run_collector(source: str, retry_sources: list) -> bool:
    """
    Determine if a collector should run based on retry_sources.

    Args:
        source: The source name (e.g., "npm", "github", "bundlephobia")
        retry_sources: List of sources that failed and need retry.
                       Empty list means run all collectors (normal refresh).

    Returns:
        True if collector should run, False if it should be skipped.
    """
    # Empty retry_sources = normal refresh, run all collectors
    if not retry_sources:
        return True
    # Run collector only if it's in the retry list
    return source in retry_sources


async def collect_package_data(
    ecosystem: str,
    name: str,
    existing: dict = None,
    retry_sources: list = None,
    bulk_downloads: dict = None
) -> dict:
    """
    Collect comprehensive package data from all sources with graceful degradation.

    Order of operations:
    1. deps.dev (primary) - always fetch, fallback to stale data if fails
    2. npm (supplementary) - always fetch for npm packages
    3. GitHub (secondary) - only if we have a repo URL and rate limit allows

    Args:
        ecosystem: Package ecosystem ("npm" or "pypi")
        name: Package name
        existing: Existing package data from DynamoDB (for selective retry)
        retry_sources: List of sources that failed previously. If non-empty,
                       only these sources will be fetched; others use cached data.
        bulk_downloads: Pre-fetched download stats from bulk API (reduces API calls)

    Returns:
        Combined package data dictionary
    """
    retry_sources = retry_sources or []
    combined_data = {
        "ecosystem": ecosystem,
        "name": name,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "sources": [],
        "data_freshness": "fresh",
    }

    # 1. deps.dev data (primary source)
    # Note: deps.dev is always fetched (never skipped for selective retry)
    # because it provides critical data like repository_url needed for GitHub
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

        # Try to use stale/cached data as fallback
        fallback_data = existing or await _get_existing_package_data(ecosystem, name)
        if fallback_data and _is_data_acceptable(fallback_data, max_age_days=STALE_DATA_MAX_AGE_DAYS):
            logger.info(f"Using stale data for {ecosystem}/{name}")
            combined_data.update(_extract_cached_fields(fallback_data))
            combined_data["data_freshness"] = "stale"
            combined_data["stale_reason"] = "deps.dev_circuit_open"

    except Exception as e:
        logger.error(f"Failed to fetch deps.dev data for {ecosystem}/{name}: {e}")
        combined_data["depsdev_error"] = _sanitize_error(str(e))

        # Try to use stale/cached data as fallback
        fallback_data = existing or await _get_existing_package_data(ecosystem, name)
        if fallback_data and _is_data_acceptable(fallback_data, max_age_days=STALE_DATA_MAX_AGE_DAYS):
            logger.info(f"Using stale data for {ecosystem}/{name}")
            combined_data.update(_extract_cached_fields(fallback_data))
            combined_data["data_freshness"] = "stale"
            combined_data["stale_reason"] = "deps.dev_unavailable"

    # 2. npm and bundlephobia data (run in parallel - they don't depend on each other)
    if ecosystem == "npm":
        # Determine which collectors to run (selective retry support)
        should_fetch_npm = _should_run_collector("npm", retry_sources)
        should_fetch_bundlephobia = _should_run_collector("bundlephobia", retry_sources)

        # If skipping npm due to selective retry, use cached data
        if not should_fetch_npm and existing:
            logger.debug(f"Selective retry: using cached npm data for {name}")
            cached_npm = _extract_cached_npm_fields(existing)
            for key, value in cached_npm.items():
                if value is not None:
                    combined_data[key] = value
            combined_data["sources"].append("npm_cached")
            # Also copy repository_url from existing if we don't have it
            if not combined_data.get("repository_url") and existing.get("repository_url"):
                combined_data["repository_url"] = existing.get("repository_url")

        # If skipping bundlephobia due to selective retry, use cached data
        if not should_fetch_bundlephobia and existing:
            logger.debug(f"Selective retry: using cached bundlephobia data for {name}")
            cached_bundle = _extract_cached_bundlephobia_fields(existing)
            for key, value in cached_bundle.items():
                if value is not None:
                    combined_data[key] = value
            if any(v is not None for v in cached_bundle.values()):
                combined_data["sources"].append("bundlephobia_cached")

        # Check rate limits before starting requests
        npm_allowed = should_fetch_npm and check_and_increment_external_rate_limit("npm", 800)
        bundle_allowed = should_fetch_bundlephobia and check_and_increment_external_rate_limit("bundlephobia", 80)

        # Only create tasks for allowed services
        tasks = []
        if npm_allowed:
            tasks.append(get_npm_metadata(name))
        if bundle_allowed:
            tasks.append(get_bundle_size(name))

        # Gather results (may be empty if both rate limited or skipped)
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            results = []

        # Map results back to services
        result_idx = 0
        if npm_allowed:
            npm_result = results[result_idx] if result_idx < len(results) else None
            result_idx += 1
        elif should_fetch_npm:
            # Wanted to fetch but rate limited - try stale fallback
            npm_result = None
            logger.warning(f"npm rate limit reached, skipping for {name}")
            combined_data["npm_error"] = "rate_limit_exceeded"
            # Try stale data fallback (mirror circuit_open pattern at lines 643-655)
            fallback_data = existing or await _get_existing_package_data(ecosystem, name)
            threshold = STALE_DATA_THRESHOLDS.get("rate_limit_exceeded", 7)
            if fallback_data and _is_data_acceptable(fallback_data, max_age_days=threshold):
                logger.info(f"Using stale npm data for {name} (rate limited)")
                cached = _extract_cached_npm_fields(fallback_data)
                for key, value in cached.items():
                    if value is not None:
                        combined_data[key] = value
                combined_data["sources"].append("npm_stale")
                combined_data["npm_freshness"] = "stale"
                combined_data["npm_stale_reason"] = "rate_limit_exceeded"
        else:
            npm_result = None  # Skipped due to selective retry

        if bundle_allowed:
            bundle_result = results[result_idx] if result_idx < len(results) else None
        elif should_fetch_bundlephobia:
            # Wanted to fetch but rate limited - try stale fallback (Fix 3c)
            bundle_result = None
            logger.warning(f"Bundlephobia rate limit reached, skipping for {name}")
            combined_data["bundlephobia_error"] = "rate_limit_exceeded"
            fallback_data = existing or await _get_existing_package_data(ecosystem, name)
            if fallback_data:
                threshold = _get_stale_threshold_days("rate_limit_exceeded")
                if _is_data_acceptable(fallback_data, max_age_days=threshold):
                    logger.info(f"Using stale bundlephobia data for {name} (rate limited)")
                    cached = _extract_cached_bundlephobia_fields(fallback_data)
                    for key, value in cached.items():
                        if value is not None:
                            combined_data[key] = value
                    if any(v is not None for v in cached.values()):
                        combined_data["sources"].append("bundlephobia_stale")
                    combined_data["bundlephobia_freshness"] = "stale"
                    combined_data["bundlephobia_stale_reason"] = "rate_limit_exceeded"
        else:
            bundle_result = None  # Skipped due to selective retry

        # Process npm result (if we tried to fetch it)
        if npm_allowed and npm_result is not None:
            if isinstance(npm_result, CircuitOpenError):
                logger.warning(f"npm circuit open for {name}")
                combined_data["npm_error"] = "circuit_open"
                # Try stale data fallback
                fallback_data = existing or await _get_existing_package_data(ecosystem, name)
                if fallback_data and _is_data_acceptable(fallback_data, max_age_days=STALE_DATA_MAX_AGE_DAYS):
                    logger.info(f"Using stale npm data for {name} (circuit open)")
                    cached = _extract_cached_npm_fields(fallback_data)
                    for key, value in cached.items():
                        if value is not None:
                            combined_data[key] = value
                    combined_data["sources"].append("npm_stale")
                    combined_data["npm_freshness"] = "stale"
                    combined_data["npm_stale_reason"] = "circuit_open"
            elif isinstance(npm_result, Exception):
                logger.error(f"Failed to fetch npm data for {name}: {npm_result}")
                combined_data["npm_error"] = _sanitize_error(str(npm_result))
                # Try stale data fallback (Fix 3a)
                fallback_data = existing or await _get_existing_package_data(ecosystem, name)
                if fallback_data:
                    threshold = _get_stale_threshold_days("exception")
                    if _is_data_acceptable(fallback_data, max_age_days=threshold):
                        logger.info(f"Using stale npm data for {name} (exception)")
                        cached = _extract_cached_npm_fields(fallback_data)
                        for key, value in cached.items():
                            if value is not None:
                                combined_data[key] = value
                        combined_data["sources"].append("npm_stale")
                        combined_data["npm_freshness"] = "stale"
                        combined_data["npm_stale_reason"] = str(npm_result)[:50]
            else:
                npm_data = npm_result
                combined_data["npm"] = npm_data
                combined_data["sources"].append("npm")

                # Supplement with npm-specific data
                # Use bulk-fetched downloads if available (more efficient API usage)
                if bulk_downloads and name in bulk_downloads:
                    combined_data["weekly_downloads"] = bulk_downloads[name]
                    combined_data["downloads_source"] = "bulk"
                else:
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
                # Try stale data fallback
                fallback_data = existing or await _get_existing_package_data(ecosystem, name)
                if fallback_data and _is_data_acceptable(fallback_data, max_age_days=STALE_DATA_MAX_AGE_DAYS):
                    logger.info(f"Using stale bundlephobia data for {name} (circuit open)")
                    cached = _extract_cached_bundlephobia_fields(fallback_data)
                    for key, value in cached.items():
                        if value is not None:
                            combined_data[key] = value
                    if any(v is not None for v in cached.values()):
                        combined_data["sources"].append("bundlephobia_stale")
                    combined_data["bundlephobia_freshness"] = "stale"
                    combined_data["bundlephobia_stale_reason"] = "circuit_open"
            elif isinstance(bundle_result, Exception):
                logger.warning(f"Failed to fetch bundle size for {name}: {bundle_result}")
                combined_data["bundlephobia_error"] = _sanitize_error(str(bundle_result))
                # Try stale data fallback (Fix 3d)
                fallback_data = existing or await _get_existing_package_data(ecosystem, name)
                if fallback_data:
                    cached = _extract_cached_bundlephobia_fields(fallback_data)
                    for key, value in cached.items():
                        if value is not None:
                            combined_data[key] = value
                    if any(v is not None for v in cached.values()):
                        combined_data["sources"].append("bundlephobia_stale")
                    combined_data["bundlephobia_freshness"] = "stale"
                    combined_data["bundlephobia_stale_reason"] = str(bundle_result)[:50]
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
        should_fetch_pypi = _should_run_collector("pypi", retry_sources)

        # If skipping PyPI due to selective retry, use cached data
        if not should_fetch_pypi and existing:
            logger.debug(f"Selective retry: using cached PyPI data for {name}")
            cached_pypi = _extract_cached_pypi_fields(existing)
            for key, value in cached_pypi.items():
                if value is not None:
                    combined_data[key] = value
            combined_data["sources"].append("pypi_cached")
            # Also copy repository_url from existing if we don't have it
            if not combined_data.get("repository_url") and existing.get("repository_url"):
                combined_data["repository_url"] = existing.get("repository_url")

        pypi_allowed = should_fetch_pypi and check_and_increment_external_rate_limit("pypi", 400)

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
                # Try stale data fallback
                fallback_data = existing or await _get_existing_package_data(ecosystem, name)
                threshold = _get_stale_threshold_days("circuit_open")
                if fallback_data and _is_data_acceptable(fallback_data, max_age_days=threshold):
                    logger.info(f"Using stale PyPI data for {name} (circuit open)")
                    cached = _extract_cached_pypi_fields(fallback_data)
                    for key, value in cached.items():
                        if value is not None:
                            combined_data[key] = value
                    combined_data["sources"].append("pypi_stale")
                    combined_data["pypi_freshness"] = "stale"
                    combined_data["pypi_stale_reason"] = "circuit_open"
            except Exception as e:
                logger.error(f"Failed to fetch PyPI data for {name}: {e}")
                combined_data["pypi_error"] = _sanitize_error(str(e))
                # Try stale data fallback
                fallback_data = existing or await _get_existing_package_data(ecosystem, name)
                threshold = _get_stale_threshold_days("exception")
                if fallback_data and _is_data_acceptable(fallback_data, max_age_days=threshold):
                    logger.info(f"Using stale PyPI data for {name} (exception)")
                    cached = _extract_cached_pypi_fields(fallback_data)
                    for key, value in cached.items():
                        if value is not None:
                            combined_data[key] = value
                    combined_data["sources"].append("pypi_stale")
                    combined_data["pypi_freshness"] = "stale"
                    combined_data["pypi_stale_reason"] = "exception"
        elif should_fetch_pypi:
            # Wanted to fetch but rate limited - try stale fallback
            logger.warning(f"PyPI rate limit reached, skipping for {name}")
            combined_data["pypi_error"] = "rate_limit_exceeded"
            fallback_data = existing or await _get_existing_package_data(ecosystem, name)
            threshold = _get_stale_threshold_days("rate_limit_exceeded")
            if fallback_data and _is_data_acceptable(fallback_data, max_age_days=threshold):
                logger.info(f"Using stale PyPI data for {name} (rate limited)")
                cached = _extract_cached_pypi_fields(fallback_data)
                for key, value in cached.items():
                    if value is not None:
                        combined_data[key] = value
                combined_data["sources"].append("pypi_stale")
                combined_data["pypi_freshness"] = "stale"
                combined_data["pypi_stale_reason"] = "rate_limit_exceeded"
        # else: skipped due to selective retry, cached data already applied above

    # 3. GitHub data (secondary - rate limited, with circuit breaker)
    should_fetch_github = _should_run_collector("github", retry_sources)
    repo_url = combined_data.get("repository_url")

    # If skipping GitHub due to selective retry, use cached data
    if not should_fetch_github and existing and repo_url:
        logger.debug(f"Selective retry: using cached GitHub data for {ecosystem}/{name}")
        cached_github = _extract_cached_github_fields(existing)
        for key, value in cached_github.items():
            if value is not None:
                combined_data[key] = value
        if _has_github_data(cached_github):
            combined_data["sources"].append("github_cached")

    if should_fetch_github and repo_url:
        parsed = parse_github_url(repo_url)
        if parsed:
            owner, repo = parsed
            github_failed = False
            github_error_reason = ""

            # Check circuit breaker FIRST (before rate limiting check)
            # Use async method to prevent race conditions
            if not await GITHUB_CIRCUIT.can_execute_async():
                logger.warning(f"GitHub circuit open, skipping for {ecosystem}/{name}")
                combined_data["github_error"] = "circuit_open"
                github_failed = True
                github_error_reason = "circuit_open"
            else:
                try:
                    # Use semaphore to limit concurrent GitHub API calls per Lambda instance
                    # AND global rate limiter to coordinate across all Lambda instances
                    async with get_github_semaphore():
                        # Check global rate limit before making GitHub API call
                        if not _check_and_increment_github_rate_limit():
                            logger.warning(
                                f"Skipping GitHub for {ecosystem}/{name} - global rate limit"
                            )
                            combined_data["github_error"] = "rate_limit_exceeded"
                            github_failed = True
                            github_error_reason = "rate_limit_exceeded"
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
                                # Check if error is transient or not
                                error_type = github_data.get("error", "")
                                # Non-transient errors: 404 (not found), invalid URL, etc.
                                # These shouldn't trip the circuit breaker
                                non_transient_errors = ["repository_not_found", "invalid_github_url"]
                                if error_type not in non_transient_errors:
                                    # Transient error - record failure for circuit breaker
                                    await GITHUB_CIRCUIT.record_failure_async()
                                else:
                                    # Non-transient error - don't count against circuit breaker
                                    logger.debug(
                                        f"GitHub non-transient error for {ecosystem}/{name}: {error_type}"
                                    )
                                combined_data["github_error"] = error_type
                                github_failed = True
                                github_error_reason = error_type

                except Exception as e:
                    # Record failure for circuit breaker (thread-safe)
                    await GITHUB_CIRCUIT.record_failure_async(e)
                    logger.error(f"Failed to fetch GitHub data for {owner}/{repo}: {e}")
                    combined_data["github_error"] = _sanitize_error(str(e))
                    github_failed = True
                    github_error_reason = _sanitize_error(str(e))

            # Try stale data fallback if GitHub collection failed
            if github_failed:
                await _try_github_stale_fallback(
                    combined_data, ecosystem, name, github_error_reason
                )

    # Note: Bundlephobia is now fetched in parallel with npm data in section 2

    # 4. OpenSSF Scorecard (fallback when deps.dev has no data)
    # OpenSSF is a FALLBACK source, not a primary source
    repo_url = combined_data.get("repository_url")

    # Only fetch if deps.dev didn't provide OpenSSF data (score is None, not 0)
    if combined_data.get("openssf_score") is None and repo_url:
        # Check if we recently collected OpenSSF data (use last_updated, not openssf_date)
        # OpenSSF scorecards update weekly, so 7-day cache is sufficient
        if existing and _has_openssf_data(existing) and _is_data_acceptable(existing, max_age_days=7):
            logger.debug(f"Using recently collected OpenSSF data for {name} (< 7 days old)")
            cached = _extract_cached_openssf_fields(existing)
            for key, value in cached.items():
                if value is not None:
                    combined_data[key] = value
            combined_data["openssf_source"] = "cached_fresh"
        else:
            # Need to fetch from OpenSSF API
            parsed = parse_github_url(repo_url)  # Reuse existing parser from github_collector
            if parsed:
                owner, repo = parsed
                openssf_error = None

                # Check circuit breaker first
                if not await OPENSSF_CIRCUIT.can_execute_async():
                    logger.warning(f"OpenSSF circuit open, skipping for {ecosystem}/{name}")
                    openssf_error = "circuit_open"
                else:
                    # Check rate limit (1000/hour - increased for backfill headroom)
                    if check_and_increment_external_rate_limit("openssf", 1000):
                        try:
                            openssf_data = await get_openssf_scorecard(owner, repo)
                            if openssf_data:
                                await OPENSSF_CIRCUIT.record_success_async()
                                combined_data["openssf_score"] = openssf_data.get("openssf_score")
                                combined_data["openssf_checks"] = openssf_data.get("openssf_checks", [])
                                combined_data["openssf_date"] = openssf_data.get("openssf_date")
                                combined_data["openssf_source"] = "direct"
                                combined_data["openssf_freshness"] = "fresh"
                                combined_data.setdefault("sources", []).append("openssf")
                                logger.info(f"Got OpenSSF score {openssf_data['openssf_score']} from direct API for {name}")
                            else:
                                # 404 or parse error - not a failure, just no data available
                                await OPENSSF_CIRCUIT.record_success_async()
                        except Exception as e:
                            await OPENSSF_CIRCUIT.record_failure_async(e)
                            logger.warning(f"OpenSSF fetch failed for {name}: {e}")
                            openssf_error = str(e)[:100]
                    else:
                        logger.info(f"OpenSSF rate limit reached for {name}, trying stale fallback")
                        openssf_error = "rate_limit_exceeded"

                # Stale fallback for ALL error cases (circuit_open, rate_limit, exception)
                if openssf_error:
                    combined_data["openssf_error"] = openssf_error
                    # Try stale data fallback (consistent with npm/GitHub pattern)
                    if existing and _has_openssf_data(existing):
                        threshold = _get_stale_threshold_days(openssf_error)
                        if _is_data_acceptable(existing, max_age_days=threshold):
                            logger.info(f"Using stale OpenSSF data for {name} ({openssf_error})")
                            cached = _extract_cached_openssf_fields(existing)
                            for key, value in cached.items():
                                if value is not None:
                                    combined_data[key] = value
                            combined_data["openssf_source"] = "cached"
                            combined_data["openssf_freshness"] = "stale"
                            combined_data["openssf_stale_reason"] = openssf_error

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

    sources = data.get("sources", [])

    if ecosystem == "npm":
        # Don't mark as missing if stale fallback provided valid data
        if data.get("npm_error") and "npm_stale" not in sources:
            missing.append("npm")
        # Note: bundlephobia is optional (DX metrics only, not used in health scoring).
        # Errors from bundlephobia should not mark a package as "partial".
    elif ecosystem == "pypi":
        # Don't mark as missing if stale fallback provided valid data
        if data.get("pypi_error") and "pypi_stale" not in sources:
            missing.append("pypi")

    # GitHub is only expected if we have a repository_url
    # Don't mark as missing if stale fallback provided valid data
    if data.get("repository_url") and data.get("github_error") and "github_stale" not in sources:
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
        "openssf_source": data.get("openssf_source"),  # "deps.dev", "direct", "cached", or "cached_fresh"
        "openssf_date": data.get("openssf_date"),      # Date the scorecard was generated
        "openssf_freshness": data.get("openssf_freshness"),      # "fresh", "stale", or None
        "openssf_stale_reason": data.get("openssf_stale_reason"),  # Error that triggered stale fallback
        # Source-specific freshness tracking (Fix 4)
        "npm_freshness": data.get("npm_freshness"),
        "npm_stale_reason": data.get("npm_stale_reason"),
        "github_freshness": data.get("github_freshness"),
        "github_stale_reason": data.get("github_stale_reason"),
        "pypi_freshness": data.get("pypi_freshness"),
        "pypi_stale_reason": data.get("pypi_stale_reason"),
        "bundlephobia_freshness": data.get("bundlephobia_freshness"),
        "bundlephobia_stale_reason": data.get("bundlephobia_stale_reason"),
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

    # Upgrade to abandoned status if max retries reached
    existing_retry = data.get("_existing_retry_count", 0)
    if data_status == "minimal" and existing_retry >= MAX_RETRY_COUNT:
        data_status = "abandoned_minimal"
        logger.info(
            f"Package {ecosystem}/{name} marked as abandoned_minimal "
            f"after {existing_retry} retries"
        )
    elif data_status == "partial" and existing_retry >= MAX_RETRY_COUNT:
        data_status = "abandoned_partial"
        logger.info(
            f"Package {ecosystem}/{name} marked as abandoned_partial "
            f"after {existing_retry} retries"
        )

    item["data_status"] = data_status
    item["missing_sources"] = missing_sources

    # Handle retry tracking based on data completeness
    if data_status == "complete":
        # Reset retry tracking on successful complete collection
        item["retry_count"] = 0
        # Don't set next_retry_at - will be removed by None filter below
    elif data_status in ("abandoned_minimal", "abandoned_partial"):
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


async def process_single_package(
    message: dict,
    bulk_downloads: dict = None
) -> tuple[bool, str, Optional[str]]:
    """Process a single package message with deduplication.

    Args:
        message: SQS message containing package info
        bulk_downloads: Pre-fetched download stats from bulk API (optional)

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
    retry_sources = message.get("retry_sources", [])

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

    # Log what we're about to do
    if retry_sources:
        logger.info(
            f"Selective retry for {ecosystem}/{name} (tier {tier}, sources={retry_sources})"
        )
    else:
        logger.info(f"Collecting data for {ecosystem}/{name} (tier {tier}, force={force_refresh})")

    try:
        # Collect data from all sources (or selectively for retries)
        data = await collect_package_data(ecosystem, name, existing, retry_sources, bulk_downloads)

        # Pass existing retry_count to store_package_data for retry tracking
        # (used to calculate next_retry_at if collection is still incomplete)
        # Note: If this is a retry, we already incremented retry_count in DynamoDB above,
        # so we need to pass the incremented value to avoid overwriting it
        if existing:
            # Convert to int - DynamoDB returns Decimal which can't be used as list index
            base_retry_count = int(existing.get("retry_count", 0))
            # If this is a retry, the count was already incremented in DynamoDB
            data["_existing_retry_count"] = base_retry_count + 1 if is_retry else base_retry_count
        else:
            # Initialize for new packages (first collection attempt)
            data["_existing_retry_count"] = 0

        # Store raw data in S3 for debugging
        store_raw_data(ecosystem, name, data)

        # Store processed data in DynamoDB
        store_package_data(ecosystem, name, data, tier)

        return (True, f"{ecosystem}/{name}", None)
    except Exception as e:
        logger.error(f"Failed to process {ecosystem}/{name}: {e}")
        error_type = type(e).__name__
        error_msg = _sanitize_error(str(e))

        # Store error in package record for DLQ processor to read
        _store_collection_error(ecosystem, name, error_msg)

        return (False, f"{ecosystem}/{name}", error_type)


async def process_batch(records: list) -> tuple[int, list[str]]:
    """Process a batch of SQS records in parallel with metrics.

    Returns:
        Tuple of (success_count, list_of_failed_message_ids)
    """
    start_time = time.time()
    tasks = []
    # Track record info: (message, messageId)
    record_info = []
    # Track messageIds for records that failed to parse
    failed_message_ids = []

    # Parse all messages first to extract npm package names
    parsed_messages = []
    for record in records:
        message_id = record.get("messageId", "")
        try:
            message = json.loads(record["body"])
            parsed_messages.append((message, message_id))
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse message {message_id}: {e}")
            emit_metric("MessageParseError")
            failed_message_ids.append(message_id)

    # Pre-fetch download stats in bulk for npm packages (reduces API calls by ~127x)
    # Only fetch for unscoped packages - scoped packages (@scope/name) must be fetched individually
    npm_packages = [
        msg["name"] for msg, _ in parsed_messages
        if msg.get("ecosystem") == "npm" and not msg["name"].startswith("@")
    ]
    bulk_downloads = {}
    if npm_packages:
        try:
            logger.info(f"Bulk fetching download stats for {len(npm_packages)} npm packages")
            bulk_downloads = await get_bulk_download_stats(npm_packages, "last-week")
            logger.info(f"Bulk fetch returned stats for {len(bulk_downloads)} packages")
        except Exception as e:
            logger.warning(f"Bulk download fetch failed, will fall back to individual: {e}")

    # Create tasks with bulk downloads passed through
    for message, message_id in parsed_messages:
        record_info.append((message, message_id))
        tasks.append(process_single_package(message, bulk_downloads=bulk_downloads))

    # Process all packages in parallel with return_exceptions=True
    # to prevent one failure from canceling others
    results = await asyncio.gather(*tasks, return_exceptions=True)

    successes = 0
    failure_reasons = {}

    for i, result in enumerate(results):
        message, message_id = record_info[i] if i < len(record_info) else ({}, "")
        ecosystem = message.get("ecosystem", "unknown")

        if isinstance(result, Exception):
            logger.error(f"Task {message_id} failed with exception: {result}")
            failed_message_ids.append(message_id)
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
                failed_message_ids.append(message_id)
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
            failed_message_ids.append(message_id)
            failure_reasons["unknown"] = failure_reasons.get("unknown", 0) + 1

    # Emit batch metrics
    batch_duration = time.time() - start_time
    emit_batch_metrics([
        {"metric_name": "BatchProcessingTime", "value": batch_duration, "unit": "Seconds"},
        {"metric_name": "BatchSize", "value": len(records)},
        {"metric_name": "BatchSuccesses", "value": successes},
        {"metric_name": "BatchFailures", "value": len(failed_message_ids)},
    ])

    return successes, failed_message_ids


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
    Returns batchItemFailures for partial batch failure handling - only failed
    messages will be retried, successful ones won't be reprocessed.
    """
    records = event.get("Records", [])
    logger.info(f"Processing {len(records)} messages")

    # Create event loop and process batch
    loop = asyncio.new_event_loop()
    try:
        successes, failed_message_ids = loop.run_until_complete(process_batch(records))
    finally:
        loop.close()

    failures = len(failed_message_ids)
    logger.info(f"Completed: {successes} successes, {failures} failures")

    # Build response with batchItemFailures for partial batch failure handling
    # SQS will only retry the failed messages, not the entire batch
    response = {
        "statusCode": 200,
        "body": json.dumps({
            "processed": successes + failures,
            "successes": successes,
            "failures": failures,
        }),
    }

    # Add batchItemFailures if any messages failed
    # This tells SQS which specific messages to retry
    if failed_message_ids:
        response["batchItemFailures"] = [
            {"itemIdentifier": msg_id} for msg_id in failed_message_ids if msg_id
        ]

    return response
