"""
Bundlephobia collector - Bundle size data for npm packages.

Fetches bundle size metrics:
- Minified size
- Gzipped size
- Dependency count
- Download time estimates

Rate limit: Unofficial API, be conservative (~100 requests/hour)
"""

import asyncio
import logging
import os
import random
import sys
from typing import Optional
from urllib.parse import quote

import httpx

sys.path.insert(0, os.path.dirname(__file__))  # Add collectors directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))  # Add functions directory
from http_client import get_http_client

from shared.circuit_breaker import BUNDLEPHOBIA_CIRCUIT, circuit_breaker

# HTTP status codes that are safe to retry
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

BUNDLEPHOBIA_API = "https://bundlephobia.com/api/size"
DEFAULT_TIMEOUT = 30.0


def encode_package_spec(name: str, version: Optional[str] = None) -> str:
    """
    URL-encode package specifier for Bundlephobia API.

    Scoped packages need proper encoding:
    @babel/core -> %40babel%2Fcore
    """
    # Encode the package name (including @ and /)
    encoded_name = quote(name, safe="")
    if version:
        encoded_version = quote(version, safe="")
        return f"{encoded_name}@{encoded_version}"
    return encoded_name


async def retry_with_backoff(
    func,
    *args,
    max_retries: int = 3,
    base_delay: float = 1.0,
    **kwargs,
):
    """Retry async function with exponential backoff and equal jitter (50%)."""
    last_exception = None

    for attempt in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except httpx.HTTPStatusError as e:
            # Only retry on server errors and rate limits, not client errors
            if e.response.status_code not in RETRYABLE_STATUS_CODES:
                raise
            last_exception = e
        except httpx.RequestError as e:
            # Network errors are always retryable
            last_exception = e

        if last_exception:
            if attempt == max_retries - 1:
                logger.error(f"Failed after {max_retries} attempts: {last_exception}")
                raise last_exception

            # Equal jitter: 50% fixed backoff + 50% random
            base = base_delay * (2 ** attempt)
            delay = base * 0.5 + random.uniform(0, base * 0.5)
            logger.warning(f"Attempt {attempt + 1} failed, retrying in {delay:.2f}s: {last_exception}")
            await asyncio.sleep(delay)
            last_exception = None

    raise last_exception  # Should not reach here


@circuit_breaker(BUNDLEPHOBIA_CIRCUIT)
async def get_bundle_size(name: str, version: Optional[str] = None) -> dict:
    """
    Fetch bundle size data from Bundlephobia.

    Args:
        name: Package name (e.g., "lodash" or "@babel/core")
        version: Optional specific version (defaults to latest)

    Returns:
        Dictionary with bundle size metrics:
        - size: Minified size in bytes
        - gzip: Gzipped size in bytes
        - dependency_count: Number of dependencies
        - has_side_effects: Whether package has side effects
        - download_time_3g: Estimated download time on 3G
        - download_time_4g: Estimated download time on 4G

    Note:
        Returns empty dict with error field if fetch fails.
        Bundlephobia may not have data for all packages.
    """
    client = get_http_client()
    # Build and encode package specifier (handles scoped packages)
    encoded_spec = encode_package_spec(name, version)

    try:
        url = f"{BUNDLEPHOBIA_API}?package={encoded_spec}"
        resp = await retry_with_backoff(client.get, url)
        resp.raise_for_status()
        data = resp.json()

        # Extract key metrics
        return {
            "name": data.get("name"),
            "version": data.get("version"),
            # Size metrics
            "size": data.get("size", 0),  # Minified size in bytes
            "gzip": data.get("gzip", 0),  # Gzipped size in bytes
            # Dependency info
            "dependency_count": data.get("dependencyCount", 0),
            "has_side_effects": data.get("hasSideEffects", True),
            # Download time estimates (milliseconds)
            # Based on bundlephobia's network speed assumptions
            "download_time_3g": _estimate_download_time(
                data.get("gzip", 0), network="3g"
            ),
            "download_time_4g": _estimate_download_time(
                data.get("gzip", 0), network="4g"
            ),
            # Size categories for quick filtering
            "size_category": _categorize_size(data.get("gzip", 0)),
            "source": "bundlephobia",
        }

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            # Not found is not transient - return error dict
            logger.debug(f"Bundle size not available for {name}")
            return {
                "name": name,
                "error": "not_found",
                "source": "bundlephobia",
            }
        elif e.response.status_code in (429, 504):
            # Transient errors - re-raise so circuit breaker can record failure
            # 429 = rate limited, 504 = timeout for large packages
            logger.warning(f"Bundlephobia transient error {e.response.status_code} for {name}")
            raise
        raise

    except Exception as e:
        logger.error(f"Failed to fetch bundle size for {name}: {e}")
        # Use error code instead of raw exception string (security)
        error_type = type(e).__name__
        return {
            "name": name,
            "error": f"fetch_error:{error_type}",
            "source": "bundlephobia",
        }


def _estimate_download_time(gzip_bytes: int, network: str = "4g") -> int:
    """
    Estimate download time in milliseconds.

    Network speed assumptions (from bundlephobia):
    - 3G: ~400 Kbps effective
    - 4G: ~7 Mbps effective
    """
    if gzip_bytes <= 0:
        return 0

    # Speeds in bytes per millisecond
    speeds = {
        "3g": 50,  # ~400 Kbps = 50 KB/s = 50 B/ms
        "4g": 875,  # ~7 Mbps = 875 KB/s = 875 B/ms
    }
    speed = speeds.get(network, speeds["4g"])
    return max(1, int(gzip_bytes / speed))


def _categorize_size(gzip_bytes: int) -> str:
    """
    Categorize bundle size for quick filtering.

    Categories:
    - tiny: < 5 KB (minimal impact)
    - small: 5-20 KB (acceptable for most use cases)
    - medium: 20-100 KB (consider alternatives for critical paths)
    - large: 100-500 KB (significant, use judiciously)
    - huge: > 500 KB (major impact, likely needs tree-shaking)
    """
    kb = gzip_bytes / 1024

    if kb < 5:
        return "tiny"
    elif kb < 20:
        return "small"
    elif kb < 100:
        return "medium"
    elif kb < 500:
        return "large"
    else:
        return "huge"


async def get_bundle_sizes_batch(packages: list[str]) -> dict[str, dict]:
    """
    Fetch bundle sizes for multiple packages.

    Note: Bundlephobia doesn't have a bulk API, so we fetch sequentially
    with small delays to avoid rate limiting.

    Args:
        packages: List of package names

    Returns:
        Dictionary mapping package names to their bundle size data
    """
    results = {}

    for i, name in enumerate(packages):
        results[name] = await get_bundle_size(name)

        # Delay between requests to respect rate limits (~100/hour = 36s between)
        # Using 2s as a balance between speed and API friendliness
        if i < len(packages) - 1:
            await asyncio.sleep(2.0)

    return results
