"""
PyPI Registry collector - Supplementary data source for Python packages.

Fetches PyPI-specific metadata:
- Download statistics (via pypistats.org API, a third-party service)
- Maintainer information
- Deprecation status (via classifiers)
- Publication timestamps
- Python version requirements

Rate limit: Undocumented, be conservative (~500 requests/hour)
Note: pypistats.org is a separate third-party service with its own rate limits.
"""

import asyncio
import json
import logging
import random
import re
from typing import Optional

import httpx

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))  # Add collectors directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))  # Add functions directory
from shared.circuit_breaker import circuit_breaker, PYPI_CIRCUIT
from shared.constants import PYPI_API, PYPISTATS_API, DEFAULT_TIMEOUT
from http_client import get_http_client

# HTTP status codes that are safe to retry
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# PEP 508 normalized package name pattern
# Allows: letters, digits, underscores, hyphens, periods
# Must start and end with alphanumeric
PYPI_PACKAGE_PATTERN = re.compile(
    r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9])$'
)

MAX_PACKAGE_NAME_LENGTH = 128  # PyPI practical limit


def normalize_package_name(name: str) -> str:
    """
    Normalize PyPI package names per PEP 503.

    - Lowercase
    - Replace underscores, hyphens, periods with hyphens
    - Collapse consecutive hyphens

    Examples:
        Django -> django
        Requests_Oauthlib -> requests-oauthlib
        Flask.WTF -> flask-wtf
        foo__bar -> foo-bar
    """
    name = name.lower()
    name = re.sub(r'[-_.]+', '-', name)
    return name


def validate_pypi_package_name(name: str) -> tuple[bool, Optional[str]]:
    """
    Validate PyPI package name format.

    Args:
        name: Package name to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not name:
        return False, "Empty package name"

    if len(name) > MAX_PACKAGE_NAME_LENGTH:
        return False, f"Package name too long: {len(name)} > {MAX_PACKAGE_NAME_LENGTH}"

    # Normalize for validation
    normalized = normalize_package_name(name)

    if not PYPI_PACKAGE_PATTERN.match(normalized):
        return False, "Invalid package name format"

    return True, None


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

    # Should not reach here, but satisfies type checker
    if last_exception:
        raise last_exception
    raise RuntimeError("Retry loop exited unexpectedly")


def _extract_development_status(classifiers: list) -> Optional[str]:
    """
    Extract development status from classifiers.

    Args:
        classifiers: List of PyPI classifiers

    Returns:
        Development status string (e.g., "5 - Production/Stable") or None
    """
    for c in classifiers:
        if c.startswith("Development Status ::"):
            return c.split("::")[-1].strip()
    return None


def _extract_python_versions(classifiers: list) -> list[str]:
    """
    Extract supported Python versions from classifiers.

    Args:
        classifiers: List of PyPI classifiers

    Returns:
        List of Python version strings (e.g., ["3.9", "3.10", "3.11"])
    """
    versions = []
    for c in classifiers:
        if "Programming Language :: Python ::" in c:
            version = c.split("::")[-1].strip()
            if version and version[0].isdigit():
                versions.append(version)
    return versions


def _parse_keywords(keywords) -> list[str]:
    """
    Parse keywords field which may be a string or list.

    Args:
        keywords: Keywords from PyPI info (str, list, or None)

    Returns:
        List of keyword strings
    """
    if not keywords:
        return []
    if isinstance(keywords, list):
        return [k.strip() for k in keywords if isinstance(k, str) and k.strip()]
    if isinstance(keywords, str):
        return [k.strip() for k in keywords.split(",") if k.strip()]
    return []


@circuit_breaker(PYPI_CIRCUIT)
async def get_pypi_metadata(name: str) -> dict:
    """
    Fetch PyPI-specific metadata.

    Args:
        name: Package name (e.g., "requests" or "Flask")

    Returns:
        Dictionary with PyPI metadata including:
        - latest_version
        - created_at (first release)
        - last_published
        - maintainers
        - is_deprecated (from classifiers)
        - weekly_downloads
        - repository_url
        - requires_python
        - classifiers
    """
    # Normalize package name for API call
    normalized_name = normalize_package_name(name)

    client = get_http_client()
    # 1. Package metadata from PyPI JSON API
    pypi_url = f"{PYPI_API}/{normalized_name}/json"

    try:
        resp = await retry_with_backoff(client.get, pypi_url)
        resp.raise_for_status()
        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError) as json_err:
            logger.error(f"Invalid JSON response from PyPI for {name}: {json_err}")
            return {"error": "invalid_json_response", "name": name}
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.warning(f"Package not found: {name}")
            return {"error": "package_not_found", "name": name}
        raise

    info = data.get("info", {})
    releases = data.get("releases", {})

    # Extract latest version
    latest_version = info.get("version", "")

    # Get release dates from all releases
    release_dates = []
    for version, files in releases.items():
        if files:
            # Use upload_time_iso_8601 if available, otherwise upload_time
            upload_time = files[0].get("upload_time_iso_8601") or files[0].get("upload_time")
            if upload_time:
                release_dates.append((version, upload_time))

    # Sort by upload time to get first and last releases
    release_dates.sort(key=lambda x: x[1])
    created_at = release_dates[0][1] if release_dates else None
    last_published = release_dates[-1][1] if release_dates else None

    # Extract maintainers from author/maintainer fields
    maintainers = []
    author = info.get("author")
    maintainer = info.get("maintainer")
    author_email = info.get("author_email")
    maintainer_email = info.get("maintainer_email")

    # Use name if available, otherwise email
    if author:
        maintainers.append(author)
    elif author_email:
        maintainers.append(author_email)

    if maintainer and maintainer != author:
        maintainers.append(maintainer)
    elif maintainer_email and maintainer_email != author_email:
        maintainers.append(maintainer_email)

    # Check deprecation via classifiers
    classifiers = info.get("classifiers", [])
    is_deprecated = any(
        "Development Status :: 7 - Inactive" in c
        for c in classifiers
    )

    # Extract repository URL from project URLs
    project_urls = info.get("project_urls", {}) or {}
    repository_url = (
        project_urls.get("Repository") or
        project_urls.get("Source") or
        project_urls.get("Source Code") or
        project_urls.get("GitHub") or
        project_urls.get("Code") or
        project_urls.get("Homepage") or
        info.get("home_page") or
        info.get("project_url")
    )

    # Clean repository URL (git+, git://, .git suffix)
    if repository_url:
        repository_url = (
            repository_url.replace("git+", "")
            .replace("git://", "https://")
            .replace(".git", "")
        )
        # Only keep GitHub/GitLab/Bitbucket URLs for repo_url (used by GitHub collector)
        # Other URLs are not useful for fetching repo metrics
        if not any(host in repository_url for host in ["github.com", "gitlab.com", "bitbucket.org"]):
            repository_url = None

    # 2. Download statistics from pypistats.org
    weekly_downloads = 0
    downloads_error = None
    try:
        stats_url = f"{PYPISTATS_API}/packages/{normalized_name}/recent?period=week"
        stats_resp = await retry_with_backoff(client.get, stats_url)
        stats_resp.raise_for_status()
        stats_data = stats_resp.json()
        weekly_downloads = stats_data.get("data", {}).get("last_week", 0)
    except httpx.HTTPStatusError as e:
        logger.warning(f"Could not fetch download stats for {name}: HTTP {e.response.status_code}")
        downloads_error = f"http_{e.response.status_code}"
    except Exception as e:
        logger.warning(f"Error fetching pypistats for {name}: {type(e).__name__}")
        downloads_error = f"error_{type(e).__name__}"

    result = {
        "name": name,
        "normalized_name": normalized_name,
        "latest_version": latest_version,
        "created_at": created_at,
        "last_published": last_published,
        "maintainers": maintainers,
        "maintainer_count": len(maintainers),
        "is_deprecated": is_deprecated,
        "weekly_downloads": weekly_downloads,
        "repository_url": repository_url,
        "license": info.get("license"),
        "description": info.get("summary"),
        "keywords": _parse_keywords(info.get("keywords")),
        # PyPI-specific fields
        "requires_python": info.get("requires_python"),
        "classifiers": classifiers,
        "development_status": _extract_development_status(classifiers),
        "python_versions": _extract_python_versions(classifiers),
        "source": "pypi",
    }
    if downloads_error:
        result["downloads_error"] = downloads_error
    return result


async def get_pypi_download_stats(name: str) -> dict:
    """
    Get download statistics for a PyPI package from pypistats.org.

    Args:
        name: Package name

    Returns:
        Dictionary with download counts for different periods
    """
    normalized_name = normalize_package_name(name)

    client = get_http_client()
    try:
        url = f"{PYPISTATS_API}/packages/{normalized_name}/recent"
        resp = await retry_with_backoff(client.get, url)
        resp.raise_for_status()
        data = resp.json()

        return {
            "package": name,
            "last_day": data.get("data", {}).get("last_day", 0),
            "last_week": data.get("data", {}).get("last_week", 0),
            "last_month": data.get("data", {}).get("last_month", 0),
        }
    except httpx.HTTPStatusError:
        return {"package": name, "error": "fetch_failed"}
