"""
deps.dev collector - Primary data source for PkgWatch.

deps.dev provides comprehensive package data with NO rate limits:
- Package versions and metadata
- Dependencies (direct + transitive)
- Dependents count
- Security advisories
- OpenSSF Scorecard scores
- License information
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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))  # Add functions directory
from http_client import get_http_client

from shared.circuit_breaker import DEPSDEV_CIRCUIT, circuit_breaker
from shared.constants import DEPSDEV_API, DEPSDEV_API_ALPHA

# HTTP status codes that are safe to retry
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def encode_package_name(name: str) -> str:
    """
    URL-encode package names for deps.dev API.

    Scoped packages like @babel/core must be encoded:
    @babel/core -> %40babel%2Fcore
    """
    return quote(name, safe="")


def encode_repo_url(url: str) -> str:
    """
    Encode repository URL for deps.dev projects endpoint.

    github.com/lodash/lodash -> github.com%2Flodash%2Flodash
    """
    return quote(url, safe="")


def cvss_to_severity(score) -> str:
    """Map CVSS v3 score to severity string per NVD thresholds."""
    if score is None:
        return "UNKNOWN"
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


MAX_ADVISORY_DETAIL_FETCHES = 50


async def fetch_advisory_details(advisory_keys: list, client) -> list[dict]:
    """
    Fetch full advisory details from /v3/advisories/{id} for each advisory key.

    The deps.dev version endpoint returns advisoryKeys with only IDs.
    This function enriches each advisory with title, severity, CVSS score, etc.
    """
    if not advisory_keys:
        return []

    advisories = []
    for key in advisory_keys[:MAX_ADVISORY_DETAIL_FETCHES]:
        advisory_id = key.get("id", "")
        if not advisory_id:
            continue
        url = f"{DEPSDEV_API}/advisories/{quote(advisory_id, safe='')}"
        try:
            resp = await retry_with_backoff(client.get, url, max_retries=2, base_delay=0.5)
            if resp.status_code == 404:
                logger.debug(f"Advisory {advisory_id} not found")
                continue
            resp.raise_for_status()
            data = resp.json()
            cvss3 = data.get("cvss3Score")
            advisories.append(
                {
                    "id": advisory_id,
                    "url": data.get("url", ""),
                    "title": data.get("title", ""),
                    "aliases": data.get("aliases", []),
                    "cvss3_score": cvss3,
                    "severity": cvss_to_severity(cvss3),
                }
            )
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            logger.warning(f"Failed to fetch advisory {advisory_id}: {e}")
            advisories.append({"id": advisory_id, "severity": "UNKNOWN"})

    return advisories


async def retry_with_backoff(
    func,
    *args,
    max_retries: int = 3,
    base_delay: float = 1.0,
    **kwargs,
):
    """
    Retry async function with exponential backoff and equal jitter (50%).

    Args:
        func: Async function to retry
        max_retries: Total number of attempts
        base_delay: Base delay in seconds (doubles each retry)
    """
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
            base = base_delay * (2**attempt)
            delay = base * 0.5 + random.uniform(0, base * 0.5)
            logger.warning(f"Attempt {attempt + 1} failed, retrying in {delay:.2f}s: {last_exception}")
            await asyncio.sleep(delay)
            last_exception = None

    raise last_exception  # Should not reach here


@circuit_breaker(DEPSDEV_CIRCUIT)
async def get_package_info(name: str, ecosystem: str = "npm") -> Optional[dict]:
    """
    Fetch comprehensive package data from deps.dev.

    Returns:
        - Version info
        - Dependencies (direct + transitive count)
        - Dependents count (who uses this)
        - Security advisories
        - License
        - OpenSSF Scorecard
        - GitHub repo link
        - None if package not found (404)

    Raises:
        httpx.HTTPStatusError: For API errors other than 404
    """
    encoded_name = encode_package_name(name)

    client = get_http_client()
    # 1. Get package versions
    pkg_url = f"{DEPSDEV_API}/systems/{ecosystem}/packages/{encoded_name}"
    try:
        pkg_resp = await retry_with_backoff(client.get, pkg_url)
        # Handle 404 gracefully - package not found is not an error
        if pkg_resp.status_code == 404:
            logger.info(f"Package {name} not found in deps.dev")
            return None
        pkg_resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.info(f"Package {name} not found in deps.dev")
            return None
        raise
    pkg_data = pkg_resp.json()

    # 2. Get default (stable) version - used for dependents count
    # The defaultVersion field is often null, so we look for isDefault: true
    latest_version = pkg_data.get("defaultVersion", "")
    if not latest_version:
        versions = pkg_data.get("versions", [])
        # First, try to find the version marked as default (stable release)
        for v in versions:
            if v.get("isDefault"):
                latest_version = v.get("versionKey", {}).get("version", "")
                break
        # Fallback to last version if no default found
        if not latest_version and versions:
            latest_version = versions[-1].get("versionKey", {}).get("version", "")

    version_data = {}
    if latest_version:
        encoded_version = quote(latest_version, safe="")
        version_url = f"{DEPSDEV_API}/systems/{ecosystem}/packages/{encoded_name}/versions/{encoded_version}"
        try:
            version_resp = await retry_with_backoff(client.get, version_url)
            version_resp.raise_for_status()
            version_data = version_resp.json()
        except httpx.HTTPStatusError as e:
            logger.warning(f"Could not fetch version data for {name}@{latest_version}: {e}")

    # 3. Get project info (includes OpenSSF score)
    project_data = {}
    links = version_data.get("links", [])
    repo_url = None

    # Find repository link
    for link in links:
        if link.get("label") == "SOURCE_REPO":
            repo_url = link.get("url") or None
            break

    if repo_url:
        # Clean up URL for deps.dev project endpoint
        # e.g., "https://github.com/lodash/lodash" -> "github.com/lodash/lodash"
        clean_url = repo_url.replace("https://", "").replace("http://", "")
        if clean_url.endswith(".git"):
            clean_url = clean_url[:-4]

        encoded_project = encode_repo_url(clean_url)
        project_url = f"{DEPSDEV_API}/projects/{encoded_project}"

        try:
            project_resp = await retry_with_backoff(client.get, project_url)
            project_resp.raise_for_status()
            project_data = project_resp.json()
        except httpx.HTTPStatusError:
            logger.debug(f"Project not found for {name}: {clean_url}")

    # 4. Get dependents count (with version fallback for indexing lag)
    # Note: Dependents endpoint only exists in v3alpha, not stable v3 API
    # deps.dev may return 404 for newly published versions not yet indexed,
    # so we walk back up to 3 older non-deprecated versions as fallback.
    dependents_count = 0
    if latest_version:
        versions_list = pkg_data.get("versions", [])
        non_deprecated_versions = [
            v.get("versionKey", {}).get("version", "")
            for v in versions_list
            if v.get("versionKey", {}).get("version") and not v.get("isDeprecated")
        ]

        # Always try latest first, then walk back through older versions
        candidates = [latest_version]
        if latest_version in non_deprecated_versions:
            idx = non_deprecated_versions.index(latest_version)
            for i in range(idx - 1, max(idx - 3, -1), -1):
                candidates.append(non_deprecated_versions[i])

        for candidate_ver in candidates:
            try:
                encoded_version = quote(candidate_ver, safe="")
                dependents_url = (
                    f"{DEPSDEV_API_ALPHA}/systems/{ecosystem}/packages/"
                    f"{encoded_name}/versions/{encoded_version}:dependents"
                )
                dependents_resp = await retry_with_backoff(client.get, dependents_url)
                dependents_resp.raise_for_status()
                dependents_data = dependents_resp.json()
                dependent_count_value = dependents_data.get("dependentCount")
                if isinstance(dependent_count_value, int) and dependent_count_value > 0:
                    dependents_count = dependent_count_value
                    if candidate_ver != latest_version:
                        logger.info(
                            f"Dependents fallback: {name}@{latest_version} -> "
                            f"{name}@{candidate_ver} (dependents={dependents_count})"
                        )
                    break
                elif isinstance(dependent_count_value, list):
                    count = len(dependent_count_value)
                    if count > 0:
                        dependents_count = count
                        break
                # 0 or missing — try next version
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    logger.debug(f"No dependents data for {name}@{candidate_ver}")
                    continue
                else:
                    logger.warning(
                        f"Failed to fetch dependents for {name}@{candidate_ver}: HTTP {e.response.status_code}"
                    )
                    break
            except httpx.RequestError:
                logger.warning(f"Network error fetching dependents for {name}@{candidate_ver}")
                break

    # Extract OpenSSF scorecard
    scorecard = project_data.get("scorecardV2", {})
    openssf_score = scorecard.get("score")
    openssf_checks = scorecard.get("check", [])

    return {
        "name": name,
        "ecosystem": ecosystem,
        "latest_version": latest_version,
        "published_at": version_data.get("publishedAt"),
        "licenses": version_data.get("licenses", []),
        "dependencies_direct": len(version_data.get("relations", {}).get("dependencies", [])),
        "advisories": await fetch_advisory_details(version_data.get("advisoryKeys", []), client),
        "repository_url": repo_url,
        "openssf_score": openssf_score,
        "openssf_checks": openssf_checks,
        "stars": project_data.get("starsCount"),
        "forks": project_data.get("forksCount"),
        "dependents_count": dependents_count,
        "source": "deps.dev",
    }


@circuit_breaker(DEPSDEV_CIRCUIT)
async def get_dependencies(name: str, ecosystem: str = "npm") -> list[str]:
    """
    Get direct dependencies for a package from deps.dev.

    Used by graph expander to discover new packages through dependency crawling.

    Returns:
        List of dependency package names (direct dependencies only).
        Empty list if package not found or on error.
    """
    encoded_name = encode_package_name(name)

    client = get_http_client()
    # 1. Get package to find latest version
    pkg_url = f"{DEPSDEV_API}/systems/{ecosystem}/packages/{encoded_name}"
    try:
        pkg_resp = await retry_with_backoff(client.get, pkg_url)
        if pkg_resp.status_code == 404:
            return []
        pkg_resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return []
        raise

    pkg_data = pkg_resp.json()

    # 2. Find latest/default version
    latest_version = pkg_data.get("defaultVersion", "")
    if not latest_version:
        versions = pkg_data.get("versions", [])
        for v in versions:
            if v.get("isDefault"):
                latest_version = v.get("versionKey", {}).get("version", "")
                break
        if not latest_version and versions:
            latest_version = versions[-1].get("versionKey", {}).get("version", "")

    if not latest_version:
        return []

    # 3. Get dependencies for this version
    encoded_version = quote(latest_version, safe="")
    deps_url = f"{DEPSDEV_API}/systems/{ecosystem}/packages/{encoded_name}/versions/{encoded_version}:dependencies"

    try:
        deps_resp = await retry_with_backoff(client.get, deps_url)
        deps_resp.raise_for_status()
    except httpx.HTTPStatusError:
        logger.debug(f"Could not fetch dependencies for {name}@{latest_version}")
        return []

    deps_data = deps_resp.json()
    nodes = deps_data.get("nodes", [])

    # 4. Extract direct dependencies only
    # The first node is the package itself, remaining are dependencies
    # Filter by relation == "DIRECT" to get only direct deps
    direct_deps = []
    for node in nodes:
        relation = node.get("relation")
        if relation == "DIRECT":
            version_key = node.get("versionKey", {})
            dep_name = version_key.get("name")
            dep_ecosystem = version_key.get("system", "").lower()
            # Only include deps from same ecosystem
            if dep_name and dep_name != name and dep_ecosystem == ecosystem:
                direct_deps.append(dep_name)

    return direct_deps
