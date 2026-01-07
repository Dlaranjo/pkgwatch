"""
npm Registry collector - Supplementary data source.

Fetches npm-specific metadata:
- Download statistics
- Maintainer information
- Deprecation status
- Publication timestamps

Rate limit: ~1000 requests/hour (undocumented but conservative)
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_API = "https://api.npmjs.org"
DEFAULT_TIMEOUT = 30.0


def encode_scoped_package(name: str) -> str:
    """
    URL-encode scoped npm package names for the registry API.

    Scoped packages like @babel/core need the forward slash encoded:
    @babel/core -> @babel%2Fcore

    Note: The @ symbol should NOT be encoded for npm registry.
    """
    if name.startswith("@") and "/" in name:
        # Split @scope/name, encode only the slash
        scope, package_name = name.split("/", 1)
        return f"{scope}%2F{package_name}"
    return name


async def retry_with_backoff(
    func,
    *args,
    max_retries: int = 3,
    base_delay: float = 1.0,
    **kwargs,
):
    """Retry async function with exponential backoff."""
    last_exception = None

    for attempt in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            last_exception = e
            if attempt == max_retries - 1:
                logger.error(f"Failed after {max_retries} retries: {e}")
                raise

            delay = base_delay * (2**attempt)
            logger.warning(f"Attempt {attempt + 1} failed, retrying in {delay}s: {e}")
            await asyncio.sleep(delay)

    raise last_exception


async def get_npm_metadata(name: str) -> dict:
    """
    Fetch npm-specific metadata.

    Args:
        name: Package name (e.g., "lodash" or "@babel/core")

    Returns:
        Dictionary with npm metadata including:
        - latest_version
        - created_at
        - last_published
        - maintainers
        - is_deprecated
        - weekly_downloads
        - repository_url
    """
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        # 1. Package metadata from registry
        # Use abbreviated metadata endpoint for faster response
        # URL-encode scoped packages (e.g., @babel/core -> @babel%2Fcore)
        encoded_name = encode_scoped_package(name)
        registry_url = f"{NPM_REGISTRY}/{encoded_name}"
        headers = {"Accept": "application/json"}

        try:
            resp = await retry_with_backoff(client.get, registry_url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"Package not found: {name}")
                return {"error": "package_not_found", "name": name}
            raise

        # Extract latest version
        latest = data.get("dist-tags", {}).get("latest", "")
        time_data = data.get("time", {})

        # Check deprecation status and extract version-specific fields
        is_deprecated = False
        deprecation_message = None
        has_types = False
        module_type = "commonjs"
        has_exports = False
        engines = None

        if latest and "versions" in data:
            version_info = data.get("versions", {}).get(latest, {})

            # Deprecation
            deprecated_field = version_info.get("deprecated")
            if deprecated_field:
                is_deprecated = True
                deprecation_message = deprecated_field if isinstance(deprecated_field, str) else None

            # TypeScript support detection
            has_types = bool(version_info.get("types") or version_info.get("typings"))

            # Module system detection (ESM vs CJS)
            module_type = version_info.get("type", "commonjs")
            has_exports = "exports" in version_info

            # Node.js engine requirements
            engines = version_info.get("engines")

        # Get maintainers
        maintainers = [m.get("name") for m in data.get("maintainers", []) if m.get("name")]

        # Get repository URL
        repository = data.get("repository", {})
        if isinstance(repository, str):
            repository_url = repository
        else:
            repository_url = repository.get("url", "")

        # Clean up repository URL
        if repository_url:
            repository_url = (
                repository_url.replace("git+", "")
                .replace("git://", "https://")
                .replace(".git", "")
            )

        # 2. Download statistics (separate API)
        weekly_downloads = 0
        try:
            downloads_url = f"{NPM_API}/downloads/point/last-week/{name}"
            downloads_resp = await retry_with_backoff(client.get, downloads_url)
            downloads_resp.raise_for_status()
            weekly_downloads = downloads_resp.json().get("downloads", 0)
        except httpx.HTTPStatusError:
            logger.debug(f"Could not fetch download stats for {name}")

        return {
            "name": name,
            "latest_version": latest,
            "created_at": time_data.get("created"),
            "last_published": time_data.get(latest) or time_data.get("modified"),
            "maintainers": maintainers,
            "maintainer_count": len(maintainers),
            "is_deprecated": is_deprecated,
            "deprecation_message": deprecation_message,
            "weekly_downloads": weekly_downloads,
            "repository_url": repository_url,
            "license": data.get("license"),
            "description": data.get("description", ""),
            "keywords": data.get("keywords", []),
            # TypeScript support
            "has_types": has_types,
            # Module system
            "module_type": module_type,
            "has_exports": has_exports,
            # Engine requirements
            "engines": engines,
            "source": "npm",
        }


async def get_download_stats(name: str, period: str = "last-week") -> dict:
    """
    Get download statistics for a package.

    Args:
        name: Package name
        period: Time period (last-day, last-week, last-month, last-year)

    Returns:
        Dictionary with download count and period
    """
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        url = f"{NPM_API}/downloads/point/{period}/{name}"
        try:
            resp = await retry_with_backoff(client.get, url)
            resp.raise_for_status()
            data = resp.json()
            return {
                "downloads": data.get("downloads", 0),
                "start": data.get("start"),
                "end": data.get("end"),
                "package": name,
            }
        except httpx.HTTPStatusError:
            return {"downloads": 0, "package": name, "error": "fetch_failed"}


async def get_bulk_download_stats(packages: list[str], period: str = "last-week") -> dict:
    """
    Get download statistics for multiple packages in bulk.

    npm API supports up to 128 packages per request.

    Args:
        packages: List of package names
        period: Time period

    Returns:
        Dictionary mapping package names to download counts
    """
    results = {}

    # Process in batches of 128
    batch_size = 128
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        for i in range(0, len(packages), batch_size):
            batch = packages[i : i + batch_size]
            scoped = [p for p in batch if p.startswith("@")]
            unscoped = [p for p in batch if not p.startswith("@")]

            # Unscoped packages can use bulk endpoint
            if unscoped:
                packages_str = ",".join(unscoped)
                url = f"{NPM_API}/downloads/point/{period}/{packages_str}"
                try:
                    resp = await retry_with_backoff(client.get, url)
                    resp.raise_for_status()
                    data = resp.json()
                    for pkg_name, pkg_data in data.items():
                        if pkg_data:
                            results[pkg_name] = pkg_data.get("downloads", 0)
                except httpx.HTTPStatusError:
                    # Fall back to individual requests
                    for pkg in unscoped:
                        stats = await get_download_stats(pkg, period)
                        results[pkg] = stats.get("downloads", 0)

            # Scoped packages must be fetched individually
            for pkg in scoped:
                stats = await get_download_stats(pkg, period)
                results[pkg] = stats.get("downloads", 0)

    return results
