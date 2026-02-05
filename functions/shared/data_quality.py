"""Data quality assessment utilities.

This module provides functions to assess and communicate the completeness
of package data. It distinguishes between:
- VERIFIED: Complete data from all sources
- PARTIAL: Some data sources succeeded but gaps exist
- UNVERIFIED: Missing critical data prevents accurate assessment
- UNAVAILABLE: Package exhausted all retries, data cannot be collected
"""


def get_assessment_category(data_status: str, has_repo: bool) -> str:
    """
    Determine assessment category from data status.

    Args:
        data_status: One of "complete", "partial", "minimal", "abandoned_minimal", or "abandoned_partial"
        has_repo: Whether the package has a repository URL

    Returns:
        Assessment category: "VERIFIED", "PARTIAL", "UNVERIFIED", or "UNAVAILABLE"
    """
    if data_status == "complete":
        return "VERIFIED"
    elif data_status == "partial" and has_repo:
        return "PARTIAL"
    elif data_status in ("abandoned_minimal", "abandoned_partial"):
        return "UNAVAILABLE"
    return "UNVERIFIED"


def get_quality_explanation(
    data_status: str, missing_sources: list, has_repo: bool
) -> str:
    """
    Generate human-readable explanation of data quality.

    Args:
        data_status: One of "complete", "partial", "minimal", "abandoned_minimal", or "abandoned_partial"
        missing_sources: List of data sources that failed (e.g., ["github", "npm"])
        has_repo: Whether the package has a repository URL

    Returns:
        Human-readable explanation string
    """
    if data_status == "complete":
        return "Complete data from all sources"

    if data_status in ("abandoned_minimal", "abandoned_partial"):
        return "Package data unavailable after multiple collection attempts"

    explanations = []
    if not has_repo:
        explanations.append("No repository URL - GitHub metrics unavailable")
    if "github" in missing_sources:
        explanations.append("GitHub data collection failed")
    if "npm" in missing_sources or "pypi" in missing_sources:
        explanations.append("Registry data incomplete")
    if "depsdev" in missing_sources:
        explanations.append("deps.dev data unavailable")

    return "; ".join(explanations) if explanations else "Some data sources unavailable"


def build_data_quality_full(item: dict) -> dict:
    """
    Build full data quality object for GET /packages response.

    This includes all available information about data completeness.

    Args:
        item: DynamoDB item representing a package

    Returns:
        Dictionary with status, assessment, missing_sources, has_repository, explanation
    """
    data_status = item.get("data_status", "minimal")
    missing_sources = item.get("missing_sources") or []
    if not isinstance(missing_sources, list):
        missing_sources = []
    has_repo = bool(item.get("repository_url"))

    return {
        "status": data_status,
        "assessment": get_assessment_category(data_status, has_repo),
        "missing_sources": missing_sources,
        "has_repository": has_repo,
        "explanation": get_quality_explanation(data_status, missing_sources, has_repo),
    }


def build_data_quality_compact(item: dict) -> dict:
    """
    Build compact data quality object for scan results.

    This returns only the essential fields to minimize response size
    when scanning many packages.

    Args:
        item: DynamoDB item representing a package

    Returns:
        Dictionary with assessment and has_repository
    """
    data_status = item.get("data_status", "minimal")
    has_repo = bool(item.get("repository_url"))

    return {
        "assessment": get_assessment_category(data_status, has_repo),
        "has_repository": has_repo,
    }


def is_queryable(data: dict) -> bool:
    """
    Determine if a package has minimum viable data for API queries.

    A package is queryable when it has:
    1. A latest_version (we know something about it)
    2. A health_score (scoring has run)
    3. Either: downloads > 0, dependents > 0, OR data_status is "complete"

    The escape hatch (data_status == "complete") allows packages with
    genuinely zero usage to still be queryable once fully collected.

    Args:
        data: Package data dictionary (from DynamoDB or collection)

    Returns:
        True if package has minimum viable data for API queries
    """
    latest_version = data.get("latest_version")
    health_score = data.get("health_score")
    weekly_downloads = data.get("weekly_downloads", 0)
    dependents_count = data.get("dependents_count", 0)
    data_status = data.get("data_status")

    has_version = latest_version is not None
    has_score = health_score is not None
    has_usage_signal = (
        weekly_downloads > 0 or
        dependents_count > 0 or
        data_status == "complete"
    )

    return has_version and has_score and has_usage_signal
