"""
OpenSSF Scorecard collector - Direct API integration.

Fetches security scorecards from api.securityscorecards.dev when deps.dev
doesn't have the data.

Note: URL parsing handled by caller using existing parse_github_url() from github_collector.
"""

import logging
from typing import Optional
from urllib.parse import quote

import httpx

from http_client import get_http_client

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

OPENSSF_API = "https://api.securityscorecards.dev"


async def get_openssf_scorecard(owner: str, repo: str) -> Optional[dict]:
    """
    Fetch OpenSSF Scorecard for a GitHub repository.

    Args:
        owner: GitHub repository owner (e.g., "facebook")
        repo: GitHub repository name (e.g., "react")

    Returns:
        Dict with openssf_score and openssf_checks, or None if not found.

    Note: Circuit breaker and rate limit checks should be done by caller.
    """
    if not owner or not repo:
        return None

    # Use shared HTTP client with built-in timeout (15s default)
    client = get_http_client()
    url = f"{OPENSSF_API}/projects/github.com/{quote(owner, safe='')}/{quote(repo, safe='')}"

    try:
        response = await client.get(url)

        if response.status_code == 404:
            logger.debug(f"No OpenSSF scorecard for {owner}/{repo}")
            return None

        # Server errors - return None, don't raise (not transient enough for circuit breaker)
        if response.status_code >= 500:
            logger.warning(f"OpenSSF server error for {owner}/{repo}: {response.status_code}")
            return None

        response.raise_for_status()
        data = response.json()

        # Validate response has expected structure
        score = data.get("score")
        if score is None:
            logger.warning(f"OpenSSF response missing score for {owner}/{repo}")
            return None

        # Transform to match deps.dev format
        # Filter out checks with score=-1 (not applicable)
        checks = [
            {"name": c.get("name"), "score": c.get("score")}
            for c in data.get("checks", [])
            if isinstance(c, dict) and c.get("score", -1) >= 0
        ]

        return {
            "openssf_score": score,
            "openssf_checks": checks,
            "openssf_date": data.get("date"),
            "openssf_source": "direct",
        }

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            logger.warning(f"OpenSSF rate limited for {owner}/{repo}")
            raise  # Propagate for circuit breaker
        logger.warning(f"OpenSSF API error for {owner}/{repo}: {e.response.status_code}")
        return None
    except httpx.TimeoutException:
        logger.warning(f"OpenSSF API timeout for {owner}/{repo}")
        raise  # Propagate for circuit breaker
    except Exception as e:
        logger.warning(f"OpenSSF fetch failed for {owner}/{repo}: {e}")
        return None
