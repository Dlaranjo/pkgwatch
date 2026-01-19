"""
GitHub collector - Secondary data source for repository metrics.

Provides:
- Commit activity (90 days)
- Contributor count
- Stars and forks
- Repository status (archived, etc.)

Rate limit: 5,000 requests/hour with token (single account)
Budget: ~2,400 calls/day for tiered refresh strategy
"""

import asyncio
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

import sys
sys.path.insert(0, os.path.dirname(__file__))  # Add collectors directory
from http_client import get_http_client_with_headers

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

GITHUB_API = "https://api.github.com"
DEFAULT_TIMEOUT = 30.0

# Known bot account patterns that should be filtered from activity metrics
BOT_PATTERNS = [
    "dependabot",
    "renovate",
    "greenkeeper",
    "snyk-bot",
    "github-actions",
    "semantic-release",
    "release-please",
]


def parse_github_url(url: str) -> Optional[tuple[str, str]]:
    """
    Parse GitHub repository URL to extract owner and repo.

    Handles various URL formats:
    - https://github.com/owner/repo
    - git://github.com/owner/repo.git
    - git+https://github.com/owner/repo.git
    - github.com/owner/repo

    Returns:
        Tuple of (owner, repo) or None if not a valid GitHub URL
    """
    if not url:
        return None

    # Normalize URL
    url = url.strip()
    url = url.replace("git+", "").replace("git://", "https://")
    if url.endswith(".git"):
        url = url[:-4]

    # Match GitHub URL pattern
    patterns = [
        r"github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?$",
        r"github\.com[/:]([^/]+)/([^/]+)$",
    ]

    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1), match.group(2)

    return None


class GitHubCollector:
    """
    GitHub API collector with rate limit awareness and retry logic.
    """

    def __init__(self, token: Optional[str] = None):
        """
        Initialize collector with optional token.

        Args:
            token: GitHub Personal Access Token (5K requests/hour)
        """
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"

        self._rate_limit_remaining = 5000
        self._rate_limit_reset: Optional[int] = None

    async def _request_with_retry(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: Optional[dict] = None,
        max_retries: int = 3,
    ) -> Optional[dict]:
        """
        Make request with exponential backoff retry.

        Handles:
        - Rate limiting (403 with X-RateLimit-Remaining: 0)
        - Server errors (5xx)
        - Network errors

        Returns:
            Response JSON or None if not found
        """
        for attempt in range(max_retries):
            try:
                resp = await client.get(url, params=params, headers=self.headers)

                # Track rate limits from response headers
                if "X-RateLimit-Remaining" in resp.headers:
                    self._rate_limit_remaining = int(
                        resp.headers.get("X-RateLimit-Remaining", 5000)
                    )
                if "X-RateLimit-Reset" in resp.headers:
                    self._rate_limit_reset = int(resp.headers.get("X-RateLimit-Reset", 0))

                if resp.status_code == 200:
                    return resp.json()

                elif resp.status_code == 404:
                    logger.debug(f"Resource not found: {url}")
                    return None

                elif resp.status_code == 403:
                    if self._rate_limit_remaining == 0:
                        # Rate limited - calculate wait time
                        now = int(datetime.now(timezone.utc).timestamp())
                        wait_time = max(0, (self._rate_limit_reset or now) - now)
                        wait_time = min(wait_time, 60)  # Cap at 60 seconds
                        logger.warning(f"Rate limited. Waiting {wait_time}s")
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        # Other 403 (e.g., blocked repo)
                        logger.warning(f"Access forbidden: {url}")
                        return None

                elif resp.status_code == 409:
                    # Empty repository (no commits)
                    return []

                elif resp.status_code >= 500:
                    # Server error - retry
                    logger.warning(f"Server error {resp.status_code}, retrying...")

                else:
                    resp.raise_for_status()

            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                if attempt == max_retries - 1:
                    logger.error(f"Failed after {max_retries} retries: {url} - {e}")
                    raise

            # Exponential backoff
            delay = 2**attempt
            await asyncio.sleep(delay)

        return None

    async def get_repo_metrics(self, owner: str, repo: str) -> dict:
        """
        Fetch essential GitHub metrics for a repository.

        Optimized to use minimal API calls (~3-4 per repo):
        1. Repository metadata (stars, forks, issues, updated_at)
        2. Recent commits (last 90 days)
        3. Contributors

        Args:
            owner: Repository owner
            repo: Repository name

        Returns:
            Dictionary with repository metrics
        """
        # Use shared HTTP client with GitHub headers for connection pooling
        client = get_http_client_with_headers(self.headers)
        # 1. Repository metadata (1 call)
        repo_url = f"{GITHUB_API}/repos/{owner}/{repo}"
        repo_data = await self._request_with_retry(client, repo_url)

        if repo_data is None:
            return {
                "error": "repository_not_found",
                "owner": owner,
                "repo": repo,
            }

        # 2. Recent commits (1 call - last 90 days)
        since = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        commits_url = f"{GITHUB_API}/repos/{owner}/{repo}/commits"
        commits = await self._request_with_retry(
            client,
            commits_url,
            params={"since": since, "per_page": 100},
        )
        commits = commits or []

        # 3. Contributors (1 call)
        contributors_url = f"{GITHUB_API}/repos/{owner}/{repo}/contributors"
        contributors = await self._request_with_retry(
            client,
            contributors_url,
            params={"per_page": 100},
        )
        contributors = contributors or []

        # 4. Issues (for response time calculation) (1 call)
        issues_url = f"{GITHUB_API}/repos/{owner}/{repo}/issues"
        issues = await self._request_with_retry(
            client,
            issues_url,
            params={
                "state": "all",
                "since": since,
                "per_page": 100,
                "sort": "created",
                "direction": "desc"
            },
        )
        issues = issues or []

        # 5. Pull Requests (for merge velocity) (1 call)
        prs_url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls"
        prs = await self._request_with_retry(
            client,
            prs_url,
            params={
                "state": "all",
                "since": since,
                "per_page": 100,
                "sort": "created",
                "direction": "desc"
            },
        )
        prs = prs or []

        # Calculate derived metrics
        unique_committers_90d = 0
        true_bus_factor = 1
        bus_factor_confidence = "LOW"
        contribution_distribution = []

        if isinstance(commits, list):
            # Count commits per author (not just unique authors)
            committers: dict[str, int] = {}
            for c in commits:
                if isinstance(c, dict):
                    author = c.get("author")
                    if author and isinstance(author, dict):
                        login = author.get("login")
                        if login:
                            committers[login] = committers.get(login, 0) + 1

            unique_committers_90d = len(committers)

            # Calculate true bus factor: minimum contributors for 50% of commits
            if committers:
                total_commits = sum(committers.values())
                sorted_counts = sorted(committers.values(), reverse=True)

                cumulative = 0
                true_bus_factor = 0
                for count in sorted_counts:
                    cumulative += count
                    true_bus_factor += 1
                    if cumulative >= total_commits * 0.5:
                        break

                # Ensure at least 1
                true_bus_factor = max(1, true_bus_factor)

                # Confidence based on sample size
                if total_commits >= 100:
                    bus_factor_confidence = "HIGH"
                elif total_commits >= 30:
                    bus_factor_confidence = "MEDIUM"
                else:
                    bus_factor_confidence = "LOW"

                # Top 10 contributors for distribution insight
                sorted_contributors = sorted(
                    committers.items(), key=lambda x: -x[1]
                )[:10]
                contribution_distribution = [
                    {"login": login, "commits": count}
                    for login, count in sorted_contributors
                ]

        # Filter bot commits
        commits_90d_non_bot = 0
        if isinstance(commits, list):
            non_bot_commits = [
                c for c in commits
                if isinstance(c, dict) and
                not any(
                    bot in (c.get("author") or {}).get("login", "").lower()
                    for bot in BOT_PATTERNS
                )
            ]
            commits_90d_non_bot = len(non_bot_commits)

        # Days since last commit
        # Primary: most recent commit from 90-day window
        # Fallback: pushed_at from repo metadata (covers commits older than 90 days)
        days_since_commit = None

        if commits and isinstance(commits, list) and len(commits) > 0:
            first_commit = commits[0]
            if isinstance(first_commit, dict):
                commit_info = first_commit.get("commit", {})
                author_info = commit_info.get("author", {})
                last_commit_date = author_info.get("date")

                if last_commit_date:
                    try:
                        last_commit = datetime.fromisoformat(
                            last_commit_date.replace("Z", "+00:00")
                        )
                        days_since_commit = (
                            datetime.now(timezone.utc) - last_commit
                        ).days
                        days_since_commit = max(0, days_since_commit)
                    except ValueError as e:
                        logger.warning(f"Could not parse commit date: {e}")

        # Fallback: Use pushed_at from repo metadata when no commits in 90-day window
        if days_since_commit is None:
            pushed_at = repo_data.get("pushed_at")
            if pushed_at:
                try:
                    pushed_date = datetime.fromisoformat(
                        pushed_at.replace("Z", "+00:00")
                    )
                    # Handle naive datetimes (defensive)
                    if pushed_date.tzinfo is None:
                        pushed_date = pushed_date.replace(tzinfo=timezone.utc)
                    days_since_commit = (
                        datetime.now(timezone.utc) - pushed_date
                    ).days
                    days_since_commit = max(0, days_since_commit)
                    logger.debug(
                        f"Using pushed_at fallback for {owner}/{repo}: "
                        f"{days_since_commit} days (no commits in 90-day window)"
                    )
                except (ValueError, TypeError) as e:
                    logger.warning(
                        f"Could not parse pushed_at date '{pushed_at}': {e}"
                    )

        # Final fallback: truly unknown
        if days_since_commit is None:
            days_since_commit = 999
            logger.info(
                f"No commit activity data for {owner}/{repo}, using 999 days"
            )

        # Calculate issue response time
        # NOTE: This uses heuristic estimation rather than actual response times
        # to avoid additional GitHub API calls (Timeline API requires +1 call per issue)
        avg_issue_response_hours = None
        if isinstance(issues, list):
            # Filter out PRs (GitHub API returns PRs as issues)
            true_issues = [i for i in issues if isinstance(i, dict) and not i.get("pull_request")]
            response_times = []

            for issue in true_issues[:50]:  # Sample up to 50 recent issues
                created_at = issue.get("created_at")
                # Check if issue has comments (indicates response)
                comments = issue.get("comments", 0)
                if created_at and comments > 0:
                    # HEURISTIC ESTIMATION (not actual response time):
                    # - Closed issues with comments: assume 24h average response
                    # - Open issues with comments: assume 48h average response
                    # TODO: Fetch actual response times using GitHub Timeline API
                    # (would require: GET /repos/{owner}/{repo}/issues/{issue_number}/timeline)
                    try:
                        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                        # Use issue state change as proxy for response
                        # Open with comments = likely responded
                        # Closed issues = assume avg 24h response
                        if issue.get("state") == "closed":
                            response_times.append(24)  # Assume 24h for closed issues
                        else:
                            response_times.append(48)  # Assume 48h for open with comments
                    except (ValueError, TypeError):
                        pass

            if response_times:
                avg_issue_response_hours = sum(response_times) / len(response_times)

        # Calculate PR merge velocity
        prs_opened_90d = 0
        prs_merged_90d = 0
        if isinstance(prs, list):
            for pr in prs:
                if isinstance(pr, dict):
                    created_at = pr.get("created_at")
                    if created_at:
                        try:
                            created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                            # Check if created within 90 days
                            if (datetime.now(timezone.utc) - created).days <= 90:
                                prs_opened_90d += 1
                                # Check if merged
                                if pr.get("merged_at"):
                                    prs_merged_90d += 1
                        except (ValueError, TypeError):
                            pass

        # Check for funding (GitHub Sponsors)
        has_funding = False
        if repo_data.get("has_sponsors_listing") or repo_data.get("has_discussions"):
            has_funding = True
        # Also check for funding file in repo metadata
        if "funding" in repo_data:
            has_funding = True

        return {
            "owner": owner,
            "repo": repo,
            "stars": repo_data.get("stargazers_count", 0),
            "forks": repo_data.get("forks_count", 0),
            "open_issues": repo_data.get("open_issues_count", 0),
            "watchers": repo_data.get("watchers_count", 0),
            "updated_at": repo_data.get("updated_at"),
            "pushed_at": repo_data.get("pushed_at"),
            "created_at": repo_data.get("created_at"),
            "days_since_last_commit": days_since_commit,
            "commits_90d": len(commits) if isinstance(commits, list) else 0,
            "commits_90d_non_bot": commits_90d_non_bot,
            "active_contributors_90d": unique_committers_90d,
            "total_contributors": len(contributors) if isinstance(contributors, list) else 0,
            # True bus factor: minimum contributors for 50% of commits
            "true_bus_factor": true_bus_factor,
            "bus_factor_confidence": bus_factor_confidence,
            "contribution_distribution": contribution_distribution,
            # New signals for enhanced scoring
            "avg_issue_response_hours": avg_issue_response_hours,
            "prs_opened_90d": prs_opened_90d,
            "prs_merged_90d": prs_merged_90d,
            "has_funding": has_funding,
            "archived": repo_data.get("archived", False),
            "disabled": repo_data.get("disabled", False),
            "default_branch": repo_data.get("default_branch", "main"),
            "language": repo_data.get("language"),
            "topics": repo_data.get("topics", []),
            "source": "github",
        }

    async def get_repo_metrics_from_url(self, url: str) -> dict:
        """
        Fetch metrics given a repository URL.

        Args:
            url: GitHub repository URL in any format

        Returns:
            Dictionary with repository metrics or error
        """
        parsed = parse_github_url(url)
        if not parsed:
            return {"error": "invalid_github_url", "url": url}

        owner, repo = parsed
        return await self.get_repo_metrics(owner, repo)

    @property
    def rate_limit_remaining(self) -> int:
        """Get remaining rate limit."""
        return self._rate_limit_remaining

    @property
    def rate_limit_reset_at(self) -> Optional[datetime]:
        """Get rate limit reset time."""
        if self._rate_limit_reset:
            return datetime.fromtimestamp(self._rate_limit_reset, tz=timezone.utc)
        return None
