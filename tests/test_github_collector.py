"""
Tests for GitHub collector.

Tests cover:
- GitHub URL parsing (various formats)
- Repository metrics fetching
- Rate limiting behavior
- Bus factor calculation
- Bot filtering from commit activity
- Issue response time estimation
- PR merge velocity
- Error handling (404, 403, network errors)

Run with: PYTHONPATH=functions:. pytest tests/test_github_collector.py -v
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx
import pytest

# Add functions directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions", "collectors"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions", "shared"))


def run_async(coro):
    """Helper to run async functions in sync tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def create_mock_transport(handler):
    """Create a mock transport for httpx that routes requests to handler."""
    async def mock_handler(request: httpx.Request) -> httpx.Response:
        return handler(request)
    return httpx.MockTransport(mock_handler)


# =============================================================================
# URL PARSING TESTS
# =============================================================================


class TestParseGitHubUrl:
    """Tests for parse_github_url function."""

    def test_parse_https_url(self):
        """Parse standard HTTPS GitHub URL."""
        from github_collector import parse_github_url

        result = parse_github_url("https://github.com/lodash/lodash")
        assert result == ("lodash", "lodash")

    def test_parse_git_protocol_url(self):
        """Parse git:// protocol URL."""
        from github_collector import parse_github_url

        result = parse_github_url("git://github.com/facebook/react.git")
        assert result == ("facebook", "react")

    def test_parse_git_plus_https_url(self):
        """Parse git+https:// URL format."""
        from github_collector import parse_github_url

        result = parse_github_url("git+https://github.com/babel/babel.git")
        assert result == ("babel", "babel")

    def test_parse_ssh_url(self):
        """Parse SSH-style GitHub URL."""
        from github_collector import parse_github_url

        result = parse_github_url("git@github.com:vercel/next.js.git")
        assert result == ("vercel", "next.js")

    def test_parse_url_without_protocol(self):
        """Parse URL without protocol prefix."""
        from github_collector import parse_github_url

        result = parse_github_url("github.com/vuejs/vue")
        assert result == ("vuejs", "vue")

    def test_parse_url_with_trailing_git(self):
        """Parse URL with .git suffix."""
        from github_collector import parse_github_url

        result = parse_github_url("https://github.com/expressjs/express.git")
        assert result == ("expressjs", "express")

    def test_parse_url_with_whitespace(self):
        """Parse URL with leading/trailing whitespace."""
        from github_collector import parse_github_url

        result = parse_github_url("  https://github.com/axios/axios  ")
        assert result == ("axios", "axios")

    def test_parse_empty_url(self):
        """Return None for empty URL."""
        from github_collector import parse_github_url

        assert parse_github_url("") is None
        assert parse_github_url(None) is None

    def test_parse_invalid_url(self):
        """Return None for non-GitHub URLs."""
        from github_collector import parse_github_url

        assert parse_github_url("https://gitlab.com/user/repo") is None
        assert parse_github_url("https://bitbucket.org/user/repo") is None
        assert parse_github_url("not-a-url") is None

    def test_parse_github_url_with_path(self):
        """Parse GitHub URL that has extra path components."""
        from github_collector import parse_github_url

        result = parse_github_url("https://github.com/microsoft/TypeScript")
        assert result == ("microsoft", "TypeScript")


# =============================================================================
# GITHUB COLLECTOR INITIALIZATION TESTS
# =============================================================================


class TestGitHubCollectorInit:
    """Tests for GitHubCollector initialization."""

    def test_collector_init_with_token(self):
        """Collector should set Authorization header with token."""
        from github_collector import GitHubCollector

        collector = GitHubCollector(token="ghp_test_token")
        assert "Authorization" in collector.headers
        assert collector.headers["Authorization"] == "Bearer ghp_test_token"

    def test_collector_init_from_env(self):
        """Collector should read token from environment."""
        from github_collector import GitHubCollector

        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_env_token"}):
            collector = GitHubCollector()
            assert collector.token == "ghp_env_token"

    def test_collector_init_without_token(self):
        """Collector should work without token (reduced rate limit)."""
        from github_collector import GitHubCollector

        with patch.dict(os.environ, {}, clear=True):
            # Remove GITHUB_TOKEN from env
            if "GITHUB_TOKEN" in os.environ:
                del os.environ["GITHUB_TOKEN"]
            collector = GitHubCollector()
            assert "Authorization" not in collector.headers

    def test_collector_rate_limit_tracking(self):
        """Collector should track rate limit from headers."""
        from github_collector import GitHubCollector

        collector = GitHubCollector(token="ghp_test")
        assert collector.rate_limit_remaining == 5000  # Initial value


# =============================================================================
# REPO METRICS TESTS
# =============================================================================


class TestGetRepoMetrics:
    """Tests for get_repo_metrics method."""

    def _create_repo_response(self, **overrides):
        """Create a mock GitHub repo API response."""
        base = {
            "stargazers_count": 58000,
            "forks_count": 7000,
            "open_issues_count": 120,
            "watchers_count": 58000,
            "updated_at": "2024-01-15T10:00:00Z",
            "pushed_at": "2024-01-14T08:00:00Z",
            "created_at": "2012-04-28T00:00:00Z",
            "archived": False,
            "disabled": False,
            "default_branch": "main",
            "language": "JavaScript",
            "topics": ["utility", "lodash"],
            "has_sponsors_listing": False,
        }
        base.update(overrides)
        return base

    def _create_commits_response(self, count=3, days_ago=7):
        """Create a mock commits API response."""
        commits = []
        for i in range(count):
            commit_date = (datetime.now(timezone.utc) - timedelta(days=days_ago + i)).isoformat()
            commits.append({
                "author": {"login": f"contributor{i}"},
                "commit": {"author": {"date": commit_date}},
            })
        return commits

    def test_successful_repo_metrics_fetch(self):
        """Test successful repo metrics fetch."""
        from github_collector import GitHubCollector

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)

            if "/repos/lodash/lodash/commits" in url:
                return httpx.Response(
                    200,
                    json=self._create_commits_response(count=10, days_ago=5),
                    headers={"X-RateLimit-Remaining": "4998"},
                )
            elif "/repos/lodash/lodash/contributors" in url:
                return httpx.Response(
                    200,
                    json=[
                        {"login": "jdalton", "contributions": 1000},
                        {"login": "contributor1", "contributions": 50},
                    ],
                    headers={"X-RateLimit-Remaining": "4997"},
                )
            elif "/repos/lodash/lodash/issues" in url:
                return httpx.Response(200, json=[])
            elif "/repos/lodash/lodash/pulls" in url:
                return httpx.Response(200, json=[])
            elif "/repos/lodash/lodash" in url:
                return httpx.Response(
                    200,
                    json=self._create_repo_response(),
                    headers={
                        "X-RateLimit-Remaining": "4999",
                        "X-RateLimit-Reset": "1700000000",
                    },
                )

            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("lodash", "lodash"))

            assert result["owner"] == "lodash"
            assert result["repo"] == "lodash"
            assert result["stars"] == 58000
            assert result["forks"] == 7000
            assert result["commits_90d"] == 10
            assert result["total_contributors"] == 2
            assert result["archived"] is False
            assert result["source"] == "github"

    def test_repo_not_found(self):
        """Test 404 response handling."""
        from github_collector import GitHubCollector

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("nonexistent", "repo"))

            assert result["error"] == "repository_not_found"
            assert result["owner"] == "nonexistent"
            assert result["repo"] == "repo"

    def test_repo_access_forbidden(self):
        """Test 403 response handling (blocked repo, not rate limit)."""
        from github_collector import GitHubCollector

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/repos/private/repo" in url and "commits" not in url and "contributors" not in url:
                return httpx.Response(
                    403,
                    headers={"X-RateLimit-Remaining": "100"},
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("private", "repo"))

            assert result["error"] == "repository_not_found"

    def test_empty_repository_409(self):
        """Test 409 response (empty repo with no commits)."""
        from github_collector import GitHubCollector

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                return httpx.Response(409)  # Empty repo
            elif "/contributors" in url:
                return httpx.Response(200, json=[])
            elif "/issues" in url:
                return httpx.Response(200, json=[])
            elif "/pulls" in url:
                return httpx.Response(200, json=[])
            elif "/repos/empty/repo" in url:
                return httpx.Response(
                    200,
                    json=self._create_repo_response(stargazers_count=0, forks_count=0),
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("empty", "repo"))

            assert result["commits_90d"] == 0
            assert result["active_contributors_90d"] == 0

    def test_archived_repository(self):
        """Test detection of archived repository."""
        from github_collector import GitHubCollector

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                return httpx.Response(200, json=[])
            elif "/contributors" in url:
                return httpx.Response(200, json=[])
            elif "/issues" in url:
                return httpx.Response(200, json=[])
            elif "/pulls" in url:
                return httpx.Response(200, json=[])
            elif "/repos/archived/repo" in url:
                return httpx.Response(
                    200,
                    json=self._create_repo_response(archived=True),
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("archived", "repo"))

            assert result["archived"] is True


# =============================================================================
# DAYS SINCE COMMIT TESTS
# =============================================================================


class TestDaysSinceCommit:
    """Tests for days_since_last_commit calculation."""

    def _create_repo_response(self, **overrides):
        """Create a mock GitHub repo API response."""
        base = {
            "stargazers_count": 1000,
            "forks_count": 100,
            "open_issues_count": 5,
            "watchers_count": 1000,
            "created_at": "2020-01-01T00:00:00Z",
            "archived": False,
            "disabled": False,
            "default_branch": "main",
        }
        base.update(overrides)
        return base

    def test_days_from_recent_commit(self):
        """When commits exist in 90-day window, should use commit date."""
        from github_collector import GitHubCollector

        commit_date = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        pushed_at_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                return httpx.Response(200, json=[{
                    "author": {"login": "dev"},
                    "commit": {"author": {"date": commit_date}},
                }])
            elif "/contributors" in url:
                return httpx.Response(200, json=[{"login": "dev", "contributions": 100}])
            elif "/issues" in url:
                return httpx.Response(200, json=[])
            elif "/pulls" in url:
                return httpx.Response(200, json=[])
            elif "/repos/active/repo" in url:
                return httpx.Response(200, json=self._create_repo_response(
                    pushed_at=pushed_at_date,
                    updated_at=commit_date,
                ))
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("active", "repo"))

            # Should use commit date (7 days), not pushed_at (30 days)
            assert result["days_since_last_commit"] == 7

    def test_fallback_to_pushed_at(self):
        """When commits list is empty but pushed_at exists, should use pushed_at."""
        from github_collector import GitHubCollector

        pushed_at_date = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                return httpx.Response(200, json=[])  # No commits in 90-day window
            elif "/contributors" in url:
                return httpx.Response(200, json=[{"login": "dev", "contributions": 100}])
            elif "/issues" in url:
                return httpx.Response(200, json=[])
            elif "/pulls" in url:
                return httpx.Response(200, json=[])
            elif "/repos/stable/package" in url:
                return httpx.Response(200, json=self._create_repo_response(
                    pushed_at=pushed_at_date,
                    updated_at=pushed_at_date,
                ))
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("stable", "package"))

            # Should use pushed_at (120 days), NOT default to 999
            assert result["days_since_last_commit"] == 120
            assert result["commits_90d"] == 0

    def test_999_when_no_activity_data(self):
        """When both commits and pushed_at are unavailable, should use 999."""
        from github_collector import GitHubCollector

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                return httpx.Response(200, json=[])
            elif "/contributors" in url:
                return httpx.Response(200, json=[])
            elif "/issues" in url:
                return httpx.Response(200, json=[])
            elif "/pulls" in url:
                return httpx.Response(200, json=[])
            elif "/repos/unknown/repo" in url:
                return httpx.Response(200, json=self._create_repo_response())
                # No pushed_at field
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("unknown", "repo"))

            assert result["days_since_last_commit"] == 999

    def test_future_date_clamped_to_zero(self):
        """Future pushed_at date should be clamped to 0."""
        from github_collector import GitHubCollector

        future_date = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                return httpx.Response(200, json=[])
            elif "/contributors" in url:
                return httpx.Response(200, json=[])
            elif "/issues" in url:
                return httpx.Response(200, json=[])
            elif "/pulls" in url:
                return httpx.Response(200, json=[])
            elif "/repos/future/repo" in url:
                return httpx.Response(200, json=self._create_repo_response(
                    pushed_at=future_date,
                ))
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("future", "repo"))

            # Future dates should be clamped to 0
            assert result["days_since_last_commit"] == 0


# =============================================================================
# BUS FACTOR TESTS
# =============================================================================


class TestBusFactor:
    """Tests for bus factor calculation."""

    def _create_repo_response(self):
        """Create a mock GitHub repo API response."""
        return {
            "stargazers_count": 1000,
            "forks_count": 100,
            "open_issues_count": 5,
            "watchers_count": 1000,
            "pushed_at": datetime.now(timezone.utc).isoformat(),
            "created_at": "2020-01-01T00:00:00Z",
            "archived": False,
            "disabled": False,
            "default_branch": "main",
        }

    def test_bus_factor_single_contributor(self):
        """Bus factor should be 1 with single contributor."""
        from github_collector import GitHubCollector

        commit_date = datetime.now(timezone.utc).isoformat()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                # Single contributor with all commits
                return httpx.Response(200, json=[
                    {"author": {"login": "solo_dev"}, "commit": {"author": {"date": commit_date}}},
                    {"author": {"login": "solo_dev"}, "commit": {"author": {"date": commit_date}}},
                    {"author": {"login": "solo_dev"}, "commit": {"author": {"date": commit_date}}},
                ])
            elif "/contributors" in url:
                return httpx.Response(200, json=[{"login": "solo_dev", "contributions": 100}])
            elif "/issues" in url:
                return httpx.Response(200, json=[])
            elif "/pulls" in url:
                return httpx.Response(200, json=[])
            elif "/repos/solo/project" in url:
                return httpx.Response(200, json=self._create_repo_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("solo", "project"))

            assert result["true_bus_factor"] == 1
            assert result["active_contributors_90d"] == 1

    def test_bus_factor_distributed_contributions(self):
        """Bus factor should be higher with distributed contributions."""
        from github_collector import GitHubCollector

        commit_date = datetime.now(timezone.utc).isoformat()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                # Multiple contributors with even distribution
                commits = []
                for i in range(30):
                    contributor = f"dev{i % 5}"  # 5 contributors, 6 commits each
                    commits.append({
                        "author": {"login": contributor},
                        "commit": {"author": {"date": commit_date}},
                    })
                return httpx.Response(200, json=commits)
            elif "/contributors" in url:
                return httpx.Response(200, json=[
                    {"login": "dev0", "contributions": 100},
                    {"login": "dev1", "contributions": 100},
                    {"login": "dev2", "contributions": 100},
                    {"login": "dev3", "contributions": 100},
                    {"login": "dev4", "contributions": 100},
                ])
            elif "/issues" in url:
                return httpx.Response(200, json=[])
            elif "/pulls" in url:
                return httpx.Response(200, json=[])
            elif "/repos/team/project" in url:
                return httpx.Response(200, json=self._create_repo_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("team", "project"))

            # With even distribution among 5 contributors,
            # bus factor should be ~3 (need 3 contributors for 50% of commits)
            assert result["true_bus_factor"] >= 2
            assert result["active_contributors_90d"] == 5

    def test_bus_factor_confidence_levels(self):
        """Bus factor confidence should reflect sample size."""
        from github_collector import GitHubCollector

        commit_date = datetime.now(timezone.utc).isoformat()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                # 100+ commits for HIGH confidence
                commits = []
                for i in range(100):
                    commits.append({
                        "author": {"login": f"dev{i % 10}"},
                        "commit": {"author": {"date": commit_date}},
                    })
                return httpx.Response(200, json=commits)
            elif "/contributors" in url:
                return httpx.Response(200, json=[{"login": f"dev{i}", "contributions": 10} for i in range(10)])
            elif "/issues" in url:
                return httpx.Response(200, json=[])
            elif "/pulls" in url:
                return httpx.Response(200, json=[])
            elif "/repos/large/project" in url:
                return httpx.Response(200, json=self._create_repo_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("large", "project"))

            assert result["bus_factor_confidence"] == "HIGH"


# =============================================================================
# BOT FILTERING TESTS
# =============================================================================


class TestBotFiltering:
    """Tests for filtering bot commits from activity metrics."""

    def _create_repo_response(self):
        """Create a mock GitHub repo API response."""
        return {
            "stargazers_count": 1000,
            "forks_count": 100,
            "open_issues_count": 5,
            "watchers_count": 1000,
            "pushed_at": datetime.now(timezone.utc).isoformat(),
            "created_at": "2020-01-01T00:00:00Z",
            "archived": False,
            "disabled": False,
            "default_branch": "main",
        }

    def test_filter_dependabot_commits(self):
        """Dependabot commits should be filtered from non-bot count."""
        from github_collector import GitHubCollector

        commit_date = datetime.now(timezone.utc).isoformat()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                return httpx.Response(200, json=[
                    {"author": {"login": "dependabot[bot]"}, "commit": {"author": {"date": commit_date}}},
                    {"author": {"login": "dependabot"}, "commit": {"author": {"date": commit_date}}},
                    {"author": {"login": "human_dev"}, "commit": {"author": {"date": commit_date}}},
                ])
            elif "/contributors" in url:
                return httpx.Response(200, json=[])
            elif "/issues" in url:
                return httpx.Response(200, json=[])
            elif "/pulls" in url:
                return httpx.Response(200, json=[])
            elif "/repos/bot/repo" in url:
                return httpx.Response(200, json=self._create_repo_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("bot", "repo"))

            assert result["commits_90d"] == 3  # Total commits
            assert result["commits_90d_non_bot"] == 1  # Only human commits

    def test_filter_multiple_bot_types(self):
        """Various bot types should be filtered."""
        from github_collector import GitHubCollector

        commit_date = datetime.now(timezone.utc).isoformat()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                return httpx.Response(200, json=[
                    {"author": {"login": "renovate[bot]"}, "commit": {"author": {"date": commit_date}}},
                    {"author": {"login": "greenkeeper[bot]"}, "commit": {"author": {"date": commit_date}}},
                    {"author": {"login": "snyk-bot"}, "commit": {"author": {"date": commit_date}}},
                    {"author": {"login": "github-actions"}, "commit": {"author": {"date": commit_date}}},
                    {"author": {"login": "semantic-release-bot"}, "commit": {"author": {"date": commit_date}}},
                    {"author": {"login": "release-please[bot]"}, "commit": {"author": {"date": commit_date}}},
                    {"author": {"login": "real_dev"}, "commit": {"author": {"date": commit_date}}},
                ])
            elif "/contributors" in url:
                return httpx.Response(200, json=[])
            elif "/issues" in url:
                return httpx.Response(200, json=[])
            elif "/pulls" in url:
                return httpx.Response(200, json=[])
            elif "/repos/bots/repo" in url:
                return httpx.Response(200, json=self._create_repo_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("bots", "repo"))

            assert result["commits_90d"] == 7
            assert result["commits_90d_non_bot"] == 1


# =============================================================================
# RATE LIMIT TESTS
# =============================================================================


class TestRateLimiting:
    """Tests for rate limit handling."""

    def test_rate_limit_tracking(self):
        """Collector should track rate limit from response headers."""
        from github_collector import GitHubCollector

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/repos/test/repo" in url:
                return httpx.Response(
                    200,
                    json={
                        "stargazers_count": 100,
                        "forks_count": 10,
                        "open_issues_count": 5,
                        "watchers_count": 100,
                        "pushed_at": datetime.now(timezone.utc).isoformat(),
                        "archived": False,
                        "disabled": False,
                        "default_branch": "main",
                    },
                    headers={
                        "X-RateLimit-Remaining": "4500",
                        "X-RateLimit-Reset": "1700000000",
                    },
                )
            elif "/commits" in url:
                return httpx.Response(200, json=[], headers={"X-RateLimit-Remaining": "4499"})
            elif "/contributors" in url:
                return httpx.Response(200, json=[], headers={"X-RateLimit-Remaining": "4498"})
            elif "/issues" in url:
                return httpx.Response(200, json=[], headers={"X-RateLimit-Remaining": "4497"})
            elif "/pulls" in url:
                return httpx.Response(200, json=[], headers={"X-RateLimit-Remaining": "4496"})
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            run_async(collector.get_repo_metrics("test", "repo"))

            # Should track the last rate limit value
            assert collector.rate_limit_remaining < 5000


# =============================================================================
# PR AND ISSUE METRICS TESTS
# =============================================================================


class TestPRAndIssueMetrics:
    """Tests for PR merge velocity and issue response time."""

    def _create_repo_response(self):
        """Create a mock GitHub repo API response."""
        return {
            "stargazers_count": 1000,
            "forks_count": 100,
            "open_issues_count": 5,
            "watchers_count": 1000,
            "pushed_at": datetime.now(timezone.utc).isoformat(),
            "created_at": "2020-01-01T00:00:00Z",
            "archived": False,
            "disabled": False,
            "default_branch": "main",
        }

    def test_pr_merge_velocity(self):
        """Test PR opened/merged counts in 90 days."""
        from github_collector import GitHubCollector

        pr_created = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                return httpx.Response(200, json=[])
            elif "/contributors" in url:
                return httpx.Response(200, json=[])
            elif "/issues" in url:
                return httpx.Response(200, json=[])
            elif "/pulls" in url:
                return httpx.Response(200, json=[
                    {"created_at": pr_created, "merged_at": pr_created, "state": "closed"},
                    {"created_at": pr_created, "merged_at": pr_created, "state": "closed"},
                    {"created_at": pr_created, "merged_at": None, "state": "open"},
                ])
            elif "/repos/pr/repo" in url:
                return httpx.Response(200, json=self._create_repo_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("pr", "repo"))

            assert result["prs_opened_90d"] == 3
            assert result["prs_merged_90d"] == 2

    def test_issue_response_time_estimation(self):
        """Test issue response time heuristic estimation."""
        from github_collector import GitHubCollector

        issue_created = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            # Check specific repo URL first (before /issues check)
            if "/repos/issuetest/repo" in url and "/issues" not in url and "/commits" not in url and "/contributors" not in url and "/pulls" not in url:
                return httpx.Response(200, json=self._create_repo_response())
            elif "/commits" in url:
                return httpx.Response(200, json=[])
            elif "/contributors" in url:
                return httpx.Response(200, json=[])
            elif "/issues" in url:
                return httpx.Response(200, json=[
                    {"created_at": issue_created, "comments": 5, "state": "closed"},
                    {"created_at": issue_created, "comments": 2, "state": "open"},
                    {"created_at": issue_created, "comments": 0, "state": "open"},  # No response
                ])
            elif "/pulls" in url:
                return httpx.Response(200, json=[])
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("issuetest", "repo"))

            # Should have an estimated response time (heuristic)
            assert result["avg_issue_response_hours"] is not None


# =============================================================================
# GET REPO METRICS FROM URL TESTS
# =============================================================================


class TestGetRepoMetricsFromUrl:
    """Tests for get_repo_metrics_from_url method."""

    def test_invalid_url_returns_error(self):
        """Invalid URL should return error dict."""
        from github_collector import GitHubCollector

        collector = GitHubCollector(token="ghp_test")
        result = run_async(collector.get_repo_metrics_from_url("https://gitlab.com/user/repo"))

        assert result["error"] == "invalid_github_url"
        assert result["url"] == "https://gitlab.com/user/repo"

    def test_valid_url_fetches_metrics(self):
        """Valid URL should fetch repo metrics."""
        from github_collector import GitHubCollector

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/repos/facebook/react" in url:
                return httpx.Response(200, json={
                    "stargazers_count": 200000,
                    "forks_count": 40000,
                    "open_issues_count": 1000,
                    "watchers_count": 200000,
                    "pushed_at": datetime.now(timezone.utc).isoformat(),
                    "archived": False,
                    "disabled": False,
                    "default_branch": "main",
                })
            elif "/commits" in url:
                return httpx.Response(200, json=[])
            elif "/contributors" in url:
                return httpx.Response(200, json=[])
            elif "/issues" in url:
                return httpx.Response(200, json=[])
            elif "/pulls" in url:
                return httpx.Response(200, json=[])
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test")
            result = run_async(collector.get_repo_metrics_from_url("https://github.com/facebook/react"))

            assert result["owner"] == "facebook"
            assert result["repo"] == "react"
            assert result["stars"] == 200000
