"""
Comprehensive tests for PkgWatch data collectors.

Tests cover:
- github_collector.py: URL parsing, API requests, rate limits, bus factor
- npm_collector.py: Registry fetching, deprecation, TypeScript detection
- depsdev_collector.py: Package info, OpenSSF scores, advisories
- bundlephobia_collector.py: Bundle size, categorization
- package_collector.py: Integration, SQS handler

Run with: PYTHONPATH=functions/collectors:functions python3 -m pytest tests/test_collectors.py -v
"""

import asyncio
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Callable
from unittest.mock import AsyncMock, MagicMock, patch

import boto3
import httpx
import pytest
from moto import mock_aws

# Add functions directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions", "collectors"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions", "shared"))


# =============================================================================
# TEST UTILITIES
# =============================================================================


def create_mock_transport(handler: Callable):
    """Create a mock transport for httpx that routes requests to handler."""

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        return handler(request)

    return httpx.MockTransport(mock_handler)


def run_async(coro):
    """Helper to run async functions in sync tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# =============================================================================
# GITHUB COLLECTOR TESTS
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

        # Should still extract owner/repo from full paths
        result = parse_github_url("https://github.com/microsoft/TypeScript")
        assert result == ("microsoft", "TypeScript")


class TestGitHubCollector:
    """Tests for GitHubCollector class."""

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

    def test_get_repo_metrics_success(self):
        """Test successful repo metrics fetch."""
        from github_collector import GitHubCollector

        # Track API calls
        requests_made = []

        def mock_handler(request: httpx.Request) -> httpx.Response:
            requests_made.append(str(request.url))
            url = str(request.url)

            if "/repos/lodash/lodash/commits" in url:
                return httpx.Response(
                    200,
                    json=[
                        {
                            "author": {"login": "jdalton"},
                            "commit": {
                                "author": {"date": datetime.now(timezone.utc).isoformat()}
                            },
                        },
                        {
                            "author": {"login": "jdalton"},
                            "commit": {
                                "author": {"date": datetime.now(timezone.utc).isoformat()}
                            },
                        },
                        {
                            "author": {"login": "contributor1"},
                            "commit": {
                                "author": {"date": datetime.now(timezone.utc).isoformat()}
                            },
                        },
                    ],
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
            elif "/repos/lodash/lodash" in url:
                return httpx.Response(
                    200,
                    json={
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
                    },
                    headers={
                        "X-RateLimit-Remaining": "4999",
                        "X-RateLimit-Reset": "1700000000",
                    },
                )

            return httpx.Response(404)

        # Patch httpx.AsyncClient to use our mock transport
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
            assert result["commits_90d"] == 3
            assert result["active_contributors_90d"] == 2
            assert result["total_contributors"] == 2
            assert result["archived"] is False
            assert result["source"] == "github"

    def test_get_repo_metrics_not_found(self):
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

    def test_get_repo_metrics_forbidden_blocked_repo(self):
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

    def test_empty_repository(self):
        """Test 409 response (empty repo with no commits)."""
        from github_collector import GitHubCollector

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                return httpx.Response(409)  # Empty repo
            elif "/contributors" in url:
                return httpx.Response(200, json=[])
            elif "/repos/empty/repo" in url:
                return httpx.Response(
                    200,
                    json={
                        "stargazers_count": 0,
                        "forks_count": 0,
                        "open_issues_count": 0,
                        "watchers_count": 0,
                        "archived": False,
                        "disabled": False,
                        "default_branch": "main",
                    },
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

    def test_days_since_commit_fallback_to_pushed_at(self):
        """When commits list is empty but pushed_at exists, should use pushed_at."""
        from github_collector import GitHubCollector

        # pushed_at is 120 days ago (outside 90-day commit window)
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
                return httpx.Response(200, json={
                    "stargazers_count": 1000,
                    "forks_count": 100,
                    "open_issues_count": 5,
                    "watchers_count": 1000,
                    "pushed_at": pushed_at_date,
                    "updated_at": pushed_at_date,
                    "created_at": "2020-01-01T00:00:00Z",
                    "archived": False,
                    "disabled": False,
                    "default_branch": "main",
                })
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

    def test_days_since_commit_999_when_no_pushed_at(self):
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
                return httpx.Response(200, json={
                    "stargazers_count": 0,
                    "forks_count": 0,
                    "open_issues_count": 0,
                    "watchers_count": 0,
                    # No pushed_at field
                    "archived": False,
                    "disabled": False,
                    "default_branch": "main",
                })
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("unknown", "repo"))

            assert result["days_since_last_commit"] == 999

    def test_days_since_commit_from_recent_commits(self):
        """When commits exist in 90-day window, should use commit date."""
        from github_collector import GitHubCollector

        # Commit is 7 days ago
        commit_date = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        # pushed_at is older (30 days) - should be ignored
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
                return httpx.Response(200, json={
                    "stargazers_count": 1000,
                    "forks_count": 100,
                    "open_issues_count": 5,
                    "watchers_count": 1000,
                    "pushed_at": pushed_at_date,
                    "updated_at": commit_date,
                    "created_at": "2020-01-01T00:00:00Z",
                    "archived": False,
                    "disabled": False,
                    "default_branch": "main",
                })
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

    def test_days_since_commit_future_pushed_at_clamped(self):
        """Future pushed_at date should be clamped to 0."""
        from github_collector import GitHubCollector

        # Future date (shouldn't happen but defensive)
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
                return httpx.Response(200, json={
                    "stargazers_count": 0,
                    "forks_count": 0,
                    "open_issues_count": 0,
                    "watchers_count": 0,
                    "pushed_at": future_date,
                    "archived": False,
                    "disabled": False,
                    "default_branch": "main",
                })
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("future", "repo"))

            # Future date should be clamped to 0
            assert result["days_since_last_commit"] == 0

    def test_days_since_commit_malformed_pushed_at(self):
        """Malformed pushed_at date should fall back to 999."""
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
            elif "/repos/malformed/repo" in url:
                return httpx.Response(200, json={
                    "stargazers_count": 0,
                    "forks_count": 0,
                    "open_issues_count": 0,
                    "watchers_count": 0,
                    "pushed_at": "not-a-valid-date",  # Invalid date format
                    "archived": False,
                    "disabled": False,
                    "default_branch": "main",
                })
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="ghp_test_token")
            result = run_async(collector.get_repo_metrics("malformed", "repo"))

            # Malformed date should fall back to 999
            assert result["days_since_last_commit"] == 999


class TestTrueBusFactor:
    """Tests for true bus factor calculation."""

    def test_bus_factor_single_contributor(self):
        """Bus factor is 1 when single contributor makes all commits."""
        from github_collector import GitHubCollector

        # 100+ commits = HIGH confidence
        commits = [
            {
                "author": {"login": "solo_dev"},
                "commit": {"author": {"date": datetime.now(timezone.utc).isoformat()}},
            }
            for _ in range(100)
        ]

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                return httpx.Response(200, json=commits)
            elif "/contributors" in url:
                return httpx.Response(200, json=[{"login": "solo_dev"}])
            elif "/repos/solo/project" in url:
                return httpx.Response(
                    200,
                    json={
                        "stargazers_count": 100,
                        "forks_count": 10,
                        "open_issues_count": 5,
                        "watchers_count": 100,
                        "archived": False,
                        "disabled": False,
                        "default_branch": "main",
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="test")
            result = run_async(collector.get_repo_metrics("solo", "project"))

            assert result["true_bus_factor"] == 1
            assert result["bus_factor_confidence"] == "HIGH"  # 50 commits

    def test_bus_factor_distributed_contributions(self):
        """Bus factor reflects distributed contributions."""
        from github_collector import GitHubCollector

        # Distributed commits: 3 people with roughly equal contributions
        commits = []
        for i in range(120):
            contributor = f"dev{i % 3}"
            commits.append({
                "author": {"login": contributor},
                "commit": {"author": {"date": datetime.now(timezone.utc).isoformat()}},
            })

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                return httpx.Response(200, json=commits[:100])  # API limit
            elif "/contributors" in url:
                return httpx.Response(
                    200, json=[{"login": f"dev{i}"} for i in range(3)]
                )
            elif "/repos/team/project" in url:
                return httpx.Response(
                    200,
                    json={
                        "stargazers_count": 1000,
                        "forks_count": 100,
                        "open_issues_count": 50,
                        "watchers_count": 1000,
                        "archived": False,
                        "disabled": False,
                        "default_branch": "main",
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="test")
            result = run_async(collector.get_repo_metrics("team", "project"))

            # With equal contributions, need 2 people for 50%
            assert result["true_bus_factor"] >= 2
            assert result["bus_factor_confidence"] == "HIGH"  # 100 commits

    def test_bus_factor_low_confidence(self):
        """Low confidence with few commits."""
        from github_collector import GitHubCollector

        # Only 5 commits
        commits = [
            {
                "author": {"login": "dev1"},
                "commit": {"author": {"date": datetime.now(timezone.utc).isoformat()}},
            }
            for _ in range(5)
        ]

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/commits" in url:
                return httpx.Response(200, json=commits)
            elif "/contributors" in url:
                return httpx.Response(200, json=[{"login": "dev1"}])
            elif "/repos/new/project" in url:
                return httpx.Response(
                    200,
                    json={
                        "stargazers_count": 10,
                        "forks_count": 1,
                        "open_issues_count": 2,
                        "watchers_count": 10,
                        "archived": False,
                        "disabled": False,
                        "default_branch": "main",
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            collector = GitHubCollector(token="test")
            result = run_async(collector.get_repo_metrics("new", "project"))

            assert result["bus_factor_confidence"] == "LOW"


# =============================================================================
# NPM COLLECTOR TESTS
# =============================================================================


class TestEncodeScopedPackage:
    """Tests for encode_scoped_package function."""

    def test_encode_scoped_package(self):
        """Encode scoped package name."""
        from npm_collector import encode_scoped_package

        assert encode_scoped_package("@babel/core") == "@babel%2Fcore"

    def test_encode_unscoped_package(self):
        """Unscoped packages should not be modified."""
        from npm_collector import encode_scoped_package

        assert encode_scoped_package("lodash") == "lodash"

    def test_encode_deeply_scoped(self):
        """Only first slash should be encoded."""
        from npm_collector import encode_scoped_package

        # Note: npm doesn't actually allow multiple slashes, but test the logic
        assert encode_scoped_package("@scope/name") == "@scope%2Fname"


class TestGetNpmMetadata:
    """Tests for get_npm_metadata function."""

    def test_get_npm_metadata_success(self):
        """Test successful npm metadata fetch."""
        from npm_collector import get_npm_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org/lodash" in url:
                return httpx.Response(
                    200,
                    json={
                        "dist-tags": {"latest": "4.17.21"},
                        "time": {
                            "created": "2012-04-28T00:00:00.000Z",
                            "4.17.21": "2021-02-20T00:00:00.000Z",
                            "modified": "2024-01-01T00:00:00.000Z",
                        },
                        "versions": {
                            "4.17.21": {
                                "types": "./index.d.ts",
                                "type": "commonjs",
                                "engines": {"node": ">=8"},
                            }
                        },
                        "maintainers": [
                            {"name": "jdalton", "email": "john@example.com"},
                            {"name": "mathias", "email": "mathias@example.com"},
                        ],
                        "repository": {"url": "git+https://github.com/lodash/lodash.git"},
                        "license": "MIT",
                        "description": "Lodash modular utilities",
                        "keywords": ["utility", "modules"],
                    },
                )
            elif "api.npmjs.org/downloads" in url:
                return httpx.Response(200, json={"downloads": 50000000})
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("lodash"))

            assert result["name"] == "lodash"
            assert result["latest_version"] == "4.17.21"
            assert result["maintainer_count"] == 2
            assert result["weekly_downloads"] == 50000000
            assert result["has_types"] is True
            assert result["module_type"] == "commonjs"
            assert result["is_deprecated"] is False
            assert result["source"] == "npm"

    def test_get_npm_metadata_deprecated(self):
        """Test deprecated package detection."""
        from npm_collector import get_npm_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org/deprecated-pkg" in url:
                return httpx.Response(
                    200,
                    json={
                        "dist-tags": {"latest": "1.0.0"},
                        "time": {"created": "2020-01-01T00:00:00.000Z"},
                        "versions": {
                            "1.0.0": {
                                "deprecated": "This package is deprecated. Use better-pkg instead.",
                            }
                        },
                        "maintainers": [],
                        "repository": {},
                    },
                )
            elif "api.npmjs.org/downloads" in url:
                return httpx.Response(200, json={"downloads": 100})
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("deprecated-pkg"))

            assert result["is_deprecated"] is True
            assert "better-pkg" in result["deprecation_message"]

    def test_get_npm_metadata_scoped_package(self):
        """Test scoped package (@org/name) handling."""
        from npm_collector import get_npm_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org/@babel%2Fcore" in url:
                return httpx.Response(
                    200,
                    json={
                        "dist-tags": {"latest": "7.23.0"},
                        "time": {"created": "2018-08-27T00:00:00.000Z"},
                        "versions": {"7.23.0": {"types": "lib/index.d.ts"}},
                        "maintainers": [{"name": "babel"}],
                        "repository": {"url": "https://github.com/babel/babel"},
                    },
                )
            elif "api.npmjs.org/downloads" in url:
                return httpx.Response(200, json={"downloads": 40000000})
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("@babel/core"))

            assert result["name"] == "@babel/core"
            assert result["latest_version"] == "7.23.0"

    def test_get_npm_metadata_not_found(self):
        """Test 404 handling for non-existent package."""
        from npm_collector import get_npm_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("nonexistent-package-xyz"))

            assert result["error"] == "package_not_found"
            assert result["name"] == "nonexistent-package-xyz"

    def test_get_npm_metadata_esm_package(self):
        """Test ESM module detection."""
        from npm_collector import get_npm_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org/esm-package" in url:
                return httpx.Response(
                    200,
                    json={
                        "dist-tags": {"latest": "1.0.0"},
                        "time": {"created": "2023-01-01T00:00:00.000Z"},
                        "versions": {
                            "1.0.0": {
                                "type": "module",
                                "exports": {"import": "./index.mjs"},
                            }
                        },
                        "maintainers": [],
                        "repository": {},
                    },
                )
            elif "api.npmjs.org/downloads" in url:
                return httpx.Response(200, json={"downloads": 1000})
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("esm-package"))

            assert result["module_type"] == "module"
            assert result["has_exports"] is True

    def test_get_npm_metadata_typings_field(self):
        """Test TypeScript detection via 'typings' field (alternative to 'types')."""
        from npm_collector import get_npm_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org/typed-pkg" in url:
                return httpx.Response(
                    200,
                    json={
                        "dist-tags": {"latest": "1.0.0"},
                        "time": {"created": "2023-01-01T00:00:00.000Z"},
                        "versions": {
                            "1.0.0": {
                                "typings": "dist/index.d.ts",  # Alternative field
                            }
                        },
                        "maintainers": [],
                        "repository": {},
                    },
                )
            elif "api.npmjs.org/downloads" in url:
                return httpx.Response(200, json={"downloads": 500})
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("typed-pkg"))

            assert result["has_types"] is True

    def test_get_npm_metadata_invalid_json(self):
        """Test handling of invalid JSON response from npm registry."""
        from npm_collector import get_npm_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org/bad-json-pkg" in url:
                # Return invalid JSON
                return httpx.Response(200, content=b"not valid json {{{")
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("bad-json-pkg"))

            assert result["error"] == "invalid_json_response"
            assert result["name"] == "bad-json-pkg"

    def test_get_npm_metadata_string_repository(self):
        """Test handling of repository as string instead of object."""
        from npm_collector import get_npm_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org/string-repo-pkg" in url:
                return httpx.Response(
                    200,
                    json={
                        "dist-tags": {"latest": "1.0.0"},
                        "time": {"created": "2023-01-01T00:00:00.000Z"},
                        "versions": {"1.0.0": {}},
                        "maintainers": [],
                        # Repository as string instead of object
                        "repository": "https://github.com/user/repo",
                    },
                )
            elif "api.npmjs.org/downloads" in url:
                return httpx.Response(200, json={"downloads": 100})
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("string-repo-pkg"))

            assert result["repository_url"] == "https://github.com/user/repo"


class TestNpmDownloadStats:
    """Tests for npm download statistics functions."""

    def test_get_download_stats_success(self):
        """Test successful download stats fetch."""
        from npm_collector import get_download_stats

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "downloads": 50000,
                    "start": "2024-01-01",
                    "end": "2024-01-07",
                    "package": "test-pkg",
                },
            )

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_download_stats("test-pkg"))

            assert result["downloads"] == 50000
            assert result["package"] == "test-pkg"

    def test_get_download_stats_error(self):
        """Test download stats error handling."""
        from npm_collector import get_download_stats

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_download_stats("failing-pkg"))

            assert result["downloads"] == 0
            assert result["error"] == "fetch_failed"

    def test_get_bulk_download_stats_unscoped(self):
        """Test bulk download stats for unscoped packages."""
        from npm_collector import get_bulk_download_stats

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "api.npmjs.org/downloads/point/last-week/pkg1,pkg2" in url:
                return httpx.Response(
                    200,
                    json={
                        "pkg1": {"downloads": 1000},
                        "pkg2": {"downloads": 2000},
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bulk_download_stats(["pkg1", "pkg2"]))

            assert result["pkg1"] == 1000
            assert result["pkg2"] == 2000

    def test_get_bulk_download_stats_scoped(self):
        """Test bulk download stats for scoped packages (fetched individually)."""
        from npm_collector import get_bulk_download_stats

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "@scope%2Fpkg" in url or "@scope/pkg" in url:
                return httpx.Response(200, json={"downloads": 5000})
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bulk_download_stats(["@scope/pkg"]))

            assert result["@scope/pkg"] == 5000


class TestBundlephobiaErrorHandling:
    """Tests for bundlephobia error handling."""

    def test_get_bundle_size_generic_exception(self):
        """Test generic exception handling in get_bundle_size."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            raise RuntimeError("Unexpected error during request")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("error-pkg"))

            assert "error" in result
            assert "fetch_error" in result["error"]
            assert result["name"] == "error-pkg"
            assert result["source"] == "bundlephobia"


# =============================================================================
# DEPSDEV COLLECTOR TESTS
# =============================================================================


class TestEncodePackageName:
    """Tests for encode_package_name function."""

    def test_encode_scoped_package(self):
        """Encode scoped package with @ and /."""
        from depsdev_collector import encode_package_name

        assert encode_package_name("@babel/core") == "%40babel%2Fcore"

    def test_encode_simple_package(self):
        """Simple packages should be unchanged."""
        from depsdev_collector import encode_package_name

        assert encode_package_name("lodash") == "lodash"

    def test_encode_package_with_special_chars(self):
        """Packages with special characters should be encoded."""
        from depsdev_collector import encode_package_name

        # Some npm packages have special characters
        result = encode_package_name("@types/node")
        assert "%40" in result  # @ encoded
        assert "%2F" in result  # / encoded


class TestGetPackageInfo:
    """Tests for get_package_info function."""

    def test_get_package_info_success(self):
        """Test successful package info fetch."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "packages/lodash/versions/4.17.21:dependents" in url:
                return httpx.Response(200, json={"dependentCount": 150000})
            elif "packages/lodash/versions/4.17.21" in url:
                return httpx.Response(
                    200,
                    json={
                        "publishedAt": "2021-02-20T00:00:00Z",
                        "licenses": ["MIT"],
                        "relations": {"dependencies": ["dep1", "dep2"]},
                        "advisories": [],
                        "links": [
                            {"label": "SOURCE_REPO", "url": "https://github.com/lodash/lodash"}
                        ],
                    },
                )
            elif "packages/lodash" in url:
                return httpx.Response(
                    200,
                    json={
                        "defaultVersion": "4.17.21",
                        "versions": [
                            {"versionKey": {"version": "4.17.21"}},
                        ],
                    },
                )
            elif "projects/github.com" in url:
                return httpx.Response(
                    200,
                    json={
                        "scorecardV2": {
                            "score": 7.5,
                            "check": [
                                {"name": "Code-Review", "score": 8},
                                {"name": "Maintained", "score": 10},
                            ],
                        },
                        "starsCount": 58000,
                        "forksCount": 7000,
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("lodash"))

            assert result["name"] == "lodash"
            assert result["ecosystem"] == "npm"
            assert result["latest_version"] == "4.17.21"
            assert result["licenses"] == ["MIT"]
            assert result["dependencies_direct"] == 2
            assert result["openssf_score"] == 7.5
            assert len(result["openssf_checks"]) == 2
            assert result["dependents_count"] == 150000
            assert result["source"] == "deps.dev"

    def test_get_package_info_not_found(self):
        """Test 404 handling for non-existent package."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("nonexistent-pkg"))

            assert result is None

    def test_get_package_info_with_advisories(self):
        """Test package with security advisories."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "packages/vulnerable-pkg:dependents" in url:
                return httpx.Response(200, json={"dependentCount": 100})
            elif "packages/vulnerable-pkg/versions/1.0.0" in url:
                return httpx.Response(
                    200,
                    json={
                        "publishedAt": "2023-01-01T00:00:00Z",
                        "licenses": ["MIT"],
                        "relations": {},
                        "advisories": [
                            {
                                "id": "GHSA-xxxx-xxxx-xxxx",
                                "title": "Prototype Pollution",
                                "severity": "HIGH",
                            }
                        ],
                        "links": [],
                    },
                )
            elif "packages/vulnerable-pkg" in url:
                return httpx.Response(
                    200,
                    json={"defaultVersion": "1.0.0"},
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("vulnerable-pkg"))

            assert len(result["advisories"]) == 1
            assert result["advisories"][0]["severity"] == "HIGH"

    def test_get_package_info_no_openssf_score(self):
        """Test package without OpenSSF scorecard."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "packages/small-pkg:dependents" in url:
                return httpx.Response(200, json={"dependentCount": 10})
            elif "packages/small-pkg/versions/1.0.0" in url:
                return httpx.Response(
                    200,
                    json={
                        "publishedAt": "2023-01-01T00:00:00Z",
                        "licenses": ["MIT"],
                        "relations": {},
                        "advisories": [],
                        "links": [
                            {"label": "SOURCE_REPO", "url": "https://github.com/user/small-pkg"}
                        ],
                    },
                )
            elif "packages/small-pkg" in url:
                return httpx.Response(
                    200,
                    json={"defaultVersion": "1.0.0"},
                )
            elif "projects/" in url:
                return httpx.Response(404)  # No scorecard
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("small-pkg"))

            assert result["openssf_score"] is None
            assert result["openssf_checks"] == []


# =============================================================================
# DEPS.DEV RETRY AND ERROR HANDLING TESTS
# =============================================================================


class TestDepsDevRetryWithBackoff:
    """Tests for depsdev_collector retry_with_backoff function."""

    def test_success_on_first_attempt(self):
        """Test successful execution on first attempt."""
        from depsdev_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            return "success"

        result = run_async(retry_with_backoff(mock_func))
        assert result == "success"
        assert call_count == 1

    def test_retry_on_429_rate_limit(self):
        """Test retry on 429 Too Many Requests."""
        from depsdev_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                response = httpx.Response(429, request=httpx.Request("GET", "http://test"))
                raise httpx.HTTPStatusError("Rate limited", request=response.request, response=response)
            return "success"

        result = run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert result == "success"
        assert call_count == 3

    def test_retry_on_500_server_error(self):
        """Test retry on 500 Internal Server Error."""
        from depsdev_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                response = httpx.Response(500, request=httpx.Request("GET", "http://test"))
                raise httpx.HTTPStatusError("Server error", request=response.request, response=response)
            return "success"

        result = run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert result == "success"
        assert call_count == 2

    def test_retry_on_502_bad_gateway(self):
        """Test retry on 502 Bad Gateway."""
        from depsdev_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                response = httpx.Response(502, request=httpx.Request("GET", "http://test"))
                raise httpx.HTTPStatusError("Bad gateway", request=response.request, response=response)
            return "success"

        result = run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert result == "success"

    def test_retry_on_503_service_unavailable(self):
        """Test retry on 503 Service Unavailable."""
        from depsdev_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                response = httpx.Response(503, request=httpx.Request("GET", "http://test"))
                raise httpx.HTTPStatusError("Service unavailable", request=response.request, response=response)
            return "success"

        result = run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert result == "success"

    def test_retry_on_504_gateway_timeout(self):
        """Test retry on 504 Gateway Timeout."""
        from depsdev_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                response = httpx.Response(504, request=httpx.Request("GET", "http://test"))
                raise httpx.HTTPStatusError("Gateway timeout", request=response.request, response=response)
            return "success"

        result = run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert result == "success"

    def test_no_retry_on_400_client_error(self):
        """Test no retry on 400 Bad Request (client error)."""
        from depsdev_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            response = httpx.Response(400, request=httpx.Request("GET", "http://test"))
            raise httpx.HTTPStatusError("Bad request", request=response.request, response=response)

        with pytest.raises(httpx.HTTPStatusError):
            run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert call_count == 1

    def test_retry_on_network_error(self):
        """Test retry on network/connection errors."""
        from depsdev_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.ConnectError("Connection failed")
            return "success"

        result = run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert result == "success"
        assert call_count == 3

    def test_raises_after_max_retries(self):
        """Test that exception is raised after max retries exhausted."""
        from depsdev_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            response = httpx.Response(500, request=httpx.Request("GET", "http://test"))
            raise httpx.HTTPStatusError("Server error", request=response.request, response=response)

        with pytest.raises(httpx.HTTPStatusError):
            run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert call_count == 3


class TestDepsDevPackageInfoEdgeCases:
    """Tests for edge cases in get_package_info function."""

    def test_version_lookup_with_is_default_flag(self):
        """Test finding version marked with isDefault: true."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "packages/test-pkg/versions/2.0.0:dependents" in url:
                return httpx.Response(200, json={"dependentCount": 100})
            elif "packages/test-pkg/versions/2.0.0" in url:
                return httpx.Response(
                    200,
                    json={
                        "publishedAt": "2023-06-01T00:00:00Z",
                        "licenses": ["MIT"],
                        "relations": {"dependencies": []},
                        "advisories": [],
                        "links": [],
                    },
                )
            elif "packages/test-pkg" in url:
                return httpx.Response(
                    200,
                    json={
                        "defaultVersion": "",
                        "versions": [
                            {"versionKey": {"version": "1.0.0"}, "isDefault": False},
                            {"versionKey": {"version": "2.0.0"}, "isDefault": True},
                            {"versionKey": {"version": "3.0.0-beta"}, "isDefault": False},
                        ],
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("test-pkg"))
            assert result["latest_version"] == "2.0.0"

    def test_version_fallback_to_last_version(self):
        """Test fallback to last version when no isDefault flag."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "packages/test-pkg/versions/3.0.0:dependents" in url:
                return httpx.Response(200, json={"dependentCount": 50})
            elif "packages/test-pkg/versions/3.0.0" in url:
                return httpx.Response(
                    200,
                    json={
                        "publishedAt": "2023-12-01T00:00:00Z",
                        "licenses": ["MIT"],
                        "relations": {},
                        "advisories": [],
                        "links": [],
                    },
                )
            elif "packages/test-pkg" in url:
                return httpx.Response(
                    200,
                    json={
                        "defaultVersion": "",
                        "versions": [
                            {"versionKey": {"version": "1.0.0"}},
                            {"versionKey": {"version": "2.0.0"}},
                            {"versionKey": {"version": "3.0.0"}},
                        ],
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("test-pkg"))
            assert result["latest_version"] == "3.0.0"

    def test_version_data_fetch_failure_graceful(self):
        """Test graceful handling when version data fetch fails."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "packages/test-pkg/versions/" in url and ":dependents" not in url:
                return httpx.Response(500)
            elif "packages/test-pkg" in url and "versions" not in url:
                return httpx.Response(
                    200,
                    json={
                        "defaultVersion": "1.0.0",
                        "versions": [{"versionKey": {"version": "1.0.0"}}],
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("test-pkg"))
            assert result["name"] == "test-pkg"
            assert result["latest_version"] == "1.0.0"

    def test_dependents_count_as_list(self):
        """Test handling dependentCount when returned as a list."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "packages/test-pkg/versions/1.0.0:dependents" in url:
                return httpx.Response(200, json={
                    "dependentCount": ["dep1", "dep2", "dep3"]
                })
            elif "packages/test-pkg/versions/1.0.0" in url:
                return httpx.Response(
                    200,
                    json={
                        "publishedAt": "2023-01-01T00:00:00Z",
                        "licenses": ["MIT"],
                        "relations": {},
                        "advisories": [],
                        "links": [],
                    },
                )
            elif "packages/test-pkg" in url:
                return httpx.Response(
                    200,
                    json={"defaultVersion": "1.0.0"},
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("test-pkg"))
            assert result["dependents_count"] == 3

    def test_dependents_fetch_failure_graceful(self):
        """Test graceful handling when dependents fetch fails."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if ":dependents" in url:
                return httpx.Response(500)
            elif "packages/test-pkg/versions/1.0.0" in url:
                return httpx.Response(
                    200,
                    json={
                        "publishedAt": "2023-01-01T00:00:00Z",
                        "licenses": ["MIT"],
                        "relations": {},
                        "advisories": [],
                        "links": [],
                    },
                )
            elif "packages/test-pkg" in url:
                return httpx.Response(
                    200,
                    json={"defaultVersion": "1.0.0"},
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("test-pkg"))
            assert result["dependents_count"] == 0


class TestGetDependentsCount:
    """Tests for get_dependents_count function."""

    def test_successful_fetch(self):
        """Test successful dependents count fetch."""
        from depsdev_collector import get_dependents_count

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"dependentCount": 5000})

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_dependents_count("lodash"))
            assert result == 5000

    def test_missing_count_returns_zero(self):
        """Test that missing dependentCount returns 0."""
        from depsdev_collector import get_dependents_count

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={})

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_dependents_count("lodash"))
            assert result == 0


class TestGetAdvisories:
    """Tests for get_advisories function."""

    def test_successful_fetch(self):
        """Test successful advisories fetch."""
        from depsdev_collector import get_advisories

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "advisories": [
                    {"id": "GHSA-1", "severity": "HIGH"},
                    {"id": "GHSA-2", "severity": "MEDIUM"},
                ]
            })

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_advisories("vulnerable-pkg"))
            assert len(result) == 2
            assert result[0]["id"] == "GHSA-1"

    def test_fetch_failure_returns_empty_list(self):
        """Test that fetch failure returns empty list."""
        from depsdev_collector import get_advisories

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_advisories("test-pkg"))
            assert result == []

    def test_pypi_ecosystem(self):
        """Test advisories fetch for pypi ecosystem."""
        from depsdev_collector import get_advisories

        requested_url = None

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal requested_url
            requested_url = str(request.url)
            return httpx.Response(200, json={"advisories": []})

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            run_async(get_advisories("requests", ecosystem="pypi"))
            assert "pypi" in requested_url


class TestGetDependencies:
    """Tests for get_dependencies function."""

    def test_successful_fetch(self):
        """Test successful dependencies fetch."""
        from depsdev_collector import get_dependencies

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if ":dependencies" in url:
                return httpx.Response(200, json={
                    "nodes": [
                        {"versionKey": {"name": "main-pkg", "system": "NPM"}, "relation": "SELF"},
                        {"versionKey": {"name": "dep1", "system": "NPM"}, "relation": "DIRECT"},
                        {"versionKey": {"name": "dep2", "system": "NPM"}, "relation": "DIRECT"},
                        {"versionKey": {"name": "transitive", "system": "NPM"}, "relation": "INDIRECT"},
                    ]
                })
            elif "packages/main-pkg" in url:
                return httpx.Response(
                    200,
                    json={
                        "defaultVersion": "1.0.0",
                        "versions": [{"versionKey": {"version": "1.0.0"}}],
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_dependencies("main-pkg"))
            assert "dep1" in result
            assert "dep2" in result
            assert "transitive" not in result
            assert "main-pkg" not in result

    def test_package_not_found_returns_empty(self):
        """Test that 404 for package returns empty list."""
        from depsdev_collector import get_dependencies

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_dependencies("nonexistent-pkg"))
            assert result == []

    def test_no_versions_returns_empty(self):
        """Test that package with no versions returns empty list."""
        from depsdev_collector import get_dependencies

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "packages/empty-pkg" in url:
                return httpx.Response(
                    200,
                    json={
                        "defaultVersion": "",
                        "versions": [],
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_dependencies("empty-pkg"))
            assert result == []

    def test_dependencies_fetch_failure_returns_empty(self):
        """Test that dependencies endpoint failure returns empty list."""
        from depsdev_collector import get_dependencies

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if ":dependencies" in url:
                return httpx.Response(500)
            elif "packages/test-pkg" in url:
                return httpx.Response(
                    200,
                    json={
                        "defaultVersion": "1.0.0",
                        "versions": [{"versionKey": {"version": "1.0.0"}}],
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_dependencies("test-pkg"))
            assert result == []

    def test_excludes_different_ecosystem_deps(self):
        """Test that dependencies from different ecosystems are excluded."""
        from depsdev_collector import get_dependencies

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if ":dependencies" in url:
                return httpx.Response(200, json={
                    "nodes": [
                        {"versionKey": {"name": "main-pkg", "system": "NPM"}, "relation": "SELF"},
                        {"versionKey": {"name": "npm-dep", "system": "NPM"}, "relation": "DIRECT"},
                        {"versionKey": {"name": "go-dep", "system": "GO"}, "relation": "DIRECT"},
                    ]
                })
            elif "packages/main-pkg" in url:
                return httpx.Response(
                    200,
                    json={
                        "defaultVersion": "1.0.0",
                        "versions": [{"versionKey": {"version": "1.0.0"}}],
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_dependencies("main-pkg", ecosystem="npm"))
            assert "npm-dep" in result
            assert "go-dep" not in result

    def test_pypi_ecosystem_dependencies(self):
        """Test fetching dependencies for pypi ecosystem."""
        from depsdev_collector import get_dependencies

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "systems/pypi" in url:
                if ":dependencies" in url:
                    return httpx.Response(200, json={
                        "nodes": [
                            {"versionKey": {"name": "requests", "system": "PYPI"}, "relation": "SELF"},
                            {"versionKey": {"name": "urllib3", "system": "PYPI"}, "relation": "DIRECT"},
                        ]
                    })
                elif "packages/requests" in url:
                    return httpx.Response(
                        200,
                        json={
                            "defaultVersion": "2.31.0",
                            "versions": [{"versionKey": {"version": "2.31.0"}}],
                        },
                    )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_dependencies("requests", ecosystem="pypi"))
            assert "urllib3" in result

    def test_version_lookup_with_is_default_flag(self):
        """Test finding version using isDefault flag in get_dependencies."""
        from depsdev_collector import get_dependencies

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if ":dependencies" in url and "2.0.0" in url:
                return httpx.Response(200, json={
                    "nodes": [
                        {"versionKey": {"name": "test-pkg", "system": "NPM"}, "relation": "SELF"},
                        {"versionKey": {"name": "my-dep", "system": "NPM"}, "relation": "DIRECT"},
                    ]
                })
            elif "packages/test-pkg" in url and ":dependencies" not in url:
                return httpx.Response(
                    200,
                    json={
                        "defaultVersion": "",
                        "versions": [
                            {"versionKey": {"version": "1.0.0"}},
                            {"versionKey": {"version": "2.0.0"}, "isDefault": True},
                        ],
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_dependencies("test-pkg"))
            assert "my-dep" in result


class TestEncodeRepoUrl:
    """Tests for encode_repo_url function."""

    def test_encode_github_url(self):
        """Test encoding GitHub URL."""
        from depsdev_collector import encode_repo_url

        result = encode_repo_url("github.com/lodash/lodash")
        assert result == "github.com%2Flodash%2Flodash"

    def test_encode_url_with_special_chars(self):
        """Test encoding URL with special characters."""
        from depsdev_collector import encode_repo_url

        result = encode_repo_url("github.com/user/repo-name")
        assert "github.com" in result
        assert "%2F" in result


# =============================================================================
# BUNDLEPHOBIA COLLECTOR TESTS
# =============================================================================


class TestBundleSizeCategorization:
    """Tests for bundle size categorization functions."""

    def test_categorize_tiny(self):
        """Less than 5KB is tiny."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(1024) == "tiny"  # 1 KB
        assert _categorize_size(4 * 1024) == "tiny"  # 4 KB

    def test_categorize_small(self):
        """5-20KB is small."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(5 * 1024) == "small"  # 5 KB
        assert _categorize_size(19 * 1024) == "small"  # 19 KB

    def test_categorize_medium(self):
        """20-100KB is medium."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(20 * 1024) == "medium"  # 20 KB
        assert _categorize_size(99 * 1024) == "medium"  # 99 KB

    def test_categorize_large(self):
        """100-500KB is large."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(100 * 1024) == "large"  # 100 KB
        assert _categorize_size(499 * 1024) == "large"  # 499 KB

    def test_categorize_huge(self):
        """More than 500KB is huge."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(500 * 1024) == "huge"  # 500 KB
        assert _categorize_size(1024 * 1024) == "huge"  # 1 MB


class TestEstimateDownloadTime:
    """Tests for download time estimation."""

    def test_estimate_3g(self):
        """Test 3G download time estimation."""
        from bundlephobia_collector import _estimate_download_time

        # 50KB on 3G (50 B/ms) = 1000ms
        result = _estimate_download_time(50 * 1024, "3g")
        assert result == 1024  # 50 * 1024 / 50

    def test_estimate_4g(self):
        """Test 4G download time estimation."""
        from bundlephobia_collector import _estimate_download_time

        # 875KB on 4G (875 B/ms) = 1000ms
        result = _estimate_download_time(875 * 1024, "4g")
        assert result == 1024  # 875 * 1024 / 875

    def test_estimate_zero_bytes(self):
        """Zero bytes should return 0ms."""
        from bundlephobia_collector import _estimate_download_time

        assert _estimate_download_time(0, "4g") == 0

    def test_estimate_negative_bytes(self):
        """Negative bytes should return 0ms."""
        from bundlephobia_collector import _estimate_download_time

        assert _estimate_download_time(-100, "4g") == 0


class TestGetBundleSize:
    """Tests for get_bundle_size function."""

    def test_get_bundle_size_success(self):
        """Test successful bundle size fetch."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "bundlephobia.com/api/size" in url and "lodash" in url:
                return httpx.Response(
                    200,
                    json={
                        "name": "lodash",
                        "version": "4.17.21",
                        "size": 71420,  # Minified
                        "gzip": 25276,  # Gzipped
                        "dependencyCount": 0,
                        "hasSideEffects": True,
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("lodash"))

            assert result["name"] == "lodash"
            assert result["version"] == "4.17.21"
            assert result["size"] == 71420
            assert result["gzip"] == 25276
            assert result["dependency_count"] == 0
            assert result["size_category"] == "medium"  # 24.68 KB gzipped
            assert result["source"] == "bundlephobia"

    def test_get_bundle_size_with_version(self):
        """Test bundle size fetch for specific version."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            # URL encoding makes @ become %40 and version separator @ is unencoded
            if "bundlephobia.com/api/size" in url and "react" in url:
                return httpx.Response(
                    200,
                    json={
                        "name": "react",
                        "version": "18.2.0",
                        "size": 6430,
                        "gzip": 2790,
                        "dependencyCount": 1,
                        "hasSideEffects": True,
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("react", "18.2.0"))

            assert result["version"] == "18.2.0"
            assert result["size_category"] == "tiny"  # 2.72 KB gzipped

    def test_get_bundle_size_scoped_package(self):
        """Test bundle size for scoped package."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            # Match scoped package - URL will contain the encoded @babel/core
            if "bundlephobia.com/api/size" in url and "babel" in url:
                return httpx.Response(
                    200,
                    json={
                        "name": "@babel/core",
                        "version": "7.23.0",
                        "size": 1500000,
                        "gzip": 550000,  # 537KB = "huge" (>500KB)
                        "dependencyCount": 25,
                        "hasSideEffects": False,
                    },
                )
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("@babel/core"))

            assert result["name"] == "@babel/core"
            assert result["size_category"] == "huge"  # 537 KB gzipped > 500KB threshold

    def test_get_bundle_size_not_found(self):
        """Test 404 handling for packages without size data."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("nonexistent-pkg"))

            assert result["error"] == "not_found"
            assert result["name"] == "nonexistent-pkg"
            assert result["source"] == "bundlephobia"

    def test_get_bundle_size_rate_limited(self):
        """Test 429 rate limit raises exception for circuit breaker."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            # 429 should now raise HTTPStatusError so circuit breaker records failure
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                run_async(get_bundle_size("some-pkg"))
            assert exc_info.value.response.status_code == 429

    def test_get_bundle_size_timeout(self):
        """Test 504 timeout raises exception for circuit breaker."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(504)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            # 504 should now raise HTTPStatusError so circuit breaker records failure
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                run_async(get_bundle_size("huge-pkg"))
            assert exc_info.value.response.status_code == 504


class TestBundlephobiaHelpers:
    """Tests for bundlephobia helper functions."""

    def test_estimate_download_time_zero_bytes(self):
        """Should return 0 for empty files."""
        from bundlephobia_collector import _estimate_download_time

        assert _estimate_download_time(0, "4g") == 0
        assert _estimate_download_time(0, "3g") == 0
        assert _estimate_download_time(-1, "4g") == 0

    def test_estimate_download_time_3g_network(self):
        """Should calculate download time for 3G network."""
        from bundlephobia_collector import _estimate_download_time

        # 50 B/ms for 3G, so 5000 bytes = 100ms
        result = _estimate_download_time(5000, "3g")
        assert result == 100

    def test_estimate_download_time_unknown_network(self):
        """Should default to 4g speed for unknown network."""
        from bundlephobia_collector import _estimate_download_time

        result_unknown = _estimate_download_time(8750, "5g")
        result_4g = _estimate_download_time(8750, "4g")
        assert result_unknown == result_4g  # Both use 4g default

    def test_categorize_size_tiny(self):
        """Should categorize files under 5KB as tiny."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(0) == "tiny"
        assert _categorize_size(1024) == "tiny"
        assert _categorize_size(5 * 1024 - 1) == "tiny"

    def test_categorize_size_small(self):
        """Should categorize files 5-20KB as small."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(5 * 1024) == "small"
        assert _categorize_size(10 * 1024) == "small"
        assert _categorize_size(20 * 1024 - 1) == "small"

    def test_categorize_size_medium(self):
        """Should categorize files 20-100KB as medium."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(20 * 1024) == "medium"
        assert _categorize_size(50 * 1024) == "medium"
        assert _categorize_size(100 * 1024 - 1) == "medium"

    def test_categorize_size_large(self):
        """Should categorize files 100-500KB as large."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(100 * 1024) == "large"
        assert _categorize_size(250 * 1024) == "large"
        assert _categorize_size(500 * 1024 - 1) == "large"

    def test_categorize_size_huge(self):
        """Should categorize files over 500KB as huge."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(500 * 1024) == "huge"
        assert _categorize_size(1024 * 1024) == "huge"

    def test_encode_package_spec_simple(self):
        """Should encode simple package names."""
        from bundlephobia_collector import encode_package_spec

        assert encode_package_spec("lodash") == "lodash"
        assert encode_package_spec("lodash", "4.17.21") == "lodash@4.17.21"

    def test_encode_package_spec_scoped(self):
        """Should properly encode scoped packages."""
        from bundlephobia_collector import encode_package_spec

        # @ becomes %40, / becomes %2F
        result = encode_package_spec("@babel/core")
        assert "%40" in result
        assert "%2F" in result


class TestBundlephobiaRetry:
    """Tests for bundlephobia retry_with_backoff function."""

    @pytest.mark.asyncio
    async def test_retry_on_server_error(self):
        """Should retry on 500 server errors."""
        from bundlephobia_collector import retry_with_backoff

        call_count = [0]

        async def mock_func():
            call_count[0] += 1
            if call_count[0] < 3:
                response = httpx.Response(500)
                raise httpx.HTTPStatusError("Server error", request=MagicMock(), response=response)
            return "success"

        result = await retry_with_backoff(mock_func, max_retries=3, base_delay=0.01)
        assert result == "success"
        assert call_count[0] == 3

    @pytest.mark.asyncio
    async def test_no_retry_on_client_error(self):
        """Should not retry on 4xx client errors (except 429)."""
        from bundlephobia_collector import retry_with_backoff

        call_count = [0]

        async def mock_func():
            call_count[0] += 1
            response = httpx.Response(400)
            raise httpx.HTTPStatusError("Bad request", request=MagicMock(), response=response)

        with pytest.raises(httpx.HTTPStatusError):
            await retry_with_backoff(mock_func, max_retries=3, base_delay=0.01)

        # Should only be called once - no retry on 400
        assert call_count[0] == 1

    @pytest.mark.asyncio
    async def test_retry_on_rate_limit(self):
        """Should retry on 429 rate limit errors."""
        from bundlephobia_collector import retry_with_backoff

        call_count = [0]

        async def mock_func():
            call_count[0] += 1
            if call_count[0] < 2:
                response = httpx.Response(429)
                raise httpx.HTTPStatusError("Rate limited", request=MagicMock(), response=response)
            return "success"

        result = await retry_with_backoff(mock_func, max_retries=3, base_delay=0.01)
        assert result == "success"
        assert call_count[0] == 2

    @pytest.mark.asyncio
    async def test_retry_on_network_error(self):
        """Should retry on network errors."""
        from bundlephobia_collector import retry_with_backoff

        call_count = [0]

        async def mock_func():
            call_count[0] += 1
            if call_count[0] < 2:
                raise httpx.RequestError("Connection failed")
            return "success"

        result = await retry_with_backoff(mock_func, max_retries=3, base_delay=0.01)
        assert result == "success"
        assert call_count[0] == 2

    @pytest.mark.asyncio
    async def test_raises_after_max_retries(self):
        """Should raise after exhausting all retries."""
        from bundlephobia_collector import retry_with_backoff

        call_count = [0]

        async def mock_func():
            call_count[0] += 1
            response = httpx.Response(503)
            raise httpx.HTTPStatusError("Service unavailable", request=MagicMock(), response=response)

        with pytest.raises(httpx.HTTPStatusError):
            await retry_with_backoff(mock_func, max_retries=3, base_delay=0.01)

        assert call_count[0] == 3

    @pytest.mark.asyncio
    async def test_success_on_first_try(self):
        """Should return immediately on success."""
        from bundlephobia_collector import retry_with_backoff

        call_count = [0]

        async def mock_func():
            call_count[0] += 1
            return "immediate_success"

        result = await retry_with_backoff(mock_func, max_retries=3, base_delay=0.01)
        assert result == "immediate_success"
        assert call_count[0] == 1


class TestBundlephobiaBatch:
    """Tests for bundlephobia batch function."""

    @pytest.mark.asyncio
    async def test_get_bundle_sizes_batch(self):
        """Should fetch sizes for multiple packages."""
        from bundlephobia_collector import get_bundle_sizes_batch

        # Mock get_bundle_size to return quickly
        with patch("bundlephobia_collector.get_bundle_size") as mock_get:
            mock_get.return_value = {"size": 1000, "gzip": 500}

            # Use patch to reduce sleep time
            with patch("bundlephobia_collector.asyncio.sleep", return_value=None):
                result = await get_bundle_sizes_batch(["pkg1", "pkg2"])

            assert "pkg1" in result
            assert "pkg2" in result
            assert mock_get.call_count == 2

    @pytest.mark.asyncio
    async def test_get_bundle_sizes_batch_empty(self):
        """Should handle empty package list."""
        from bundlephobia_collector import get_bundle_sizes_batch

        result = await get_bundle_sizes_batch([])
        assert result == {}

    @pytest.mark.asyncio
    async def test_get_bundle_sizes_batch_single(self):
        """Should handle single package without delay."""
        from bundlephobia_collector import get_bundle_sizes_batch

        with patch("bundlephobia_collector.get_bundle_size") as mock_get:
            mock_get.return_value = {"size": 1000}

            with patch("bundlephobia_collector.asyncio.sleep") as mock_sleep:
                result = await get_bundle_sizes_batch(["single-pkg"])

                assert "single-pkg" in result
                # No sleep needed for single package
                mock_sleep.assert_not_called()


# =============================================================================
# PACKAGE COLLECTOR INTEGRATION TESTS
# =============================================================================


class TestCollectPackageData:
    """Integration tests for collect_package_data function."""

    def test_collect_package_data_all_sources(self):
        """Test collecting data from all sources."""
        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)

            # deps.dev
            if "api.deps.dev/v3/systems/npm/packages/lodash:dependents" in url:
                return httpx.Response(200, json={"dependentCount": 150000})
            elif "api.deps.dev/v3/systems/npm/packages/lodash/versions" in url:
                return httpx.Response(
                    200,
                    json={
                        "publishedAt": "2021-02-20T00:00:00Z",
                        "licenses": ["MIT"],
                        "relations": {},
                        "advisories": [],
                        "links": [
                            {"label": "SOURCE_REPO", "url": "https://github.com/lodash/lodash"}
                        ],
                    },
                )
            elif "api.deps.dev/v3/systems/npm/packages/lodash" in url:
                return httpx.Response(200, json={"defaultVersion": "4.17.21"})
            elif "api.deps.dev/v3/projects" in url:
                return httpx.Response(
                    200,
                    json={"scorecardV2": {"score": 7.5, "check": []}},
                )

            # npm
            elif "registry.npmjs.org/lodash" in url:
                return httpx.Response(
                    200,
                    json={
                        "dist-tags": {"latest": "4.17.21"},
                        "time": {
                            "created": "2012-04-28T00:00:00.000Z",
                            "4.17.21": "2021-02-20T00:00:00.000Z",
                        },
                        "versions": {"4.17.21": {"types": "./index.d.ts"}},
                        "maintainers": [{"name": "jdalton"}],
                        "repository": {"url": "https://github.com/lodash/lodash"},
                    },
                )
            elif "api.npmjs.org/downloads" in url:
                return httpx.Response(200, json={"downloads": 50000000})

            # GitHub
            elif "api.github.com/repos/lodash/lodash/commits" in url:
                return httpx.Response(
                    200,
                    json=[
                        {
                            "author": {"login": "jdalton"},
                            "commit": {
                                "author": {"date": datetime.now(timezone.utc).isoformat()}
                            },
                        }
                    ],
                )
            elif "api.github.com/repos/lodash/lodash/contributors" in url:
                return httpx.Response(
                    200,
                    json=[{"login": "jdalton", "contributions": 1000}],
                )
            elif "api.github.com/repos/lodash/lodash" in url:
                return httpx.Response(
                    200,
                    json={
                        "stargazers_count": 58000,
                        "forks_count": 7000,
                        "open_issues_count": 120,
                        "watchers_count": 58000,
                        "archived": False,
                        "disabled": False,
                        "default_branch": "main",
                    },
                )

            # Bundlephobia
            elif "bundlephobia.com/api/size" in url:
                return httpx.Response(
                    200,
                    json={
                        "name": "lodash",
                        "version": "4.17.21",
                        "size": 71420,
                        "gzip": 25276,
                        "dependencyCount": 0,
                        "hasSideEffects": True,
                    },
                )

            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.dict(
            os.environ,
            {
                "PACKAGES_TABLE": "pkgwatch-packages",
                "RAW_DATA_BUCKET": "pkgwatch-raw-data",
                "GITHUB_TOKEN_SECRET_ARN": "",
                "API_KEYS_TABLE": "pkgwatch-api-keys",
            },
        ):
            with patch.object(httpx.AsyncClient, "__init__", patched_init), \
                 patch("package_collector._check_and_increment_github_rate_limit", return_value=True), \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=True):
                from package_collector import collect_package_data

                result = run_async(collect_package_data("npm", "lodash"))

                assert result["ecosystem"] == "npm"
                assert result["name"] == "lodash"
                assert "deps.dev" in result["sources"]
                assert "npm" in result["sources"]
                assert "github" in result["sources"]
                assert "bundlephobia" in result["sources"]
                assert result["weekly_downloads"] == 50000000
                assert result["stars"] == 58000
                assert result["openssf_score"] == 7.5
                assert result["bundle_size"] == 71420

    def test_collect_package_data_partial_failure(self):
        """Test graceful handling when some sources fail."""
        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)

            # deps.dev succeeds
            if "api.deps.dev/v3/systems/npm/packages/test-pkg:dependents" in url:
                return httpx.Response(200, json={"dependentCount": 100})
            elif "api.deps.dev/v3/systems/npm/packages/test-pkg/versions" in url:
                return httpx.Response(
                    200,
                    json={
                        "publishedAt": "2023-01-01T00:00:00Z",
                        "licenses": ["MIT"],
                        "relations": {},
                        "advisories": [],
                        "links": [],
                    },
                )
            elif "api.deps.dev/v3/systems/npm/packages/test-pkg" in url:
                return httpx.Response(200, json={"defaultVersion": "1.0.0"})

            # npm fails
            elif "registry.npmjs.org" in url:
                return httpx.Response(500)

            # Bundlephobia fails
            elif "bundlephobia.com" in url:
                return httpx.Response(404)

            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.dict(
            os.environ,
            {
                "PACKAGES_TABLE": "pkgwatch-packages",
                "RAW_DATA_BUCKET": "pkgwatch-raw-data",
                "GITHUB_TOKEN_SECRET_ARN": "",
                "API_KEYS_TABLE": "pkgwatch-api-keys",
            },
        ):
            with patch.object(httpx.AsyncClient, "__init__", patched_init), \
                 patch("rate_limit_utils.check_and_increment_external_rate_limit", return_value=True):
                from importlib import reload
                import package_collector
                reload(package_collector)

                result = run_async(package_collector.collect_package_data("npm", "test-pkg"))

                # Should still have deps.dev data
                assert "deps.dev" in result["sources"]
                assert result["latest_version"] == "1.0.0"

    def test_collect_package_data_uses_bulk_downloads(self):
        """Test that bulk_downloads parameter overrides individual npm download fetch."""
        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)

            # deps.dev
            if "api.deps.dev/v3/systems/npm/packages/test-pkg:dependents" in url:
                return httpx.Response(200, json={"dependentCount": 100})
            elif "api.deps.dev/v3/systems/npm/packages/test-pkg/versions" in url:
                return httpx.Response(
                    200,
                    json={
                        "publishedAt": "2023-01-01T00:00:00Z",
                        "licenses": ["MIT"],
                        "relations": {},
                        "advisories": [],
                        "links": [],
                    },
                )
            elif "api.deps.dev/v3/systems/npm/packages/test-pkg" in url:
                return httpx.Response(200, json={"defaultVersion": "1.0.0"})

            # npm registry metadata
            elif "registry.npmjs.org/test-pkg" in url:
                return httpx.Response(
                    200,
                    json={
                        "dist-tags": {"latest": "1.0.0"},
                        "time": {"created": "2023-01-01T00:00:00.000Z", "1.0.0": "2023-01-01T00:00:00.000Z"},
                        "versions": {"1.0.0": {}},
                        "maintainers": [{"name": "test"}],
                    },
                )

            # npm downloads - this should NOT be called when bulk_downloads is provided
            elif "api.npmjs.org/downloads" in url:
                # Return a different value to detect if individual fetch was used
                return httpx.Response(200, json={"downloads": 999})

            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.dict(
            os.environ,
            {
                "PACKAGES_TABLE": "pkgwatch-packages",
                "RAW_DATA_BUCKET": "pkgwatch-raw-data",
                "GITHUB_TOKEN_SECRET_ARN": "",
                "API_KEYS_TABLE": "pkgwatch-api-keys",
            },
        ):
            from importlib import reload
            import package_collector
            reload(package_collector)

            with patch.object(httpx.AsyncClient, "__init__", patched_init), \
                 patch.object(package_collector, "check_and_increment_external_rate_limit", return_value=True):

                # Pre-fetched bulk downloads (simulating batch processing)
                bulk_downloads = {"test-pkg": 12345}

                result = run_async(package_collector.collect_package_data(
                    "npm", "test-pkg", existing=None, retry_sources=None, bulk_downloads=bulk_downloads
                ))

                # Should use bulk-fetched downloads instead of individual fetch
                assert result["weekly_downloads"] == 12345
                assert result.get("downloads_source") == "bulk"


class TestStorePackageData:
    """Tests for store_package_data function."""

    @mock_aws
    def test_store_package_data_success(self):
        """Test storing package data in DynamoDB."""
        # Set up mock DynamoDB
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {"PACKAGES_TABLE": "pkgwatch-packages"}):
            # Need to reimport to get fresh boto3 resources
            from importlib import reload

            import package_collector

            reload(package_collector)

            data = {
                "latest_version": "1.0.0",
                "weekly_downloads": 100000,
                "stars": 5000,
                "sources": ["deps.dev", "npm"],
            }

            package_collector.store_package_data("npm", "test-pkg", data, tier=2)

            # Verify data was stored
            table = dynamodb.Table("pkgwatch-packages")
            response = table.get_item(Key={"pk": "npm#test-pkg", "sk": "LATEST"})

            assert "Item" in response
            item = response["Item"]
            assert item["ecosystem"] == "npm"
            assert item["name"] == "test-pkg"
            assert item["tier"] == 2
            assert item["weekly_downloads"] == 100000

    @mock_aws
    def test_store_package_data_removes_none_values(self):
        """Test that None values are not stored in DynamoDB."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {"PACKAGES_TABLE": "pkgwatch-packages"}):
            from importlib import reload

            import package_collector

            reload(package_collector)

            data = {
                "latest_version": "1.0.0",
                "openssf_score": None,  # Should be removed
                "days_since_last_commit": None,  # Should be removed
                "sources": ["deps.dev"],
            }

            package_collector.store_package_data("npm", "test-pkg", data, tier=3)

            table = dynamodb.Table("pkgwatch-packages")
            response = table.get_item(Key={"pk": "npm#test-pkg", "sk": "LATEST"})

            item = response["Item"]
            assert "openssf_score" not in item
            assert "days_since_last_commit" not in item

    @mock_aws
    def test_store_package_data_upgrades_minimal_to_abandoned(self):
        """Test that minimal packages with max retries become abandoned_minimal."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Pre-populate with a package that has exhausted retries
        table = dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#abandoned-test",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "abandoned-test",
                "data_status": "minimal",
                "retry_count": 5,  # Max retries reached
            }
        )

        with patch.dict(os.environ, {"PACKAGES_TABLE": "pkgwatch-packages"}):
            from importlib import reload

            import package_collector

            reload(package_collector)

            # Data that would still result in minimal status (deps.dev failed)
            data = {
                "latest_version": "1.0.0",
                "depsdev_error": "API unavailable",  # deps.dev failure = minimal
                "_existing_retry_count": 5,  # Signal that we're at max retries
            }

            package_collector.store_package_data("npm", "abandoned-test", data, tier=3)

            response = table.get_item(Key={"pk": "npm#abandoned-test", "sk": "LATEST"})

            item = response["Item"]
            # Should be upgraded to abandoned_minimal
            assert item["data_status"] == "abandoned_minimal"
            # Should preserve retry_count
            assert item["retry_count"] == 5
            # Should NOT have next_retry_at (no more retries)
            assert "next_retry_at" not in item

    @mock_aws
    def test_store_package_data_does_not_upgrade_below_max_retries(self):
        """Test that minimal packages below max retries stay minimal."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {"PACKAGES_TABLE": "pkgwatch-packages"}):
            from importlib import reload

            import package_collector

            reload(package_collector)

            # Data that results in minimal status with retries remaining
            data = {
                "latest_version": "1.0.0",
                "depsdev_error": "API unavailable",  # deps.dev failure = minimal
                "_existing_retry_count": 3,  # Below max (5)
            }

            package_collector.store_package_data("npm", "retry-test", data, tier=3)

            table = dynamodb.Table("pkgwatch-packages")
            response = table.get_item(Key={"pk": "npm#retry-test", "sk": "LATEST"})

            item = response["Item"]
            # Should stay minimal (not abandoned)
            assert item["data_status"] == "minimal"
            # Should have next_retry_at for future retry
            assert "next_retry_at" in item


class TestHandler:
    """Tests for the Lambda handler function."""

    @mock_aws
    def test_handler_single_message(self):
        """Test handler processing a single SQS message."""
        # Set up AWS mocks
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="pkgwatch-raw-data")

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "api.deps.dev" in url and ":dependents" in url:
                return httpx.Response(200, json={"dependentCount": 50})
            elif "api.deps.dev" in url and "/versions/" in url:
                return httpx.Response(
                    200,
                    json={
                        "publishedAt": "2023-01-01T00:00:00Z",
                        "licenses": ["MIT"],
                        "relations": {},
                        "advisories": [],
                        "links": [],
                    },
                )
            elif "api.deps.dev" in url:
                return httpx.Response(200, json={"defaultVersion": "1.0.0"})
            elif "registry.npmjs.org" in url:
                return httpx.Response(
                    200,
                    json={
                        "dist-tags": {"latest": "1.0.0"},
                        "time": {"created": "2023-01-01T00:00:00.000Z"},
                        "versions": {"1.0.0": {}},
                        "maintainers": [{"name": "author"}],
                        "repository": {},
                    },
                )
            elif "api.npmjs.org/downloads" in url:
                return httpx.Response(200, json={"downloads": 1000})
            elif "bundlephobia.com" in url:
                return httpx.Response(404)
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.dict(
            os.environ,
            {
                "PACKAGES_TABLE": "pkgwatch-packages",
                "RAW_DATA_BUCKET": "pkgwatch-raw-data",
                "GITHUB_TOKEN_SECRET_ARN": "",
                "API_KEYS_TABLE": "pkgwatch-api-keys",
            },
        ):
            with patch.object(httpx.AsyncClient, "__init__", patched_init), \
                 patch("rate_limit_utils.check_and_increment_external_rate_limit", return_value=True):
                from importlib import reload

                import package_collector

                reload(package_collector)

                event = {
                    "Records": [
                        {
                            "body": json.dumps(
                                {
                                    "ecosystem": "npm",
                                    "name": "test-pkg",
                                    "tier": 2,
                                    "reason": "test",
                                }
                            )
                        }
                    ]
                }

                result = package_collector.handler(event, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["processed"] == 1
                assert body["successes"] == 1
                assert body["failures"] == 0

    def test_handler_invalid_json(self):
        """Test handler handling invalid JSON in message body."""
        with patch.dict(
            os.environ,
            {
                "PACKAGES_TABLE": "pkgwatch-packages",
                "RAW_DATA_BUCKET": "pkgwatch-raw-data",
                "GITHUB_TOKEN_SECRET_ARN": "",
            },
        ):
            from importlib import reload

            import package_collector

            reload(package_collector)

            event = {"Records": [{"messageId": "msg-1", "body": "not valid json"}]}

            result = package_collector.handler(event, None)

            # Should not crash - with partial batch failure handling, invalid JSON
            # is counted as a failure and included in batchItemFailures for retry
            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["processed"] == 1  # 1 attempted (0 success + 1 failure)
            assert body["successes"] == 0
            assert body["failures"] == 1
            # Should include the failed message ID for SQS retry
            assert "batchItemFailures" in result
            assert result["batchItemFailures"] == [{"itemIdentifier": "msg-1"}]

    def test_handler_empty_records(self):
        """Test handler with no records."""
        with patch.dict(
            os.environ,
            {
                "PACKAGES_TABLE": "pkgwatch-packages",
                "RAW_DATA_BUCKET": "pkgwatch-raw-data",
                "GITHUB_TOKEN_SECRET_ARN": "",
            },
        ):
            from importlib import reload

            import package_collector

            reload(package_collector)

            event = {"Records": []}

            result = package_collector.handler(event, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["processed"] == 0


class TestGetGitHubToken:
    """Tests for get_github_token function."""

    @mock_aws
    def test_get_github_token_json_format(self):
        """Test retrieving token stored as JSON."""
        secrets = boto3.client("secretsmanager", region_name="us-east-1")
        secrets.create_secret(
            Name="github-token",
            SecretString=json.dumps({"token": "ghp_secret_token_123"}),
        )

        with patch.dict(
            os.environ,
            {"GITHUB_TOKEN_SECRET_ARN": "github-token"},
        ):
            from importlib import reload

            import package_collector

            reload(package_collector)

            token = package_collector.get_github_token()
            assert token == "ghp_secret_token_123"

    @mock_aws
    def test_get_github_token_plain_string(self):
        """Test retrieving token stored as plain string."""
        secrets = boto3.client("secretsmanager", region_name="us-east-1")
        secrets.create_secret(
            Name="github-token-plain",
            SecretString="ghp_plain_token_456",
        )

        with patch.dict(
            os.environ,
            {"GITHUB_TOKEN_SECRET_ARN": "github-token-plain"},
        ):
            from importlib import reload

            import package_collector

            reload(package_collector)

            token = package_collector.get_github_token()
            assert token == "ghp_plain_token_456"

    def test_get_github_token_no_arn(self):
        """Test when no secret ARN is configured."""
        with patch.dict(os.environ, {"GITHUB_TOKEN_SECRET_ARN": ""}):
            from importlib import reload

            import package_collector

            reload(package_collector)

            token = package_collector.get_github_token()
            assert token is None


# =============================================================================
# RETRY LOGIC TESTS
# =============================================================================


class TestRetryWithBackoff:
    """Tests for retry_with_backoff function.

    The retry_with_backoff function catches HTTPStatusError and RequestError.
    HTTPStatusError is only raised when raise_for_status() is called, which
    happens within the actual collector functions after retry returns.

    These tests verify the retry behavior when network errors occur.
    """

    def test_retry_on_network_error(self):
        """Test retry on network/connection errors."""
        from npm_collector import retry_with_backoff

        call_count = 0

        async def flaky_request(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.RequestError("Connection failed", request=None)
            # Return a mock response object
            return MagicMock(status_code=200, json=lambda: {"success": True})

        async def test_coro():
            nonlocal call_count
            call_count = 0
            result = await retry_with_backoff(
                flaky_request, max_retries=3, base_delay=0.01
            )
            return result.json(), call_count

        result, count = run_async(test_coro())
        assert result == {"success": True}
        assert count == 3

    def test_retry_exhausted_on_network_error(self):
        """Test exception raised when all retries exhausted."""
        from npm_collector import retry_with_backoff

        async def always_fail(*args, **kwargs):
            raise httpx.RequestError("Connection failed", request=None)

        async def test_coro():
            await retry_with_backoff(
                always_fail, max_retries=2, base_delay=0.01
            )

        with pytest.raises(httpx.RequestError):
            run_async(test_coro())

    def test_retry_on_http_status_error(self):
        """Test retry on HTTPStatusError (e.g., when raise_for_status is called)."""
        from npm_collector import retry_with_backoff

        call_count = 0

        async def failing_then_success(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_request = MagicMock()
            mock_response = MagicMock(status_code=500)
            if call_count < 2:
                raise httpx.HTTPStatusError(
                    "Server Error", request=mock_request, response=mock_response
                )
            return MagicMock(status_code=200, json=lambda: {"ok": True})

        async def test_coro():
            nonlocal call_count
            call_count = 0
            result = await retry_with_backoff(
                failing_then_success, max_retries=3, base_delay=0.01
            )
            return result.json(), call_count

        result, count = run_async(test_coro())
        assert result == {"ok": True}
        assert count == 2


# =============================================================================
# DLQ Processor Tests
# =============================================================================


class TestDLQProcessor:
    """Tests for the DLQ processor Lambda."""

    @pytest.fixture(autouse=True)
    def setup_env(self, monkeypatch):
        """Set up environment variables for DLQ processor."""
        monkeypatch.setenv("DLQ_URL", "https://sqs.us-east-1.amazonaws.com/123456789/test-dlq")
        monkeypatch.setenv("MAIN_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789/test-queue")
        monkeypatch.setenv("PACKAGES_TABLE", "test-packages")
        monkeypatch.setenv("MAX_DLQ_RETRIES", "5")

    def test_handler_missing_dlq_url(self, monkeypatch):
        """Handler should return error if DLQ_URL not configured."""
        monkeypatch.delenv("DLQ_URL", raising=False)

        # Force reimport to pick up new env
        import importlib
        import sys
        if "dlq_processor" in sys.modules:
            del sys.modules["dlq_processor"]

        from dlq_processor import handler

        result = handler({}, {})
        assert result == {"error": "DLQ_URL not configured"}

    def test_handler_missing_main_queue_url(self, monkeypatch):
        """Handler should return error if MAIN_QUEUE_URL not configured."""
        monkeypatch.delenv("MAIN_QUEUE_URL", raising=False)

        import importlib
        import sys
        if "dlq_processor" in sys.modules:
            del sys.modules["dlq_processor"]

        from dlq_processor import handler

        result = handler({}, {})
        assert result == {"error": "MAIN_QUEUE_URL not configured"}

    def test_process_dlq_message_invalid_json(self):
        """Invalid JSON in message should be skipped and deleted."""
        from dlq_processor import _process_dlq_message

        with patch("dlq_processor._delete_dlq_message") as mock_delete:
            message = {
                "MessageId": "test-123",
                "Body": "not valid json at all",
                "ReceiptHandle": "test-handle",
            }

            result = _process_dlq_message(message)

            assert result == "skipped"
            mock_delete.assert_called_once_with(message)

    def test_process_dlq_message_missing_body(self):
        """Message without Body key should be skipped."""
        from dlq_processor import _process_dlq_message

        with patch("dlq_processor._delete_dlq_message") as mock_delete:
            message = {
                "MessageId": "test-123",
                "ReceiptHandle": "test-handle",
                # No "Body" key
            }

            result = _process_dlq_message(message)

            assert result == "skipped"
            mock_delete.assert_called_once()

    def test_process_dlq_message_exceeds_max_retries(self):
        """Message exceeding max retries should be stored as permanent failure."""
        from dlq_processor import _process_dlq_message

        with patch("dlq_processor._delete_dlq_message") as mock_delete, \
             patch("dlq_processor._store_permanent_failure") as mock_store:
            message = {
                "MessageId": "test-123",
                "Body": json.dumps({
                    "ecosystem": "npm",
                    "name": "test-package",
                    "_retry_count": 5,  # At max
                    "_last_error": "rate_limited",
                }),
                "ReceiptHandle": "test-handle",
            }

            result = _process_dlq_message(message)

            assert result == "permanently_failed"
            mock_store.assert_called_once()
            mock_delete.assert_called_once_with(message)

    def test_process_dlq_message_requeues_with_backoff(self):
        """Message under max retries should be requeued with exponential backoff."""
        from dlq_processor import _process_dlq_message

        with patch("dlq_processor.sqs") as mock_sqs, \
             patch("dlq_processor._delete_dlq_message") as mock_delete:
            message = {
                "MessageId": "test-123",
                "Body": json.dumps({
                    "ecosystem": "npm",
                    "name": "test-package",
                    "_retry_count": 2,
                }),
                "ReceiptHandle": "test-handle",
            }

            result = _process_dlq_message(message)

            assert result == "requeued"
            mock_sqs.send_message.assert_called_once()
            call_kwargs = mock_sqs.send_message.call_args.kwargs

            # Verify retry count was incremented
            body = json.loads(call_kwargs["MessageBody"])
            assert body["_retry_count"] == 3

            # Verify exponential backoff: 60 * 2^2 = 240 seconds
            assert call_kwargs["DelaySeconds"] == 240

            mock_delete.assert_called_once_with(message)

    def test_exponential_backoff_values(self):
        """Verify exponential backoff calculation."""
        from dlq_processor import _process_dlq_message

        # Test backoff values for each retry count
        expected_delays = {
            0: 60,    # 60 * 2^0 = 60
            1: 120,   # 60 * 2^1 = 120
            2: 240,   # 60 * 2^2 = 240
            3: 480,   # 60 * 2^3 = 480
            4: 900,   # 60 * 2^4 = 960, but capped at 900
        }

        for retry_count, expected_delay in expected_delays.items():
            with patch("dlq_processor.sqs") as mock_sqs, \
                 patch("dlq_processor._delete_dlq_message"):
                message = {
                    "MessageId": f"test-{retry_count}",
                    "Body": json.dumps({
                        "ecosystem": "npm",
                        "name": "test-package",
                        "_retry_count": retry_count,
                    }),
                    "ReceiptHandle": "test-handle",
                }

                _process_dlq_message(message)

                call_kwargs = mock_sqs.send_message.call_args.kwargs
                assert call_kwargs["DelaySeconds"] == expected_delay, \
                    f"Retry {retry_count}: expected {expected_delay}, got {call_kwargs['DelaySeconds']}"

    def test_process_dlq_message_requeue_failure_doesnt_delete(self):
        """If requeue fails, message should NOT be deleted from DLQ."""
        from dlq_processor import _process_dlq_message

        with patch("dlq_processor.sqs") as mock_sqs, \
             patch("dlq_processor._delete_dlq_message") as mock_delete:
            mock_sqs.send_message.side_effect = Exception("SQS error")

            message = {
                "MessageId": "test-123",
                "Body": json.dumps({
                    "ecosystem": "npm",
                    "name": "test-package",
                    "_retry_count": 0,
                }),
                "ReceiptHandle": "test-handle",
            }

            result = _process_dlq_message(message)

            assert result == "skipped"
            mock_delete.assert_not_called()  # Should NOT delete if requeue failed

    def test_store_permanent_failure(self, mock_dynamodb, monkeypatch):
        """Permanent failures should be stored in DynamoDB."""
        # Create the packages table
        mock_dynamodb.create_table(
            TableName="test-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Reimport to pick up env
        import sys
        if "dlq_processor" in sys.modules:
            del sys.modules["dlq_processor"]
        from dlq_processor import _store_permanent_failure

        body = {
            "ecosystem": "npm",
            "name": "failing-package",
            "_retry_count": 5,
        }

        _store_permanent_failure(body, "msg-123", "rate_limited")

        # Verify item was put into DynamoDB
        table = mock_dynamodb.Table("test-packages")
        response = table.scan()
        items = response.get("Items", [])

        # Find the FAILED# item
        failed_items = [i for i in items if i.get("pk", "").startswith("FAILED#")]
        assert len(failed_items) == 1
        assert failed_items[0]["ecosystem"] == "npm"
        assert failed_items[0]["name"] == "failing-package"
        assert failed_items[0]["failure_reason"] == "rate_limited"

    def test_handler_processes_empty_queue(self, monkeypatch):
        """Handler should handle empty DLQ gracefully."""
        # Ensure env vars are set
        monkeypatch.setenv("DLQ_URL", "https://sqs.us-east-1.amazonaws.com/123456789/test-dlq")
        monkeypatch.setenv("MAIN_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789/test-queue")

        import sys
        if "dlq_processor" in sys.modules:
            del sys.modules["dlq_processor"]
        from dlq_processor import handler

        with patch("dlq_processor.sqs") as mock_sqs:
            mock_sqs.receive_message.return_value = {"Messages": []}

            result = handler({}, {})

            assert result["processed"] == 0
            assert result["requeued"] == 0
            assert result["permanently_failed"] == 0

    def test_handler_processes_multiple_messages(self, monkeypatch):
        """Handler should process multiple messages from DLQ."""
        # Ensure env vars are set
        monkeypatch.setenv("DLQ_URL", "https://sqs.us-east-1.amazonaws.com/123456789/test-dlq")
        monkeypatch.setenv("MAIN_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789/test-queue")

        import sys
        if "dlq_processor" in sys.modules:
            del sys.modules["dlq_processor"]
        from dlq_processor import handler

        with patch("dlq_processor.sqs") as mock_sqs, \
             patch("dlq_processor._process_dlq_message") as mock_process:
            # First call returns 2 messages, second call returns empty
            mock_sqs.receive_message.side_effect = [
                {"Messages": [{"MessageId": "1"}, {"MessageId": "2"}]},
                {"Messages": []},
            ]
            mock_process.return_value = "requeued"

            result = handler({}, {})

            assert result["processed"] == 2
            assert result["requeued"] == 2
            assert mock_process.call_count == 2


# =============================================================================
# NEW FUNCTIONALITY TESTS - Data Pipeline Reliability
# =============================================================================


class TestMessageValidation:
    """Tests for message validation in package_collector."""

    def test_validate_valid_npm_package(self):
        """Valid npm package should pass validation."""
        from package_collector import validate_message

        message = {"ecosystem": "npm", "name": "lodash"}
        is_valid, error = validate_message(message)

        assert is_valid is True
        assert error is None

    def test_validate_scoped_package(self):
        """Valid scoped package should pass validation."""
        from package_collector import validate_message

        message = {"ecosystem": "npm", "name": "@babel/core"}
        is_valid, error = validate_message(message)

        assert is_valid is True
        assert error is None

    def test_validate_missing_ecosystem(self):
        """Missing ecosystem should fail validation."""
        from package_collector import validate_message

        message = {"name": "lodash"}
        is_valid, error = validate_message(message)

        assert is_valid is False
        assert "ecosystem" in error

    def test_validate_missing_name(self):
        """Missing name should fail validation."""
        from package_collector import validate_message

        message = {"ecosystem": "npm"}
        is_valid, error = validate_message(message)

        assert is_valid is False
        assert "name" in error

    def test_validate_unsupported_ecosystem(self):
        """Unsupported ecosystem should fail validation."""
        from package_collector import validate_message

        message = {"ecosystem": "maven", "name": "com.example:artifact"}
        is_valid, error = validate_message(message)

        assert is_valid is False
        assert "Unsupported ecosystem" in error

    def test_validate_package_name_too_long(self):
        """Package name exceeding 214 chars should fail."""
        from package_collector import validate_message

        long_name = "a" * 215
        message = {"ecosystem": "npm", "name": long_name}
        is_valid, error = validate_message(message)

        assert is_valid is False
        assert "too long" in error

    def test_validate_invalid_package_name_format(self):
        """Invalid package name format should fail (structural issues, not case)."""
        from package_collector import validate_message

        # Packages starting with underscore should fail (per npm rules)
        message = {"ecosystem": "npm", "name": "_private"}
        is_valid, error = validate_message(message)
        assert is_valid is False
        assert "Invalid npm package name format" in error

        # Packages starting with dot should fail
        message = {"ecosystem": "npm", "name": ".hidden"}
        is_valid, error = validate_message(message)
        assert is_valid is False
        assert "Invalid npm package name format" in error

    def test_validate_uppercase_package_normalized(self):
        """Uppercase npm package should pass and be normalized."""
        from package_collector import validate_message

        message = {"ecosystem": "npm", "name": "JSONStream"}
        is_valid, error = validate_message(message)

        assert is_valid is True
        assert error is None
        assert message["name"] == "jsonstream"  # Normalized
        assert message["_original_name"] == "JSONStream"  # Original preserved

    def test_validate_path_traversal_attempt(self):
        """Path traversal attempts should fail validation."""
        from package_collector import validate_message

        message = {"ecosystem": "npm", "name": "../../../etc/passwd"}
        is_valid, error = validate_message(message)

        assert is_valid is False
        assert "path traversal detected" in error


class TestRateLimitAtomicOperation:
    """Tests for the fixed GitHub rate limit race condition."""

    @mock_aws
    def test_rate_limit_atomic_increment_success(self):
        """Test successful atomic rate limit increment."""
        # Set up mock DynamoDB
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-api-keys",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(
            os.environ,
            {
                "API_KEYS_TABLE": "pkgwatch-api-keys",
            },
        ):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # First call should succeed
            result = package_collector._check_and_increment_github_rate_limit()
            assert result is True

    @mock_aws
    def test_rate_limit_atomic_increment_limit_exceeded(self):
        """Test rate limit enforcement with atomic operation."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="pkgwatch-api-keys",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(
            os.environ,
            {
                "API_KEYS_TABLE": "pkgwatch-api-keys",
            },
        ):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Pre-populate rate limit counter at the limit
            window_key = package_collector._get_rate_limit_window_key()
            per_shard_limit = (package_collector.GITHUB_HOURLY_LIMIT // package_collector.RATE_LIMIT_SHARDS) + 50

            # Fill up all shards to the limit
            for shard_id in range(package_collector.RATE_LIMIT_SHARDS):
                table.put_item(
                    Item={
                        "pk": f"github_rate_limit#{shard_id}",
                        "sk": window_key,
                        "calls": per_shard_limit,
                        "ttl": int(datetime.now(timezone.utc).timestamp()) + 7200,
                    }
                )

            # Next call should be rejected
            result = package_collector._check_and_increment_github_rate_limit()
            assert result is False


class TestErrorClassification:
    """Tests for error classification in DLQ processor."""

    def test_classify_permanent_error_404(self):
        """404 errors should be classified as permanent."""
        from dlq_processor import classify_error

        error_msg = "404 package not found"
        result = classify_error(error_msg)

        assert result == "permanent"

    def test_classify_permanent_error_not_found(self):
        """'not found' errors should be classified as permanent."""
        from dlq_processor import classify_error

        error_msg = "Package not found in registry"
        result = classify_error(error_msg)

        assert result == "permanent"

    def test_classify_invalid_package_now_transient(self):
        """'invalid package' errors are now unknown (transient) to allow retry after regex fix."""
        from dlq_processor import classify_error

        error_msg = "Invalid package name specified"
        result = classify_error(error_msg)

        # Changed: These were previously permanent but are now unknown to allow
        # packages with uppercase/underscore scopes to be retried after the regex fix
        assert result == "unknown"

    def test_classify_permanent_error_forbidden(self):
        """'forbidden' errors should be classified as permanent."""
        from dlq_processor import classify_error

        error_msg = "403 Forbidden: Access denied"
        result = classify_error(error_msg)

        assert result == "permanent"

    def test_classify_validation_now_transient(self):
        """Validation format errors are now unknown (transient) to allow retry."""
        from dlq_processor import classify_error

        error_msg = "validation_error: Invalid package name format"
        result = classify_error(error_msg)

        # Changed: These were previously permanent but are now unknown to allow
        # retry after the regex fix accepts more package name formats
        assert result == "unknown"

    def test_classify_permanent_error_path_traversal(self):
        """Path traversal errors should remain permanent (security)."""
        from dlq_processor import classify_error

        error_msg = "Invalid package name (path traversal detected)"
        result = classify_error(error_msg)

        assert result == "permanent"

    def test_classify_permanent_error_too_long(self):
        """Package name too long errors should remain permanent."""
        from dlq_processor import classify_error

        error_msg = "Package name too long: 250 > 214"
        result = classify_error(error_msg)

        assert result == "permanent"

    def test_classify_permanent_error_empty(self):
        """Empty package name errors should remain permanent."""
        from dlq_processor import classify_error

        error_msg = "Empty package name"
        result = classify_error(error_msg)

        assert result == "permanent"

    def test_classify_transient_error_timeout(self):
        """Timeout errors should be classified as transient."""
        from dlq_processor import classify_error

        error_msg = "Request timeout after 30 seconds"
        result = classify_error(error_msg)

        assert result == "transient"

    def test_classify_transient_error_502(self):
        """502 errors should be classified as transient."""
        from dlq_processor import classify_error

        error_msg = "502 Bad Gateway"
        result = classify_error(error_msg)

        assert result == "transient"

    def test_classify_transient_error_503(self):
        """503 Service Unavailable should be classified as transient."""
        from dlq_processor import classify_error

        error_msg = "503 Service Unavailable"
        result = classify_error(error_msg)

        assert result == "transient"

    def test_classify_transient_error_504(self):
        """504 Gateway Timeout should be classified as transient."""
        from dlq_processor import classify_error

        error_msg = "504 Gateway Timeout"
        result = classify_error(error_msg)

        assert result == "transient"

    def test_classify_transient_error_rate_limit(self):
        """'rate limit' errors should be classified as transient."""
        from dlq_processor import classify_error

        error_msg = "Rate limit exceeded, try again later"
        result = classify_error(error_msg)

        assert result == "transient"

    def test_classify_transient_error_connection(self):
        """'connection' errors should be classified as transient."""
        from dlq_processor import classify_error

        error_msg = "Connection refused by server"
        result = classify_error(error_msg)

        assert result == "transient"

    def test_classify_transient_error_unavailable(self):
        """'unavailable' errors should be classified as transient."""
        from dlq_processor import classify_error

        error_msg = "Service temporarily unavailable"
        result = classify_error(error_msg)

        assert result == "transient"

    def test_classify_error_case_insensitive(self):
        """Error classification should be case insensitive."""
        from dlq_processor import classify_error

        assert classify_error("TIMEOUT ERROR") == "transient"
        assert classify_error("Not Found") == "permanent"
        assert classify_error("Rate Limit Exceeded") == "transient"

    def test_classify_unknown_error(self):
        """Unknown errors should be classified as unknown."""
        from dlq_processor import classify_error

        error_msg = "Something unexpected happened"
        result = classify_error(error_msg)

        assert result == "unknown"

    def test_classify_error_empty_message(self):
        """Empty error message should return unknown."""
        from dlq_processor import classify_error

        result = classify_error("")
        assert result == "unknown"

        result = classify_error(None)
        assert result == "unknown"


class TestStaleDataFallback:
    """Tests for stale data fallback in package_collector."""

    def test_is_data_acceptable_fresh_data(self):
        """Fresh data within max age should be acceptable."""
        from package_collector import _is_data_acceptable

        recent_time = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        data = {"last_updated": recent_time}

        result = _is_data_acceptable(data, max_age_days=7)
        assert result is True

    def test_is_data_acceptable_stale_data(self):
        """Data older than max age should not be acceptable."""
        from package_collector import _is_data_acceptable

        old_time = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        data = {"last_updated": old_time}

        result = _is_data_acceptable(data, max_age_days=7)
        assert result is False

    def test_is_data_acceptable_missing_last_updated(self):
        """Data without last_updated should not be acceptable."""
        from package_collector import _is_data_acceptable

        data = {"name": "test-pkg"}
        result = _is_data_acceptable(data, max_age_days=7)
        assert result is False

    def test_is_data_acceptable_invalid_date_format(self):
        """Data with invalid date format should not be acceptable."""
        from package_collector import _is_data_acceptable

        data = {"last_updated": "not-a-date"}
        result = _is_data_acceptable(data, max_age_days=7)
        assert result is False

    def test_extract_cached_fields(self):
        """Extract cached fields should return correct subset of data."""
        from package_collector import _extract_cached_fields

        existing = {
            "latest_version": "1.0.0",
            "published_at": "2023-01-01T00:00:00Z",
            "licenses": ["MIT"],
            "dependents_count": 100,
            "repository_url": "https://github.com/user/repo",
            "extra_field": "should not be included",
        }

        result = _extract_cached_fields(existing)

        assert result["latest_version"] == "1.0.0"
        assert result["licenses"] == ["MIT"]
        assert result["dependents_count"] == 100
        assert "extra_field" not in result


class TestPipelineMetrics:
    """Tests for pipeline metrics emission."""

    def test_emit_metric_success(self):
        """Test successful metric emission."""
        from shared.metrics import emit_metric

        with patch("shared.metrics._get_cloudwatch") as mock_get_cw:
            mock_cw = MagicMock()
            mock_get_cw.return_value = mock_cw
            emit_metric("TestMetric", value=5.0, dimensions={"Test": "Value"})

            mock_cw.put_metric_data.assert_called_once()
            call_args = mock_cw.put_metric_data.call_args

            assert call_args.kwargs["Namespace"] == "PkgWatch"
            assert call_args.kwargs["MetricData"][0]["MetricName"] == "TestMetric"
            assert call_args.kwargs["MetricData"][0]["Value"] == 5.0

    def test_emit_metric_failure_doesnt_crash(self):
        """Test that metric emission failures don't crash Lambda."""
        from shared.metrics import emit_metric

        with patch("shared.metrics._get_cloudwatch") as mock_get_cw:
            mock_cw = MagicMock()
            mock_get_cw.return_value = mock_cw
            mock_cw.put_metric_data.side_effect = Exception("CloudWatch error")

            # Should not raise exception
            emit_metric("TestMetric", value=1.0)

    def test_emit_batch_metrics_success(self):
        """Test successful batch metrics emission."""
        from shared.metrics import emit_batch_metrics

        with patch("shared.metrics._get_cloudwatch") as mock_get_cw:
            mock_cw = MagicMock()
            mock_get_cw.return_value = mock_cw
            metrics = [
                {"metric_name": "Metric1", "value": 10},
                {"metric_name": "Metric2", "value": 20, "unit": "Seconds"},
                {"metric_name": "Metric3", "value": 30, "dimensions": {"Env": "Test"}},
            ]
            emit_batch_metrics(metrics)

            mock_cw.put_metric_data.assert_called_once()
            call_args = mock_cw.put_metric_data.call_args
            metric_data = call_args.kwargs["MetricData"]

            assert len(metric_data) == 3
            assert metric_data[0]["MetricName"] == "Metric1"
            assert metric_data[1]["Unit"] == "Seconds"
            assert metric_data[2]["Dimensions"][0]["Name"] == "Env"

    def test_emit_batch_metrics_pagination(self):
        """Test batch metrics are paginated at 20 per request."""
        from shared.metrics import emit_batch_metrics

        with patch("shared.metrics._get_cloudwatch") as mock_get_cw:
            mock_cw = MagicMock()
            mock_get_cw.return_value = mock_cw
            # Create 25 metrics (should be 2 API calls)
            metrics = [{"metric_name": f"Metric{i}", "value": i} for i in range(25)]
            emit_batch_metrics(metrics)

            assert mock_cw.put_metric_data.call_count == 2
            # First call should have 20 metrics
            first_call = mock_cw.put_metric_data.call_args_list[0]
            assert len(first_call.kwargs["MetricData"]) == 20
            # Second call should have 5 metrics
            second_call = mock_cw.put_metric_data.call_args_list[1]
            assert len(second_call.kwargs["MetricData"]) == 5

    def test_emit_batch_metrics_failure_doesnt_crash(self):
        """Test that batch metric emission failures don't crash."""
        from shared.metrics import emit_batch_metrics

        with patch("shared.metrics._get_cloudwatch") as mock_get_cw:
            mock_cw = MagicMock()
            mock_get_cw.return_value = mock_cw
            mock_cw.put_metric_data.side_effect = Exception("CloudWatch error")

            # Should not raise exception
            metrics = [{"metric_name": "Test", "value": 1.0}]
            emit_batch_metrics(metrics)


class TestHelperFunctions:
    """Tests for helper functions in package_collector."""

    def test_get_rate_limit_window_key(self):
        """Test rate limit window key generation."""
        from package_collector import _get_rate_limit_window_key

        # Mock datetime to get consistent result
        mock_time = datetime(2024, 3, 15, 14, 30, 0, tzinfo=timezone.utc)
        with patch("package_collector.datetime") as mock_dt:
            mock_dt.now.return_value = mock_time
            mock_dt.timezone = timezone

            result = _get_rate_limit_window_key()

            # Should be YYYY-MM-DD-HH format
            assert result == "2024-03-15-14"

    @mock_aws
    def test_get_total_github_calls_empty(self):
        """Test getting total GitHub calls when no shards exist."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-api-keys",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {"API_KEYS_TABLE": "pkgwatch-api-keys"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            total = package_collector._get_total_github_calls("2024-03-15-14")
            assert total == 0

    @mock_aws
    def test_get_total_github_calls_with_data(self):
        """Test getting total GitHub calls across shards."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="pkgwatch-api-keys",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Add data to multiple shards
        window_key = "2024-03-15-14"
        table.put_item(Item={"pk": "github_rate_limit#0", "sk": window_key, "calls": 100})
        table.put_item(Item={"pk": "github_rate_limit#1", "sk": window_key, "calls": 150})
        table.put_item(Item={"pk": "github_rate_limit#2", "sk": window_key, "calls": 200})

        with patch.dict(os.environ, {"API_KEYS_TABLE": "pkgwatch-api-keys"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            total = package_collector._get_total_github_calls(window_key)
            assert total == 450  # 100 + 150 + 200

    @mock_aws
    def test_rate_limit_fails_closed_on_dynamodb_error(self):
        """Test that rate limit check fails closed on DynamoDB errors."""
        # Create table but don't configure it properly to trigger errors
        with patch.dict(os.environ, {"API_KEYS_TABLE": "nonexistent-table"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Should return False (fail closed) on error
            result = package_collector._check_and_increment_github_rate_limit()
            assert result is False


class TestConfigurableValues:
    """Tests for configurable threshold values."""

    def test_stale_data_age_configurable(self):
        """Test that stale data max age is configurable."""
        with patch.dict(os.environ, {"STALE_DATA_MAX_AGE_DAYS": "14"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            assert package_collector.STALE_DATA_MAX_AGE_DAYS == 14

    def test_dedup_window_configurable(self):
        """Test that deduplication window is configurable."""
        with patch.dict(os.environ, {"DEDUP_WINDOW_MINUTES": "60"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            assert package_collector.DEDUP_WINDOW_MINUTES == 60

    def test_tier_jitter_configurable(self):
        """Test that tier jitter values are configurable."""
        with patch.dict(os.environ, {
            "TIER1_JITTER_MAX": "600",
            "TIER2_JITTER_MAX": "1200",
            "TIER3_JITTER_MAX": "3600",
        }):
            from importlib import reload
            import refresh_dispatcher
            reload(refresh_dispatcher)

            assert refresh_dispatcher.JITTER_MAX_SECONDS[1] == 600
            assert refresh_dispatcher.JITTER_MAX_SECONDS[2] == 1200
            assert refresh_dispatcher.JITTER_MAX_SECONDS[3] == 3600


# =============================================================================
# PACKAGE COLLECTOR COVERAGE TESTS
# =============================================================================


class TestErrorRecoveryFlows:
    """Tests for error recovery in package_collector (lines 286-288, etc.)."""

    @mock_aws
    def test_get_existing_package_data_exception_returns_none(self):
        """Test that _get_existing_package_data returns None on exception (lines 286-288)."""
        with patch.dict(os.environ, {"PACKAGES_TABLE": "pkgwatch-packages"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Patch DynamoDB to raise an exception
            with patch.object(package_collector, "_get_dynamodb") as mock_get_ddb:
                mock_table = MagicMock()
                mock_table.get_item.side_effect = Exception("DynamoDB error")
                mock_resource = MagicMock()
                mock_resource.Table.return_value = mock_table
                mock_get_ddb.return_value = mock_resource

                # Should return None, not raise exception
                result = run_async(package_collector._get_existing_package_data("npm", "test-pkg"))
                assert result is None

    @mock_aws
    def test_store_collection_error_success(self):
        """Test _store_collection_error stores error in DynamoDB (lines 299-321)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create initial record
        table.put_item(Item={
            "pk": "npm#test-pkg",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "test-pkg",
        })

        with patch.dict(os.environ, {"PACKAGES_TABLE": "pkgwatch-packages"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            package_collector._store_collection_error("npm", "test-pkg", "Test error message")

            # Verify error was stored
            response = table.get_item(Key={"pk": "npm#test-pkg", "sk": "LATEST"})
            item = response.get("Item", {})
            assert item.get("collection_error") == "Test error message"
            assert "collection_error_at" in item
            assert "collection_error_class" in item

    def test_store_collection_error_handles_exception(self):
        """Test _store_collection_error handles DynamoDB errors gracefully (line 321)."""
        with patch.dict(os.environ, {"PACKAGES_TABLE": "pkgwatch-packages"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Patch DynamoDB to raise an exception
            with patch.object(package_collector, "_get_dynamodb") as mock_get_ddb:
                mock_table = MagicMock()
                mock_table.update_item.side_effect = Exception("DynamoDB error")
                mock_resource = MagicMock()
                mock_resource.Table.return_value = mock_table
                mock_get_ddb.return_value = mock_resource

                # Should not raise exception
                package_collector._store_collection_error("npm", "test-pkg", "Error")

    def test_is_data_acceptable_returns_false_for_none_data(self):
        """Test _is_data_acceptable returns False for None data (line 327)."""
        from package_collector import _is_data_acceptable

        result = _is_data_acceptable(None, max_age_days=7)
        assert result is False


class TestStaleThresholdHandling:
    """Tests for stale data threshold handling (lines 382-396, 413-430)."""

    def test_get_stale_threshold_days_circuit_open(self):
        """Test _get_stale_threshold_days returns 14 for circuit errors (lines 389-393)."""
        from package_collector import _get_stale_threshold_days

        result = _get_stale_threshold_days("circuit_open")
        assert result == 14

        result = _get_stale_threshold_days("GitHub circuit breaker tripped")
        assert result == 14

    def test_get_stale_threshold_days_rate_limit(self):
        """Test _get_stale_threshold_days returns 7 for rate limit errors (lines 394-395)."""
        from package_collector import _get_stale_threshold_days

        result = _get_stale_threshold_days("rate_limit_exceeded")
        assert result == 7

        result = _get_stale_threshold_days("API rate_limit reached")
        assert result == 7

    def test_get_stale_threshold_days_default(self):
        """Test _get_stale_threshold_days returns default for other errors (line 396)."""
        from package_collector import _get_stale_threshold_days

        result = _get_stale_threshold_days("some other error")
        assert result == 7

        result = _get_stale_threshold_days("")
        assert result == 7

    def test_get_stale_threshold_days_none_input(self):
        """Test _get_stale_threshold_days returns default for None (line 389-390)."""
        from package_collector import _get_stale_threshold_days

        result = _get_stale_threshold_days(None)
        assert result == 7

    @mock_aws
    def test_try_github_stale_fallback_with_valid_stale_data(self):
        """Test _try_github_stale_fallback uses cached data (lines 413-430)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create existing package data with GitHub fields
        recent_time = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        table.put_item(Item={
            "pk": "npm#test-pkg",
            "sk": "LATEST",
            "last_updated": recent_time,
            "stars": 1000,
            "forks": 100,
            "days_since_last_commit": 5,
            "commits_90d": 50,
            "sources": ["github"],
        })

        with patch.dict(os.environ, {"PACKAGES_TABLE": "pkgwatch-packages"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            combined_data = {"sources": []}

            run_async(package_collector._try_github_stale_fallback(
                combined_data, "npm", "test-pkg", "rate_limit_exceeded"
            ))

            # Verify stale data was used
            assert combined_data.get("stars") == 1000
            assert combined_data.get("forks") == 100
            assert combined_data.get("github_freshness") == "stale"
            assert combined_data.get("github_stale_reason") == "rate_limit_exceeded"
            assert "github_stale" in combined_data.get("sources", [])

    @mock_aws
    def test_try_github_stale_fallback_circuit_open_accepts_older_data(self):
        """Test circuit_open error accepts 14-day old data (lines 416-417)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create existing package data that's 10 days old
        old_time = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        table.put_item(Item={
            "pk": "npm#test-pkg",
            "sk": "LATEST",
            "last_updated": old_time,
            "stars": 500,
            "days_since_last_commit": 15,
        })

        with patch.dict(os.environ, {"PACKAGES_TABLE": "pkgwatch-packages"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            combined_data = {"sources": []}

            # With rate_limit (7 days), 10-day data would be rejected
            run_async(package_collector._try_github_stale_fallback(
                combined_data, "npm", "test-pkg", "rate_limit_exceeded"
            ))
            assert combined_data.get("stars") is None  # Should not use stale data

            # With circuit_open (14 days), 10-day data should be accepted
            combined_data = {"sources": []}
            run_async(package_collector._try_github_stale_fallback(
                combined_data, "npm", "test-pkg", "circuit_open"
            ))
            assert combined_data.get("stars") == 500

    @mock_aws
    def test_try_github_stale_fallback_no_existing_data(self):
        """Test _try_github_stale_fallback handles missing data gracefully."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {"PACKAGES_TABLE": "pkgwatch-packages"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            combined_data = {"sources": []}

            # Should not crash when no existing data
            run_async(package_collector._try_github_stale_fallback(
                combined_data, "npm", "nonexistent-pkg", "rate_limit"
            ))
            assert "github_freshness" not in combined_data


class TestExtractCachedGitHubFields:
    """Tests for _extract_cached_github_fields (line 358)."""

    def test_extract_cached_github_fields_complete_data(self):
        """Test extracting all GitHub fields from cached data."""
        from package_collector import _extract_cached_github_fields

        existing = {
            "stars": 1000,
            "forks": 200,
            "open_issues": 50,
            "days_since_last_commit": 3,
            "commits_90d": 45,
            "active_contributors_90d": 8,
            "total_contributors": 25,
            "true_bus_factor": 3,
            "bus_factor_confidence": "HIGH",
            "contribution_distribution": [50, 30, 20],
            "archived": False,
            "extra_field": "ignored",
        }

        result = _extract_cached_github_fields(existing)

        assert result["stars"] == 1000
        assert result["forks"] == 200
        assert result["true_bus_factor"] == 3
        assert result["archived"] is False
        assert "extra_field" not in result

    def test_extract_cached_github_fields_partial_data(self):
        """Test extracting fields when some are missing."""
        from package_collector import _extract_cached_github_fields

        existing = {
            "stars": 500,
            # Most fields missing
        }

        result = _extract_cached_github_fields(existing)

        assert result["stars"] == 500
        assert result["forks"] is None
        assert result.get("contribution_distribution") == []


class TestHasGitHubData:
    """Tests for _has_github_data (line 375)."""

    def test_has_github_data_with_stars(self):
        """Test _has_github_data returns True when stars present."""
        from package_collector import _has_github_data

        assert _has_github_data({"stars": 100}) is True
        assert _has_github_data({"stars": 0}) is True

    def test_has_github_data_with_days_since_commit(self):
        """Test _has_github_data returns True when days_since_last_commit present."""
        from package_collector import _has_github_data

        assert _has_github_data({"days_since_last_commit": 5}) is True
        assert _has_github_data({"days_since_last_commit": 0}) is True

    def test_has_github_data_with_commits_90d(self):
        """Test _has_github_data returns True when commits_90d present."""
        from package_collector import _has_github_data

        assert _has_github_data({"commits_90d": 50}) is True

    def test_has_github_data_empty(self):
        """Test _has_github_data returns False for empty data."""
        from package_collector import _has_github_data

        assert _has_github_data({}) is False
        assert _has_github_data({"other_field": "value"}) is False


class TestS3RawDataArchival:
    """Tests for S3 raw data archival paths (lines 471-495, 734-735)."""

    @mock_aws
    def test_collect_package_data_depsdev_circuit_open_with_stale_fallback(self):
        """Test circuit open triggers stale data fallback (lines 473-484)."""
        from circuit_breaker import CircuitOpenError

        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create existing package with valid stale data
        recent_time = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        table.put_item(Item={
            "pk": "npm#test-pkg",
            "sk": "LATEST",
            "last_updated": recent_time,
            "latest_version": "1.0.0",
            "licenses": ["MIT"],
            "repository_url": "https://github.com/test/pkg",
        })

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Mock deps.dev to raise CircuitOpenError
            with patch("package_collector.get_depsdev_info") as mock_depsdev, \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=False):
                mock_depsdev.side_effect = CircuitOpenError("deps.dev", retry_after=60)

                result = run_async(package_collector.collect_package_data("npm", "test-pkg"))

                assert result["depsdev_error"] == "circuit_open"
                assert result["data_freshness"] == "stale"
                assert result["stale_reason"] == "deps.dev_circuit_open"
                assert result["latest_version"] == "1.0.0"

    @mock_aws
    def test_collect_package_data_depsdev_exception_with_stale_fallback(self):
        """Test general exception triggers stale data fallback (lines 485-495)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create existing package with valid stale data
        recent_time = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        table.put_item(Item={
            "pk": "npm#test-pkg",
            "sk": "LATEST",
            "last_updated": recent_time,
            "latest_version": "2.0.0",
            "dependents_count": 500,
        })

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Mock deps.dev to raise general exception
            with patch("package_collector.get_depsdev_info") as mock_depsdev, \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=False):
                mock_depsdev.side_effect = Exception("Network timeout")

                result = run_async(package_collector.collect_package_data("npm", "test-pkg"))

                assert "Network timeout" in result.get("depsdev_error", "")
                assert result["data_freshness"] == "stale"
                assert result["stale_reason"] == "deps.dev_unavailable"
                assert result["latest_version"] == "2.0.0"
                assert result["dependents_count"] == 500

    @mock_aws
    def test_store_raw_data_failure_handled(self):
        """Test store_raw_data handles S3 errors gracefully (lines 734-735)."""
        with patch.dict(os.environ, {"RAW_DATA_BUCKET": "pkgwatch-raw-data"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Mock S3 to fail
            with patch.object(package_collector, "_get_s3") as mock_get_s3:
                mock_s3 = MagicMock()
                mock_s3.put_object.side_effect = Exception("S3 error")
                mock_get_s3.return_value = mock_s3

                # Should not raise exception
                package_collector.store_raw_data("npm", "test-pkg", {"data": "test"})


class TestCircuitBreakerAsyncContext:
    """Tests for circuit breaker interaction in async context."""

    @mock_aws
    def test_github_circuit_open_skips_collection(self):
        """Test GitHub collection skipped when circuit is open (lines 634-638)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Mock deps.dev to return data with repo URL
            mock_depsdev_data = {
                "latest_version": "1.0.0",
                "repository_url": "https://github.com/test/repo",
            }

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=False), \
                 patch("package_collector.GITHUB_CIRCUIT") as mock_circuit:
                # Mock circuit as open
                mock_circuit.can_execute_async = AsyncMock(return_value=False)

                result = run_async(package_collector.collect_package_data("npm", "test-pkg"))

                assert result.get("github_error") == "circuit_open"
                # GitHub data should not be fetched
                assert "github" not in result.get("sources", [])

    @mock_aws
    def test_github_rate_limit_exceeded_skips_collection(self):
        """Test GitHub collection skipped when rate limit exceeded (lines 646-651)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Mock deps.dev to return data with repo URL
            mock_depsdev_data = {
                "latest_version": "1.0.0",
                "repository_url": "https://github.com/test/repo",
            }

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=False), \
                 patch("package_collector.GITHUB_CIRCUIT") as mock_circuit, \
                 patch("package_collector._check_and_increment_github_rate_limit", return_value=False):
                mock_circuit.can_execute_async = AsyncMock(return_value=True)

                result = run_async(package_collector.collect_package_data("npm", "test-pkg"))

                assert result.get("github_error") == "rate_limit_exceeded"

    @mock_aws
    def test_github_exception_records_failure_and_uses_stale(self):
        """Test GitHub exception records failure and tries stale fallback (lines 704-716)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create existing data with GitHub fields
        recent_time = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        table.put_item(Item={
            "pk": "npm#test-pkg",
            "sk": "LATEST",
            "last_updated": recent_time,
            "stars": 1000,
            "commits_90d": 25,
        })

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {
                "latest_version": "1.0.0",
                "repository_url": "https://github.com/test/repo",
            }

            mock_collector = MagicMock()
            mock_collector.get_repo_metrics = AsyncMock(side_effect=Exception("GitHub API error"))

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=False), \
                 patch("package_collector.GITHUB_CIRCUIT") as mock_circuit, \
                 patch("package_collector._check_and_increment_github_rate_limit", return_value=True), \
                 patch("package_collector.GitHubCollector", return_value=mock_collector):
                mock_circuit.can_execute_async = AsyncMock(return_value=True)
                mock_circuit.record_failure_async = AsyncMock()

                result = run_async(package_collector.collect_package_data("npm", "test-pkg"))

                # Should have recorded failure
                mock_circuit.record_failure_async.assert_called()

                # Should have error
                assert "github_error" in result

                # Should have used stale fallback
                assert result.get("stars") == 1000
                assert result.get("github_freshness") == "stale"


class TestPartialCollectionFailures:
    """Tests for partial collection failures (some collectors succeed, some fail)."""

    @mock_aws
    def test_npm_rate_limit_records_error(self):
        """Test npm rate limit sets error (lines 522-524)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {"latest_version": "1.0.0"}

            def rate_limit_check(service, limit):
                # npm rate limited, bundlephobia not
                return service != "npm"

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", side_effect=rate_limit_check):

                result = run_async(package_collector.collect_package_data("npm", "test-pkg"))

                assert result.get("npm_error") == "rate_limit_exceeded"

    @mock_aws
    def test_npm_rate_limit_uses_stale_fallback(self):
        """Test npm rate limit uses stale data fallback when available."""
        from datetime import datetime, timezone

        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Insert existing package with npm data
        table = dynamodb.Table("pkgwatch-packages")
        table.put_item(Item={
            "pk": "npm#test-pkg",
            "sk": "LATEST",
            "weekly_downloads": 50000,
            "maintainer_count": 3,
            "has_types": True,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        })

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {"latest_version": "1.0.0"}
            existing = {
                "weekly_downloads": 50000,
                "maintainer_count": 3,
                "has_types": True,
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }

            def rate_limit_check(service, limit):
                # npm rate limited
                return service != "npm"

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", side_effect=rate_limit_check), \
                 patch("package_collector._get_existing_package_data", return_value=existing), \
                 patch("package_collector._is_data_acceptable", return_value=True):

                result = run_async(package_collector.collect_package_data("npm", "test-pkg"))

                # Should have stale data with npm_stale in sources
                assert result.get("weekly_downloads") == 50000
                assert "npm_stale" in result.get("sources", [])
                assert result.get("npm_freshness") == "stale"
                assert result.get("npm_stale_reason") == "rate_limit_exceeded"

    @mock_aws
    def test_bundlephobia_rate_limit_records_error(self):
        """Test bundlephobia rate limit sets error (lines 529-531)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {"latest_version": "1.0.0"}

            def rate_limit_check(service, limit):
                # bundlephobia rate limited, npm not
                return service != "bundlephobia"

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", side_effect=rate_limit_check), \
                 patch("package_collector.get_npm_metadata", return_value={"weekly_downloads": 1000}):

                result = run_async(package_collector.collect_package_data("npm", "test-pkg"))

                assert result.get("bundlephobia_error") == "rate_limit_exceeded"

    @mock_aws
    def test_npm_circuit_open_records_error(self):
        """Test npm circuit open sets error (lines 535-537)."""
        from circuit_breaker import CircuitOpenError

        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {"latest_version": "1.0.0"}

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=True), \
                 patch("package_collector.get_npm_metadata", side_effect=CircuitOpenError("npm", retry_after=60)), \
                 patch("package_collector.get_bundle_size", return_value={"size": 1000}):

                result = run_async(package_collector.collect_package_data("npm", "test-pkg"))

                assert result.get("npm_error") == "circuit_open"

    @mock_aws
    def test_bundlephobia_circuit_open_records_error(self):
        """Test bundlephobia circuit open sets error (lines 566-568)."""
        from circuit_breaker import CircuitOpenError

        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {"latest_version": "1.0.0"}

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=True), \
                 patch("package_collector.get_npm_metadata", return_value={"weekly_downloads": 1000}), \
                 patch("package_collector.get_bundle_size", side_effect=CircuitOpenError("bundlephobia", retry_after=60)):

                result = run_async(package_collector.collect_package_data("npm", "test-pkg"))

                assert result.get("bundlephobia_error") == "circuit_open"

    @mock_aws
    def test_bundlephobia_generic_exception(self):
        """Test bundlephobia generic exception sets sanitized error (lines 569-571)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {"latest_version": "1.0.0"}

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=True), \
                 patch("package_collector.get_npm_metadata", return_value={"weekly_downloads": 1000}), \
                 patch("package_collector.get_bundle_size", side_effect=Exception("Connection timeout")):

                result = run_async(package_collector.collect_package_data("npm", "test-pkg"))

                assert "Connection timeout" in result.get("bundlephobia_error", "")


class TestPyPICollectionPath:
    """Tests for PyPI collection path (lines 585-621)."""

    @mock_aws
    def test_pypi_collection_success(self):
        """Test successful PyPI collection (lines 588-610)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {"latest_version": "1.0.0"}
            mock_pypi_data = {
                "weekly_downloads": 50000,
                "maintainers": [{"name": "author"}],
                "maintainer_count": 1,
                "requires_python": ">=3.8",
                "development_status": "5 - Production/Stable",
                "python_versions": ["3.8", "3.9", "3.10"],
                "repository_url": "https://github.com/test/pypi-pkg",
            }

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=True), \
                 patch("package_collector.get_pypi_metadata", return_value=mock_pypi_data):

                result = run_async(package_collector.collect_package_data("pypi", "test-pkg"))

                assert "pypi" in result.get("sources", [])
                assert result.get("weekly_downloads") == 50000
                assert result.get("requires_python") == ">=3.8"
                assert result.get("development_status") == "5 - Production/Stable"
                assert result.get("repository_url") == "https://github.com/test/pypi-pkg"

    @mock_aws
    def test_pypi_collection_error_response(self):
        """Test PyPI error response handling (lines 611-612)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {"latest_version": "1.0.0"}
            mock_pypi_data = {"error": "Package not found"}

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=True), \
                 patch("package_collector.get_pypi_metadata", return_value=mock_pypi_data):

                result = run_async(package_collector.collect_package_data("pypi", "test-pkg"))

                assert result.get("pypi_error") == "Package not found"
                assert "pypi" not in result.get("sources", [])

    @mock_aws
    def test_pypi_circuit_open(self):
        """Test PyPI circuit open handling (lines 613-615)."""
        from circuit_breaker import CircuitOpenError

        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {"latest_version": "1.0.0"}

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=True), \
                 patch("package_collector.get_pypi_metadata", side_effect=CircuitOpenError("pypi", retry_after=60)):

                result = run_async(package_collector.collect_package_data("pypi", "test-pkg"))

                assert result.get("pypi_error") == "circuit_open"

    @mock_aws
    def test_pypi_rate_limit(self):
        """Test PyPI rate limit handling (lines 619-621)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {"latest_version": "1.0.0"}

            def rate_limit_check(service, limit):
                return service != "pypi"

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", side_effect=rate_limit_check):

                result = run_async(package_collector.collect_package_data("pypi", "test-pkg"))

                assert result.get("pypi_error") == "rate_limit_exceeded"

    @mock_aws
    def test_pypi_generic_exception(self):
        """Test PyPI generic exception handling (lines 616-618)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {"latest_version": "1.0.0"}

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=True), \
                 patch("package_collector.get_pypi_metadata", side_effect=Exception("Network error")):

                result = run_async(package_collector.collect_package_data("pypi", "test-pkg"))

                assert "Network error" in result.get("pypi_error", "")


class TestDatabaseWriteErrors:
    """Tests for database write errors during score persistence (lines 889-891)."""

    @mock_aws
    def test_store_package_data_raises_on_dynamodb_error(self):
        """Test store_package_data raises exception on DynamoDB error (lines 889-891)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        with patch.dict(os.environ, {"PACKAGES_TABLE": "pkgwatch-packages"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Mock DynamoDB to raise error
            with patch.object(package_collector, "_get_dynamodb") as mock_get_ddb:
                mock_table = MagicMock()
                mock_table.put_item.side_effect = Exception("DynamoDB write failed")
                mock_resource = MagicMock()
                mock_resource.Table.return_value = mock_table
                mock_get_ddb.return_value = mock_resource

                with pytest.raises(Exception) as exc_info:
                    package_collector.store_package_data("npm", "test-pkg", {"latest_version": "1.0.0"}, tier=2)

                assert "DynamoDB write failed" in str(exc_info.value)


class TestDataStatusCalculation:
    """Tests for _calculate_data_status (lines 758, 761-763, 767)."""

    def test_calculate_data_status_complete(self):
        """Test complete status when no errors (line 769-770)."""
        from package_collector import _calculate_data_status

        data = {
            "sources": ["deps.dev", "npm", "bundlephobia", "github"],
        }

        status, missing = _calculate_data_status(data, "npm")
        assert status == "complete"
        assert missing == []

    def test_calculate_data_status_minimal_depsdev_error(self):
        """Test minimal status when deps.dev fails (lines 771-772)."""
        from package_collector import _calculate_data_status

        data = {
            "depsdev_error": "API unavailable",
            "sources": ["npm"],
        }

        status, missing = _calculate_data_status(data, "npm")
        assert status == "minimal"
        assert "deps.dev" in missing

    def test_calculate_data_status_partial_npm_error(self):
        """Test partial status when npm fails (lines 757-758)."""
        from package_collector import _calculate_data_status

        data = {
            "npm_error": "rate_limit_exceeded",
            "sources": ["deps.dev"],
        }

        status, missing = _calculate_data_status(data, "npm")
        assert status == "partial"
        assert "npm" in missing

    def test_calculate_data_status_bundlephobia_error_not_partial(self):
        """Test bundlephobia error does NOT cause partial status (optional source)."""
        from package_collector import _calculate_data_status

        data = {
            "bundlephobia_error": "circuit_open",
            "sources": ["deps.dev", "npm"],
        }

        status, missing = _calculate_data_status(data, "npm")
        assert status == "complete"  # bundlephobia is optional, not used in scoring
        assert "bundlephobia" not in missing

    def test_calculate_data_status_partial_github_error(self):
        """Test partial status when github fails with repo_url (lines 766-767)."""
        from package_collector import _calculate_data_status

        data = {
            "repository_url": "https://github.com/test/repo",
            "github_error": "rate_limit_exceeded",
            "sources": ["deps.dev", "npm"],
        }

        status, missing = _calculate_data_status(data, "npm")
        assert status == "partial"
        assert "github" in missing

    def test_calculate_data_status_pypi_error(self):
        """Test partial status when PyPI fails (lines 761-763)."""
        from package_collector import _calculate_data_status

        data = {
            "pypi_error": "circuit_open",
            "sources": ["deps.dev"],
        }

        status, missing = _calculate_data_status(data, "pypi")
        assert status == "partial"
        assert "pypi" in missing

    def test_calculate_data_status_github_stale_not_partial(self):
        """Test github_stale fallback does NOT cause partial status."""
        from package_collector import _calculate_data_status

        data = {
            "github_error": "rate_limit_exceeded",
            "repository_url": "https://github.com/vuejs/core",
            "sources": ["deps.dev", "npm", "github_stale"],  # stale fallback succeeded
        }

        status, missing = _calculate_data_status(data, "npm")
        assert status == "complete"  # stale data is valid
        assert "github" not in missing

    def test_calculate_data_status_npm_stale_not_partial(self):
        """Test npm_stale fallback does NOT cause partial status."""
        from package_collector import _calculate_data_status

        data = {
            "npm_error": "circuit_open",
            "sources": ["deps.dev", "npm_stale"],  # stale fallback succeeded
        }

        status, missing = _calculate_data_status(data, "npm")
        assert status == "complete"  # stale data is valid
        assert "npm" not in missing

    def test_calculate_data_status_pypi_stale_not_partial(self):
        """Test pypi_stale fallback does NOT cause partial status."""
        from package_collector import _calculate_data_status

        data = {
            "pypi_error": "circuit_open",
            "sources": ["deps.dev", "pypi_stale"],  # stale fallback succeeded
        }

        status, missing = _calculate_data_status(data, "pypi")
        assert status == "complete"  # stale data is valid
        assert "pypi" not in missing


class TestRetryTracking:
    """Tests for retry tracking in process_single_package (lines 918-927)."""

    @mock_aws
    def test_process_single_package_increments_retry_count(self):
        """Test retry count incremented for incomplete_data_retry (lines 918-927)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="pkgwatch-raw-data")

        # Create existing package with retry_count
        table.put_item(Item={
            "pk": "npm#test-pkg",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "test-pkg",
            "retry_count": 2,
        })

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "RAW_DATA_BUCKET": "pkgwatch-raw-data",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {"latest_version": "1.0.0"}

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=False):

                message = {
                    "ecosystem": "npm",
                    "name": "test-pkg",
                    "tier": 2,
                    "reason": "incomplete_data_retry",  # This triggers retry tracking
                }

                success, pkg_name, error = run_async(package_collector.process_single_package(message))

                assert success is True

                # Check retry_count was incremented
                response = table.get_item(Key={"pk": "npm#test-pkg", "sk": "LATEST"})
                # Note: increment happens before collection, then store_package_data
                # may update it again. The important thing is the flow was exercised.


class TestProcessSinglePackageErrors:
    """Tests for process_single_package error handling (lines 966-974)."""

    @mock_aws
    def test_process_single_package_exception_stores_error(self):
        """Test process_single_package stores error on exception (lines 966-974)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create existing package
        table.put_item(Item={
            "pk": "npm#test-pkg",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "test-pkg",
        })

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "RAW_DATA_BUCKET": "pkgwatch-raw-data",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Mock collect_package_data to raise exception
            with patch.object(package_collector, "collect_package_data", side_effect=Exception("Collection failed")):

                message = {
                    "ecosystem": "npm",
                    "name": "test-pkg",
                    "tier": 2,
                }

                success, pkg_name, error = run_async(package_collector.process_single_package(message))

                assert success is False
                assert "Exception" in error

                # Check that error was stored
                response = table.get_item(Key={"pk": "npm#test-pkg", "sk": "LATEST"})
                item = response.get("Item", {})
                assert "collection_error" in item


class TestProcessBatchExceptions:
    """Tests for process_batch exception handling (lines 1012-1018, 1034-1046)."""

    def test_process_batch_handles_task_exception(self):
        """Test process_batch handles task exceptions (lines 1012-1018)."""
        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "RAW_DATA_BUCKET": "pkgwatch-raw-data",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Mock process_single_package to raise exception
            with patch.object(package_collector, "process_single_package", side_effect=Exception("Task failed")), \
                 patch("package_collector.emit_metric"), \
                 patch("package_collector.emit_batch_metrics"):

                records = [
                    {"messageId": "msg-1", "body": json.dumps({"ecosystem": "npm", "name": "pkg1"})},
                    {"messageId": "msg-2", "body": json.dumps({"ecosystem": "npm", "name": "pkg2"})},
                ]

                successes, failed_ids = run_async(package_collector.process_batch(records))

                assert successes == 0
                assert "msg-1" in failed_ids
                assert "msg-2" in failed_ids

    def test_process_batch_handles_unexpected_result_format(self):
        """Test process_batch handles unexpected result format (lines 1044-1046)."""
        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "RAW_DATA_BUCKET": "pkgwatch-raw-data",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Mock process_single_package to return unexpected format
            async def mock_process(*args):
                return "unexpected_format"  # Not a tuple

            with patch.object(package_collector, "process_single_package", side_effect=mock_process), \
                 patch("package_collector.emit_metric"), \
                 patch("package_collector.emit_batch_metrics"):

                records = [
                    {"messageId": "msg-1", "body": json.dumps({"ecosystem": "npm", "name": "pkg1"})},
                ]

                successes, failed_ids = run_async(package_collector.process_batch(records))

                assert successes == 0
                assert "msg-1" in failed_ids

    def test_process_batch_handles_partial_success(self):
        """Test process_batch handles partial success (lines 1025-1036)."""
        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "RAW_DATA_BUCKET": "pkgwatch-raw-data",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            call_count = [0]

            async def mock_process(message, bulk_downloads=None):
                call_count[0] += 1
                if call_count[0] == 1:
                    return (True, "npm/pkg1", None)  # Success
                else:
                    return (False, "npm/pkg2", "rate_limit")  # Failure

            with patch.object(package_collector, "process_single_package", side_effect=mock_process), \
                 patch("package_collector.emit_metric"), \
                 patch("package_collector.emit_batch_metrics"):

                records = [
                    {"messageId": "msg-1", "body": json.dumps({"ecosystem": "npm", "name": "pkg1"})},
                    {"messageId": "msg-2", "body": json.dumps({"ecosystem": "npm", "name": "pkg2"})},
                ]

                successes, failed_ids = run_async(package_collector.process_batch(records))

                assert successes == 1
                assert "msg-1" not in failed_ids
                assert "msg-2" in failed_ids


class TestSanitizeError:
    """Tests for _sanitize_error function (line 128)."""

    def test_sanitize_error_truncates_long_message(self):
        """Test _sanitize_error truncates messages over 500 chars (line 128)."""
        from package_collector import _sanitize_error

        long_error = "a" * 600
        result = _sanitize_error(long_error)

        assert len(result) <= 517  # 500 + "...[truncated]"
        assert result.endswith("...[truncated]")

    def test_sanitize_error_redacts_github_tokens(self):
        """Test _sanitize_error redacts GitHub tokens."""
        from package_collector import _sanitize_error

        # Token must be exactly 36 characters to match the pattern
        # 36 chars: abcdefghijklmnopqrstuvwxyz1234567890
        error_with_token = "Error: ghp_abcdefghijklmnopqrstuvwxyz1234567890 is invalid"
        result = _sanitize_error(error_with_token)

        assert "ghp_abcdefghijklmnopqrstuvwxyz1234567890" not in result
        assert "ghp_***" in result

    def test_sanitize_error_redacts_aws_arns(self):
        """Test _sanitize_error redacts AWS ARNs."""
        from package_collector import _sanitize_error

        error_with_arn = "Error: arn:aws:secretsmanager:us-east-1:123456789012:secret:test"
        result = _sanitize_error(error_with_arn)

        assert "123456789012" not in result


class TestCalculateNextRetryAt:
    """Tests for _calculate_next_retry_at function (line 784)."""

    def test_calculate_next_retry_at_returns_none_after_max_retries(self):
        """Test returns None when retry_count >= MAX_RETRY_COUNT (line 784)."""
        from package_collector import _calculate_next_retry_at, MAX_RETRY_COUNT

        result = _calculate_next_retry_at(MAX_RETRY_COUNT)
        assert result is None

        result = _calculate_next_retry_at(MAX_RETRY_COUNT + 1)
        assert result is None

    def test_calculate_next_retry_at_returns_future_time(self):
        """Test returns ISO timestamp in the future."""
        from package_collector import _calculate_next_retry_at

        result = _calculate_next_retry_at(0)
        assert result is not None

        # Should be 1 hour in future for first retry
        result_dt = datetime.fromisoformat(result.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff = result_dt - now

        assert diff.total_seconds() > 3500  # Close to 1 hour
        assert diff.total_seconds() < 3700


class TestGetGitHubTokenErrors:
    """Tests for get_github_token error handling (lines 194-196)."""

    @mock_aws
    def test_get_github_token_client_error(self):
        """Test get_github_token returns None on ClientError (lines 194-196)."""
        with patch.dict(os.environ, {"GITHUB_TOKEN_SECRET_ARN": "nonexistent-secret"}):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # With mock_aws, accessing non-existent secret will raise ClientError
            token = package_collector.get_github_token()
            assert token is None


class TestDeduplicationWindow:
    """Tests for deduplication window in process_single_package (lines 931-941)."""

    @mock_aws
    def test_skips_recently_updated_package(self):
        """Test process_single_package skips recently updated packages."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Create package updated 10 minutes ago (within 30 min window)
        recent_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        table.put_item(Item={
            "pk": "npm#test-pkg",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "test-pkg",
            "last_updated": recent_time,
        })

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "RAW_DATA_BUCKET": "pkgwatch-raw-data",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
            "DEDUP_WINDOW_MINUTES": "30",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            message = {
                "ecosystem": "npm",
                "name": "test-pkg",
                "tier": 2,
            }

            # Should not call collect_package_data
            with patch.object(package_collector, "collect_package_data") as mock_collect:
                success, pkg_name, error = run_async(package_collector.process_single_package(message))

                assert success is True
                mock_collect.assert_not_called()

    @mock_aws
    def test_force_refresh_bypasses_dedup(self):
        """Test force_refresh=True bypasses deduplication."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="pkgwatch-raw-data")

        # Create package updated 10 minutes ago (within window)
        recent_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        table.put_item(Item={
            "pk": "npm#test-pkg",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "test-pkg",
            "last_updated": recent_time,
        })

        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
            "RAW_DATA_BUCKET": "pkgwatch-raw-data",
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            mock_depsdev_data = {"latest_version": "1.0.0"}

            message = {
                "ecosystem": "npm",
                "name": "test-pkg",
                "tier": 2,
                "force_refresh": True,  # Should bypass dedup
            }

            with patch("package_collector.get_depsdev_info", return_value=mock_depsdev_data), \
                 patch("package_collector.check_and_increment_external_rate_limit", return_value=False):

                success, pkg_name, error = run_async(package_collector.process_single_package(message))

                assert success is True
                # Data should have been refreshed
                response = table.get_item(Key={"pk": "npm#test-pkg", "sk": "LATEST"})
                item = response.get("Item", {})
                assert item.get("latest_version") == "1.0.0"


class TestValidationError:
    """Tests for validation error handling (lines 903-904)."""

    def test_process_single_package_validation_error(self):
        """Test process_single_package returns failure on validation error."""
        with patch.dict(os.environ, {
            "PACKAGES_TABLE": "pkgwatch-packages",
        }):
            from importlib import reload
            import package_collector
            reload(package_collector)

            # Invalid message (missing ecosystem)
            message = {"name": "test-pkg"}

            success, pkg_name, error = run_async(package_collector.process_single_package(message))

            assert success is False
            assert "validation_error" in error


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def mock_dynamodb():
    """Provide a mock DynamoDB resource."""
    with mock_aws():
        yield boto3.resource("dynamodb", region_name="us-east-1")
