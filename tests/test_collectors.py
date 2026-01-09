"""
Comprehensive tests for DepHealth data collectors.

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
            if "packages/lodash:dependents" in url:
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
        """Test 429 rate limit handling."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("some-pkg"))

            assert result["error"] == "rate_limited"

    def test_get_bundle_size_timeout(self):
        """Test 504 timeout handling (large packages)."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(504)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("huge-pkg"))

            assert result["error"] == "timeout"


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
                "PACKAGES_TABLE": "dephealth-packages",
                "RAW_DATA_BUCKET": "dephealth-raw-data",
                "GITHUB_TOKEN_SECRET_ARN": "",
                "API_KEYS_TABLE": "dephealth-api-keys",
            },
        ):
            with patch.object(httpx.AsyncClient, "__init__", patched_init), \
                 patch("package_collector._check_and_increment_github_rate_limit", return_value=True):
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
                "PACKAGES_TABLE": "dephealth-packages",
                "RAW_DATA_BUCKET": "dephealth-raw-data",
                "GITHUB_TOKEN_SECRET_ARN": "",
            },
        ):
            with patch.object(httpx.AsyncClient, "__init__", patched_init):
                from importlib import reload
                import package_collector
                reload(package_collector)

                result = run_async(package_collector.collect_package_data("npm", "test-pkg"))

                # Should still have deps.dev data
                assert "deps.dev" in result["sources"]
                assert result["latest_version"] == "1.0.0"


class TestStorePackageData:
    """Tests for store_package_data function."""

    @mock_aws
    def test_store_package_data_success(self):
        """Test storing package data in DynamoDB."""
        # Set up mock DynamoDB
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="dephealth-packages",
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

        with patch.dict(os.environ, {"PACKAGES_TABLE": "dephealth-packages"}):
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
            table = dynamodb.Table("dephealth-packages")
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
            TableName="dephealth-packages",
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

        with patch.dict(os.environ, {"PACKAGES_TABLE": "dephealth-packages"}):
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

            table = dynamodb.Table("dephealth-packages")
            response = table.get_item(Key={"pk": "npm#test-pkg", "sk": "LATEST"})

            item = response["Item"]
            assert "openssf_score" not in item
            assert "days_since_last_commit" not in item


class TestHandler:
    """Tests for the Lambda handler function."""

    @mock_aws
    def test_handler_single_message(self):
        """Test handler processing a single SQS message."""
        # Set up AWS mocks
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="dephealth-packages",
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
        s3.create_bucket(Bucket="dephealth-raw-data")

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
                "PACKAGES_TABLE": "dephealth-packages",
                "RAW_DATA_BUCKET": "dephealth-raw-data",
                "GITHUB_TOKEN_SECRET_ARN": "",
            },
        ):
            with patch.object(httpx.AsyncClient, "__init__", patched_init):
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
                "PACKAGES_TABLE": "dephealth-packages",
                "RAW_DATA_BUCKET": "dephealth-raw-data",
                "GITHUB_TOKEN_SECRET_ARN": "",
            },
        ):
            from importlib import reload

            import package_collector

            reload(package_collector)

            event = {"Records": [{"body": "not valid json"}]}

            result = package_collector.handler(event, None)

            # Should not crash, just report 0 processed
            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["processed"] == 0

    def test_handler_empty_records(self):
        """Test handler with no records."""
        with patch.dict(
            os.environ,
            {
                "PACKAGES_TABLE": "dephealth-packages",
                "RAW_DATA_BUCKET": "dephealth-raw-data",
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

        message = {"ecosystem": "pypi", "name": "requests"}
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
        """Invalid package name format should fail."""
        from package_collector import validate_message

        message = {"ecosystem": "npm", "name": "INVALID-NAME"}  # No uppercase allowed
        is_valid, error = validate_message(message)

        assert is_valid is False
        assert "Invalid package name format" in error

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
            TableName="dephealth-api-keys",
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
                "API_KEYS_TABLE": "dephealth-api-keys",
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
            TableName="dephealth-api-keys",
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
                "API_KEYS_TABLE": "dephealth-api-keys",
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

    def test_classify_permanent_error_invalid_package(self):
        """'invalid package' errors should be classified as permanent."""
        from dlq_processor import classify_error

        error_msg = "Invalid package name specified"
        result = classify_error(error_msg)

        assert result == "permanent"

    def test_classify_permanent_error_forbidden(self):
        """'forbidden' errors should be classified as permanent."""
        from dlq_processor import classify_error

        error_msg = "403 Forbidden: Access denied"
        result = classify_error(error_msg)

        assert result == "permanent"

    def test_classify_permanent_error_validation(self):
        """Validation errors should be classified as permanent."""
        from dlq_processor import classify_error

        error_msg = "validation_error: Invalid package name format"
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

        with patch("shared.metrics.cloudwatch") as mock_cw:
            emit_metric("TestMetric", value=5.0, dimensions={"Test": "Value"})

            mock_cw.put_metric_data.assert_called_once()
            call_args = mock_cw.put_metric_data.call_args

            assert call_args.kwargs["Namespace"] == "DepHealth"
            assert call_args.kwargs["MetricData"][0]["MetricName"] == "TestMetric"
            assert call_args.kwargs["MetricData"][0]["Value"] == 5.0

    def test_emit_metric_failure_doesnt_crash(self):
        """Test that metric emission failures don't crash Lambda."""
        from shared.metrics import emit_metric

        with patch("shared.metrics.cloudwatch") as mock_cw:
            mock_cw.put_metric_data.side_effect = Exception("CloudWatch error")

            # Should not raise exception
            emit_metric("TestMetric", value=1.0)

    def test_emit_batch_metrics_success(self):
        """Test successful batch metrics emission."""
        from shared.metrics import emit_batch_metrics

        with patch("shared.metrics.cloudwatch") as mock_cw:
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

        with patch("shared.metrics.cloudwatch") as mock_cw:
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

        with patch("shared.metrics.cloudwatch") as mock_cw:
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
            TableName="dephealth-api-keys",
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

        with patch.dict(os.environ, {"API_KEYS_TABLE": "dephealth-api-keys"}):
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
            TableName="dephealth-api-keys",
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

        with patch.dict(os.environ, {"API_KEYS_TABLE": "dephealth-api-keys"}):
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
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def mock_dynamodb():
    """Provide a mock DynamoDB resource."""
    with mock_aws():
        yield boto3.resource("dynamodb", region_name="us-east-1")
