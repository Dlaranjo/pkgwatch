"""
Tests for deps.dev collector.

Tests cover:
- Package name encoding (scoped packages)
- Package info fetching
- Vulnerability/advisory data parsing
- OpenSSF scorecard extraction
- Dependents count fetching
- Dependencies fetching (for graph expansion)
- Error handling (404, rate limits, network errors)
- Retry logic with backoff

Run with: PYTHONPATH=functions:. pytest tests/test_depsdev_collector.py -v
"""

import asyncio
import os
import sys
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
# ENCODING TESTS
# =============================================================================


class TestEncodePackageName:
    """Tests for encode_package_name function."""

    def test_encode_simple_package(self):
        """Simple package names should be encoded."""
        from depsdev_collector import encode_package_name

        # Simple names don't have special chars, should stay same
        assert encode_package_name("lodash") == "lodash"

    def test_encode_scoped_package(self):
        """Scoped npm packages should be URL-encoded."""
        from depsdev_collector import encode_package_name

        # @ and / need to be encoded
        assert encode_package_name("@babel/core") == "%40babel%2Fcore"

    def test_encode_package_with_hyphen(self):
        """Package names with hyphens should be encoded properly."""
        from depsdev_collector import encode_package_name

        assert encode_package_name("react-dom") == "react-dom"

    def test_encode_scoped_package_complex(self):
        """Complex scoped packages should be fully encoded."""
        from depsdev_collector import encode_package_name

        assert encode_package_name("@types/node") == "%40types%2Fnode"
        assert encode_package_name("@angular/core") == "%40angular%2Fcore"


class TestEncodeRepoUrl:
    """Tests for encode_repo_url function."""

    def test_encode_github_url(self):
        """GitHub URLs should be URL-encoded."""
        from depsdev_collector import encode_repo_url

        result = encode_repo_url("github.com/lodash/lodash")
        assert result == "github.com%2Flodash%2Flodash"

    def test_encode_gitlab_url(self):
        """GitLab URLs should be URL-encoded."""
        from depsdev_collector import encode_repo_url

        result = encode_repo_url("gitlab.com/user/repo")
        assert result == "gitlab.com%2Fuser%2Frepo"


# =============================================================================
# GET PACKAGE INFO TESTS
# =============================================================================


class TestGetPackageInfo:
    """Tests for get_package_info function."""

    def _create_package_response(self, name="lodash"):
        """Create a mock deps.dev package API response."""
        return {
            "packageKey": {"system": "NPM", "name": name},
            "versions": [
                {
                    "versionKey": {"system": "NPM", "name": name, "version": "4.17.20"},
                    "isDefault": False,
                },
                {
                    "versionKey": {"system": "NPM", "name": name, "version": "4.17.21"},
                    "isDefault": True,
                },
            ],
        }

    def _create_version_response(self, name="lodash", version="4.17.21"):
        """Create a mock deps.dev version API response."""
        return {
            "versionKey": {"system": "NPM", "name": name, "version": version},
            "publishedAt": "2024-01-15T00:00:00Z",
            "licenses": ["MIT"],
            "relations": {
                "dependencies": [
                    {"package": {"name": "dep1"}},
                    {"package": {"name": "dep2"}},
                ]
            },
            "advisories": [],
            "links": [
                {"label": "SOURCE_REPO", "url": "https://github.com/lodash/lodash"},
            ],
        }

    def _create_project_response(self):
        """Create a mock deps.dev project API response."""
        return {
            "starsCount": 58000,
            "forksCount": 7000,
            "scorecardV2": {
                "score": 7.5,
                "check": [
                    {"name": "Code-Review", "score": 8},
                    {"name": "Maintained", "score": 10},
                ],
            },
        }

    def _create_dependents_response(self, count=5000):
        """Create a mock deps.dev dependents API response."""
        return {
            "dependentCount": count,
        }

    def test_successful_package_info_fetch(self):
        """Test successful package info fetch with all fields."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/packages/lodash/versions/" in url and ":dependents" in url:
                return httpx.Response(200, json=self._create_dependents_response())
            elif "/packages/lodash/versions/" in url:
                return httpx.Response(200, json=self._create_version_response())
            elif "/packages/lodash" in url:
                return httpx.Response(200, json=self._create_package_response())
            elif "/projects/" in url:
                return httpx.Response(200, json=self._create_project_response())
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
            assert result["repository_url"] == "https://github.com/lodash/lodash"
            assert result["openssf_score"] == 7.5
            assert result["stars"] == 58000
            assert result["dependents_count"] == 5000
            assert result["source"] == "deps.dev"

    def test_package_not_found(self):
        """Test 404 handling for non-existent package."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("nonexistent-package-xyz"))
            assert result is None

    def test_scoped_package_fetch(self):
        """Test fetching scoped npm package."""
        from depsdev_collector import get_package_info

        scoped_pkg = self._create_package_response(name="@babel/core")

        requested_urls = []

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            requested_urls.append(url)
            if "%40babel%2Fcore" in url:
                if ":dependents" in url:
                    return httpx.Response(200, json=self._create_dependents_response())
                elif "/versions/" in url:
                    return httpx.Response(200, json=self._create_version_response(name="@babel/core", version="7.24.0"))
                else:
                    scoped_pkg["versions"][1]["versionKey"]["version"] = "7.24.0"
                    return httpx.Response(200, json=scoped_pkg)
            elif "/projects/" in url:
                return httpx.Response(200, json=self._create_project_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("@babel/core"))

            assert result is not None
            # Verify URL encoding was applied
            assert any("%40babel%2Fcore" in url for url in requested_urls)

    def test_pypi_ecosystem(self):
        """Test fetching PyPI package."""
        from depsdev_collector import get_package_info

        pypi_pkg = self._create_package_response(name="requests")
        pypi_pkg["packageKey"]["system"] = "PYPI"

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/systems/pypi/" in url.lower():
                if ":dependents" in url:
                    return httpx.Response(200, json=self._create_dependents_response())
                elif "/versions/" in url:
                    return httpx.Response(200, json=self._create_version_response(name="requests", version="2.31.0"))
                else:
                    return httpx.Response(200, json=pypi_pkg)
            elif "/projects/" in url:
                return httpx.Response(200, json=self._create_project_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("requests", ecosystem="pypi"))

            assert result is not None
            assert result["ecosystem"] == "pypi"

    def test_version_fallback_when_no_default(self):
        """Test version selection when no isDefault version."""
        from depsdev_collector import get_package_info

        no_default_pkg = self._create_package_response()
        # No version marked as default
        for v in no_default_pkg["versions"]:
            v["isDefault"] = False

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if ":dependents" in url:
                return httpx.Response(200, json=self._create_dependents_response())
            elif "/versions/" in url:
                return httpx.Response(200, json=self._create_version_response())
            elif "/packages/lodash" in url:
                return httpx.Response(200, json=no_default_pkg)
            elif "/projects/" in url:
                return httpx.Response(200, json=self._create_project_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("lodash"))

            # Should fall back to last version in list
            assert result is not None
            assert result["latest_version"] == "4.17.21"

    def test_no_repo_url(self):
        """Test handling of package without repository URL."""
        from depsdev_collector import get_package_info

        no_repo_version = self._create_version_response()
        no_repo_version["links"] = []  # No source repo link

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if ":dependents" in url:
                return httpx.Response(200, json=self._create_dependents_response())
            elif "/versions/" in url:
                return httpx.Response(200, json=no_repo_version)
            elif "/packages/lodash" in url:
                return httpx.Response(200, json=self._create_package_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("lodash"))

            assert result is not None
            assert result["repository_url"] is None
            assert result["openssf_score"] is None  # No project data without repo

    def test_version_fetch_failure_graceful(self):
        """Test graceful handling when version fetch fails."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/versions/" in url and ":dependents" not in url:
                return httpx.Response(500)  # Version fetch fails
            elif "/packages/lodash" in url:
                return httpx.Response(200, json=self._create_package_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            # Should not raise, returns partial data
            result = run_async(get_package_info("lodash"))
            assert result is not None


# =============================================================================
# SECURITY ADVISORIES TESTS
# =============================================================================


class TestSecurityAdvisories:
    """Tests for advisory data extraction."""

    def _create_package_response(self):
        """Create a mock deps.dev package API response."""
        return {
            "packageKey": {"system": "NPM", "name": "vulnerable-pkg"},
            "versions": [
                {"versionKey": {"system": "NPM", "name": "vulnerable-pkg", "version": "1.0.0"}, "isDefault": True},
            ],
        }

    def _create_version_with_advisories(self):
        """Create a version response with security advisories."""
        return {
            "versionKey": {"system": "NPM", "name": "vulnerable-pkg", "version": "1.0.0"},
            "publishedAt": "2024-01-15T00:00:00Z",
            "licenses": ["MIT"],
            "relations": {"dependencies": []},
            "advisories": [
                {
                    "advisoryKey": {"id": "GHSA-xxx-yyy"},
                    "url": "https://github.com/advisories/GHSA-xxx-yyy",
                    "title": "Prototype Pollution",
                    "aliases": ["CVE-2024-1234"],
                    "severity": "HIGH",
                },
                {
                    "advisoryKey": {"id": "GHSA-aaa-bbb"},
                    "url": "https://github.com/advisories/GHSA-aaa-bbb",
                    "title": "ReDoS vulnerability",
                    "aliases": ["CVE-2024-5678"],
                    "severity": "MEDIUM",
                },
            ],
            "links": [],
        }

    def test_advisories_extracted(self):
        """Test that security advisories are extracted."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if ":dependents" in url:
                return httpx.Response(200, json={"dependentCount": 100})
            elif "/versions/" in url:
                return httpx.Response(200, json=self._create_version_with_advisories())
            elif "/packages/" in url:
                return httpx.Response(200, json=self._create_package_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("vulnerable-pkg"))

            assert result is not None
            assert len(result["advisories"]) == 2
            assert result["advisories"][0]["severity"] == "HIGH"


class TestGetAdvisories:
    """Tests for get_advisories function."""

    def test_get_advisories_success(self):
        """Test successful advisory fetch."""
        from depsdev_collector import get_advisories

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "advisories": [
                        {"advisoryKey": {"id": "GHSA-test"}, "severity": "HIGH"},
                    ]
                },
            )

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_advisories("lodash"))
            assert len(result) == 1
            assert result[0]["severity"] == "HIGH"

    def test_get_advisories_failure(self):
        """Test advisory fetch failure returns empty list."""
        from depsdev_collector import get_advisories

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_advisories("lodash"))
            assert result == []


# =============================================================================
# DEPENDENTS TESTS
# =============================================================================


class TestGetDependentsCount:
    """Tests for get_dependents_count function."""

    def test_get_dependents_count_success(self):
        """Test successful dependents count fetch."""
        from depsdev_collector import get_dependents_count

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"dependentCount": 50000})

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_dependents_count("lodash"))
            assert result == 50000

    def test_get_dependents_count_as_list(self):
        """Test handling when dependentCount is a list instead of int."""
        from depsdev_collector import get_package_info

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if ":dependents" in url:
                # Some responses return list of dependents
                return httpx.Response(200, json={"dependentCount": ["pkg1", "pkg2", "pkg3"]})
            elif "/versions/" in url:
                return httpx.Response(
                    200,
                    json={
                        "versionKey": {"version": "1.0.0"},
                        "publishedAt": "2024-01-01T00:00:00Z",
                        "licenses": ["MIT"],
                        "relations": {"dependencies": []},
                        "advisories": [],
                        "links": [],
                    },
                )
            elif "/packages/" in url:
                return httpx.Response(
                    200,
                    json={
                        "packageKey": {"system": "NPM", "name": "test-pkg"},
                        "versions": [
                            {"versionKey": {"version": "1.0.0"}, "isDefault": True},
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
            assert result["dependents_count"] == 3  # Length of list


# =============================================================================
# DEPENDENCIES TESTS
# =============================================================================


class TestGetDependencies:
    """Tests for get_dependencies function."""

    def _create_package_response(self, name="lodash"):
        """Create a mock deps.dev package API response."""
        return {
            "packageKey": {"system": "NPM", "name": name},
            "versions": [
                {"versionKey": {"system": "NPM", "name": name, "version": "1.0.0"}, "isDefault": True},
            ],
        }

    def _create_dependencies_response(self, name="lodash"):
        """Create a mock deps.dev dependencies API response."""
        return {
            "nodes": [
                # First node is the package itself
                {"versionKey": {"system": "npm", "name": name, "version": "1.0.0"}, "relation": "SELF"},
                # Direct dependencies
                {"versionKey": {"system": "npm", "name": "dep1", "version": "2.0.0"}, "relation": "DIRECT"},
                {"versionKey": {"system": "npm", "name": "dep2", "version": "3.0.0"}, "relation": "DIRECT"},
                # Transitive dependency (should be excluded)
                {"versionKey": {"system": "npm", "name": "transitive-dep", "version": "1.0.0"}, "relation": "INDIRECT"},
            ],
        }

    def test_get_dependencies_success(self):
        """Test successful dependencies fetch."""
        from depsdev_collector import get_dependencies

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if ":dependencies" in url:
                return httpx.Response(200, json=self._create_dependencies_response())
            elif "/packages/lodash" in url:
                return httpx.Response(200, json=self._create_package_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_dependencies("lodash"))

            # Should only return direct dependencies
            assert "dep1" in result
            assert "dep2" in result
            assert "transitive-dep" not in result  # INDIRECT should be excluded
            assert "lodash" not in result  # SELF should be excluded

    def test_get_dependencies_package_not_found(self):
        """Test dependencies fetch for non-existent package."""
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

    def test_get_dependencies_no_versions(self):
        """Test dependencies fetch when package has no versions."""
        from depsdev_collector import get_dependencies

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/packages/" in url:
                return httpx.Response(
                    200,
                    json={
                        "packageKey": {"system": "NPM", "name": "empty-pkg"},
                        "versions": [],  # No versions
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

    def test_get_dependencies_filters_other_ecosystems(self):
        """Test that dependencies from other ecosystems are filtered."""
        from depsdev_collector import get_dependencies

        mixed_deps = {
            "nodes": [
                {"versionKey": {"system": "npm", "name": "lodash", "version": "1.0.0"}, "relation": "SELF"},
                {"versionKey": {"system": "npm", "name": "npm-dep", "version": "1.0.0"}, "relation": "DIRECT"},
                {"versionKey": {"system": "pypi", "name": "pypi-dep", "version": "1.0.0"}, "relation": "DIRECT"},
            ],
        }

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if ":dependencies" in url:
                return httpx.Response(200, json=mixed_deps)
            elif "/packages/lodash" in url:
                return httpx.Response(200, json=self._create_package_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_dependencies("lodash"))

            assert "npm-dep" in result
            assert "pypi-dep" not in result  # Different ecosystem


# =============================================================================
# RETRY WITH BACKOFF TESTS
# =============================================================================


class TestRetryWithBackoff:
    """Tests for retry_with_backoff function."""

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


# =============================================================================
# OPENSSF SCORECARD TESTS
# =============================================================================


class TestOpenSSFScorecard:
    """Tests for OpenSSF scorecard extraction."""

    def _create_package_response(self):
        """Create a mock deps.dev package API response."""
        return {
            "packageKey": {"system": "NPM", "name": "lodash"},
            "versions": [
                {"versionKey": {"system": "NPM", "name": "lodash", "version": "4.17.21"}, "isDefault": True},
            ],
        }

    def _create_version_response(self):
        """Create a mock deps.dev version API response."""
        return {
            "versionKey": {"system": "NPM", "name": "lodash", "version": "4.17.21"},
            "publishedAt": "2024-01-15T00:00:00Z",
            "licenses": ["MIT"],
            "relations": {"dependencies": []},
            "advisories": [],
            "links": [
                {"label": "SOURCE_REPO", "url": "https://github.com/lodash/lodash"},
            ],
        }

    def test_openssf_score_extraction(self):
        """Test extraction of OpenSSF scorecard score."""
        from depsdev_collector import get_package_info

        project_with_scorecard = {
            "starsCount": 58000,
            "forksCount": 7000,
            "scorecardV2": {
                "score": 8.5,
                "check": [
                    {"name": "Code-Review", "score": 9},
                    {"name": "Maintained", "score": 10},
                    {"name": "Vulnerabilities", "score": 10},
                    {"name": "Security-Policy", "score": 8},
                ],
            },
        }

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if ":dependents" in url:
                return httpx.Response(200, json={"dependentCount": 5000})
            elif "/versions/" in url:
                return httpx.Response(200, json=self._create_version_response())
            elif "/packages/" in url:
                return httpx.Response(200, json=self._create_package_response())
            elif "/projects/" in url:
                return httpx.Response(200, json=project_with_scorecard)
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("lodash"))

            assert result["openssf_score"] == 8.5
            assert len(result["openssf_checks"]) == 4
            assert any(check["name"] == "Code-Review" for check in result["openssf_checks"])

    def test_no_scorecard_available(self):
        """Test handling when OpenSSF scorecard is not available."""
        from depsdev_collector import get_package_info

        project_without_scorecard = {
            "starsCount": 100,
            "forksCount": 10,
            # No scorecardV2 field
        }

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if ":dependents" in url:
                return httpx.Response(200, json={"dependentCount": 100})
            elif "/versions/" in url:
                return httpx.Response(200, json=self._create_version_response())
            elif "/packages/" in url:
                return httpx.Response(200, json=self._create_package_response())
            elif "/projects/" in url:
                return httpx.Response(200, json=project_without_scorecard)
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_package_info("lodash"))

            assert result["openssf_score"] is None
            assert result["openssf_checks"] == []
