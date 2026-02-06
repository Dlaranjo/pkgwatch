"""
Tests for npm registry collector.

Tests cover:
- Package name encoding (scoped packages)
- Registry metadata fetching
- Download statistics
- Deprecation detection
- TypeScript support detection
- Module system detection (ESM/CJS)
- Error handling (404, rate limits, network errors)
- Retry logic with backoff

Run with: PYTHONPATH=functions:. pytest tests/test_npm_collector.py -v
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
# PACKAGE NAME ENCODING TESTS
# =============================================================================


class TestEncodeScopedPackage:
    """Tests for encode_scoped_package function."""

    def test_encode_scoped_package(self):
        """Encode scoped package name."""
        from npm_collector import encode_scoped_package
        assert encode_scoped_package("@babel/core") == "@babel%2Fcore"

    def test_encode_nested_scoped_package(self):
        """Encode scoped package with complex name."""
        from npm_collector import encode_scoped_package
        assert encode_scoped_package("@types/node") == "@types%2Fnode"

    def test_encode_unscoped_package(self):
        """Unscoped packages remain unchanged."""
        from npm_collector import encode_scoped_package
        assert encode_scoped_package("lodash") == "lodash"
        assert encode_scoped_package("express") == "express"

    def test_encode_package_with_hyphen(self):
        """Packages with hyphens remain unchanged."""
        from npm_collector import encode_scoped_package
        assert encode_scoped_package("react-dom") == "react-dom"

    def test_encode_scoped_package_with_hyphen(self):
        """Scoped packages with hyphens are encoded correctly."""
        from npm_collector import encode_scoped_package
        assert encode_scoped_package("@angular/core") == "@angular%2Fcore"
        assert encode_scoped_package("@vue/reactivity") == "@vue%2Freactivity"


# =============================================================================
# NPM METADATA FETCH TESTS
# =============================================================================


class TestGetNpmMetadata:
    """Tests for get_npm_metadata function with mocked HTTP."""

    def _create_npm_registry_response(self, name="lodash", version="4.17.21"):
        """Create a mock npm registry JSON response."""
        return {
            "name": name,
            "dist-tags": {"latest": version},
            "time": {
                "created": "2012-04-01T00:00:00.000Z",
                version: "2024-01-15T00:00:00.000Z",
                "modified": "2024-01-15T00:00:00.000Z",
            },
            "maintainers": [
                {"name": "jdalton", "email": "john@example.com"},
                {"name": "mathias", "email": "mathias@example.com"},
            ],
            "repository": {
                "type": "git",
                "url": "git+https://github.com/lodash/lodash.git",
            },
            "license": "MIT",
            "description": "Lodash modular utilities.",
            "keywords": ["util", "functional", "modules"],
            "versions": {
                version: {
                    "name": name,
                    "version": version,
                    "types": "./index.d.ts",
                    "type": "commonjs",
                }
            },
        }

    def _create_downloads_response(self, downloads=5000000):
        """Create a mock npm downloads API response."""
        return {
            "downloads": downloads,
            "start": "2024-01-08",
            "end": "2024-01-14",
            "package": "lodash",
        }

    def test_successful_fetch(self):
        """Test successful metadata fetch with all expected fields."""
        from npm_collector import get_npm_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=self._create_npm_registry_response())
            elif "api.npmjs.org" in url:
                return httpx.Response(200, json=self._create_downloads_response())
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
            assert "jdalton" in result["maintainers"]
            assert result["is_deprecated"] is False
            assert result["weekly_downloads"] == 5000000
            assert "github.com/lodash/lodash" in result["repository_url"]
            assert result["license"] == "MIT"
            assert result["source"] == "npm"

    def test_scoped_package_fetch(self):
        """Test fetching scoped package metadata."""
        from npm_collector import get_npm_metadata

        scoped_response = self._create_npm_registry_response(
            name="@babel/core",
            version="7.24.0"
        )

        requested_urls = []

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            requested_urls.append(url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=scoped_response)
            elif "api.npmjs.org" in url:
                return httpx.Response(200, json=self._create_downloads_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("@babel/core"))

            assert result["name"] == "@babel/core"
            # Verify URL encoding was applied
            assert any("%2F" in url for url in requested_urls if "registry" in url)

    def test_package_not_found(self):
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
            assert "error" in result
            assert result["error"] == "package_not_found"

    def test_deprecated_package_detection(self):
        """Test detection of deprecated package via deprecated field."""
        from npm_collector import get_npm_metadata

        deprecated_response = self._create_npm_registry_response()
        deprecated_response["versions"]["4.17.21"]["deprecated"] = "Use lodash-es instead"

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=deprecated_response)
            elif "api.npmjs.org" in url:
                return httpx.Response(200, json=self._create_downloads_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("lodash"))
            assert result["is_deprecated"] is True
            assert result["deprecation_message"] == "Use lodash-es instead"

    def test_typescript_support_detection_types(self):
        """Test detection of TypeScript support via types field."""
        from npm_collector import get_npm_metadata

        ts_response = self._create_npm_registry_response()
        ts_response["versions"]["4.17.21"]["types"] = "./types/index.d.ts"

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=ts_response)
            elif "api.npmjs.org" in url:
                return httpx.Response(200, json=self._create_downloads_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("lodash"))
            assert result["has_types"] is True

    def test_typescript_support_detection_typings(self):
        """Test detection of TypeScript support via typings field."""
        from npm_collector import get_npm_metadata

        ts_response = self._create_npm_registry_response()
        ts_response["versions"]["4.17.21"]["typings"] = "./index.d.ts"
        del ts_response["versions"]["4.17.21"]["types"]

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=ts_response)
            elif "api.npmjs.org" in url:
                return httpx.Response(200, json=self._create_downloads_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("lodash"))
            assert result["has_types"] is True

    def test_no_typescript_support(self):
        """Test package without TypeScript support."""
        from npm_collector import get_npm_metadata

        no_ts_response = self._create_npm_registry_response()
        del no_ts_response["versions"]["4.17.21"]["types"]

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=no_ts_response)
            elif "api.npmjs.org" in url:
                return httpx.Response(200, json=self._create_downloads_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("lodash"))
            assert result["has_types"] is False

    def test_esm_module_detection(self):
        """Test detection of ESM module type."""
        from npm_collector import get_npm_metadata

        esm_response = self._create_npm_registry_response()
        esm_response["versions"]["4.17.21"]["type"] = "module"
        esm_response["versions"]["4.17.21"]["exports"] = {"import": "./index.mjs"}

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=esm_response)
            elif "api.npmjs.org" in url:
                return httpx.Response(200, json=self._create_downloads_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("lodash"))
            assert result["module_type"] == "module"
            assert result["has_exports"] is True

    def test_commonjs_module_default(self):
        """Test default CommonJS module type."""
        from npm_collector import get_npm_metadata

        cjs_response = self._create_npm_registry_response()
        # No type field means CommonJS
        if "type" in cjs_response["versions"]["4.17.21"]:
            del cjs_response["versions"]["4.17.21"]["type"]

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=cjs_response)
            elif "api.npmjs.org" in url:
                return httpx.Response(200, json=self._create_downloads_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("lodash"))
            assert result["module_type"] == "commonjs"

    def test_downloads_api_failure_graceful_degradation(self):
        """Test that downloads API failure doesn't fail the whole request."""
        from npm_collector import get_npm_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=self._create_npm_registry_response())
            elif "api.npmjs.org" in url:
                return httpx.Response(500)  # Downloads API fails
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("lodash"))
            # Should succeed with 0 downloads
            assert "error" not in result
            assert result["weekly_downloads"] == 0
            assert result["name"] == "lodash"

    def test_invalid_json_response(self):
        """Test handling of invalid JSON response from npm registry."""
        from npm_collector import get_npm_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, content=b"not valid json {{{")
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("test-package"))
            assert result["error"] == "invalid_json_response"
            assert result["name"] == "test-package"

    def test_repository_url_string_format(self):
        """Test handling of repository as string instead of object."""
        from npm_collector import get_npm_metadata

        response = self._create_npm_registry_response()
        response["repository"] = "https://github.com/user/repo"

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=response)
            elif "api.npmjs.org" in url:
                return httpx.Response(200, json=self._create_downloads_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("lodash"))
            assert result["repository_url"] == "https://github.com/user/repo"

    def test_repository_url_cleanup(self):
        """Test cleanup of git+ prefix and .git suffix from repository URL."""
        from npm_collector import get_npm_metadata

        response = self._create_npm_registry_response()
        response["repository"]["url"] = "git+https://github.com/user/repo.git"

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=response)
            elif "api.npmjs.org" in url:
                return httpx.Response(200, json=self._create_downloads_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("lodash"))
            assert result["repository_url"] == "https://github.com/user/repo"

    def test_engine_requirements(self):
        """Test extraction of Node.js engine requirements."""
        from npm_collector import get_npm_metadata

        response = self._create_npm_registry_response()
        response["versions"]["4.17.21"]["engines"] = {"node": ">=14.0.0"}

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=response)
            elif "api.npmjs.org" in url:
                return httpx.Response(200, json=self._create_downloads_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("lodash"))
            assert result["engines"] == {"node": ">=14.0.0"}

    def test_no_maintainers(self):
        """Test handling of package with no maintainers."""
        from npm_collector import get_npm_metadata

        response = self._create_npm_registry_response()
        response["maintainers"] = []

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=response)
            elif "api.npmjs.org" in url:
                return httpx.Response(200, json=self._create_downloads_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("lodash"))
            assert result["maintainers"] == []
            assert result["maintainer_count"] == 0

    def test_no_versions_info(self):
        """Test handling of package with no versions field."""
        from npm_collector import get_npm_metadata

        response = self._create_npm_registry_response()
        del response["versions"]

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "registry.npmjs.org" in url:
                return httpx.Response(200, json=response)
            elif "api.npmjs.org" in url:
                return httpx.Response(200, json=self._create_downloads_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_npm_metadata("lodash"))
            # Should still succeed with defaults
            assert result["is_deprecated"] is False
            assert result["has_types"] is False


# =============================================================================
# DOWNLOAD STATS TESTS
# =============================================================================


class TestGetDownloadStats:
    """Tests for get_download_stats function."""

    def test_successful_stats_fetch(self):
        """Test successful download stats fetch."""
        from npm_collector import get_download_stats

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "downloads": 5000000,
                "start": "2024-01-08",
                "end": "2024-01-14",
                "package": "lodash",
            })

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_download_stats("lodash"))
            assert result["downloads"] == 5000000
            assert result["package"] == "lodash"
            assert result["start"] == "2024-01-08"

    def test_stats_fetch_failure(self):
        """Test handling of download stats fetch failure."""
        from npm_collector import get_download_stats

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_download_stats("lodash"))
            assert result["downloads"] == 0
            assert result["error"] == "fetch_failed"

    def test_stats_different_periods(self):
        """Test download stats with different periods."""
        from npm_collector import get_download_stats

        requested_url = None

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal requested_url
            requested_url = str(request.url)
            return httpx.Response(200, json={
                "downloads": 1000000,
                "package": "lodash",
            })

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            run_async(get_download_stats("lodash", period="last-month"))
            assert "last-month" in requested_url


# =============================================================================
# BULK DOWNLOAD STATS TESTS
# =============================================================================


class TestGetBulkDownloadStats:
    """Tests for get_bulk_download_stats function."""

    def test_bulk_stats_unscoped(self):
        """Test bulk download stats for unscoped packages."""
        from npm_collector import get_bulk_download_stats

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "lodash,express" in url:
                return httpx.Response(200, json={
                    "lodash": {"downloads": 5000000},
                    "express": {"downloads": 3000000},
                })
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bulk_download_stats(["lodash", "express"]))
            assert result["lodash"] == 5000000
            assert result["express"] == 3000000

    def test_bulk_stats_scoped_packages(self):
        """Test bulk download stats for scoped packages (fetched individually)."""
        from npm_collector import get_bulk_download_stats

        call_count = 0

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            url = str(request.url)
            if "@babel" in url:
                return httpx.Response(200, json={"downloads": 1000000})
            elif "@types" in url:
                return httpx.Response(200, json={"downloads": 500000})
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bulk_download_stats(["@babel/core", "@types/node"]))
            assert result["@babel/core"] == 1000000
            assert result["@types/node"] == 500000
            # Scoped packages should be fetched individually
            assert call_count >= 2

    def test_bulk_stats_fallback_on_error(self):
        """Test fallback to individual requests on bulk API error."""
        from npm_collector import get_bulk_download_stats

        bulk_attempted = False

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal bulk_attempted
            url = str(request.url)
            if "lodash,express" in url:
                bulk_attempted = True
                return httpx.Response(500)  # Bulk API fails
            elif "lodash" in url:
                return httpx.Response(200, json={"downloads": 5000000})
            elif "express" in url:
                return httpx.Response(200, json={"downloads": 3000000})
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bulk_download_stats(["lodash", "express"]))
            assert bulk_attempted is True
            # Should fall back to individual requests
            assert result["lodash"] == 5000000
            assert result["express"] == 3000000


# =============================================================================
# RETRY WITH BACKOFF TESTS
# =============================================================================


class TestRetryWithBackoff:
    """Tests for retry_with_backoff function."""

    def test_success_on_first_attempt(self):
        """Test successful execution on first attempt."""
        from npm_collector import retry_with_backoff

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
        from npm_collector import retry_with_backoff

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
        from npm_collector import retry_with_backoff

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
        from npm_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            response = httpx.Response(400, request=httpx.Request("GET", "http://test"))
            raise httpx.HTTPStatusError("Bad request", request=response.request, response=response)

        with pytest.raises(httpx.HTTPStatusError):
            run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert call_count == 1  # No retries for client errors

    def test_no_retry_on_404_not_found(self):
        """Test no retry on 404 Not Found."""
        from npm_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            response = httpx.Response(404, request=httpx.Request("GET", "http://test"))
            raise httpx.HTTPStatusError("Not found", request=response.request, response=response)

        with pytest.raises(httpx.HTTPStatusError):
            run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert call_count == 1

    def test_retry_on_network_error(self):
        """Test retry on network/connection errors."""
        from npm_collector import retry_with_backoff

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

    def test_retry_on_timeout_error(self):
        """Test retry on timeout errors."""
        from npm_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise httpx.ReadTimeout("Request timed out")
            return "success"

        result = run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert result == "success"

    def test_raises_after_max_retries(self):
        """Test that exception is raised after max retries exhausted."""
        from npm_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            response = httpx.Response(500, request=httpx.Request("GET", "http://test"))
            raise httpx.HTTPStatusError("Server error", request=response.request, response=response)

        with pytest.raises(httpx.HTTPStatusError):
            run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert call_count == 3
