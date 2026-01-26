"""
Tests for Bundlephobia collector.

Tests cover:
- Package name encoding (scoped packages)
- Bundle size fetching
- Download time estimation
- Size categorization
- Batch fetching
- Error handling (404, 429, 504, network errors)
- Retry logic with backoff

Run with: PYTHONPATH=functions:. pytest tests/test_bundlephobia_collector.py -v
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


class TestEncodePackageSpec:
    """Tests for encode_package_spec function."""

    def test_encode_simple_package(self):
        """Simple package names should be URL-encoded."""
        from bundlephobia_collector import encode_package_spec
        assert encode_package_spec("lodash") == "lodash"

    def test_encode_scoped_package(self):
        """Scoped npm packages should be URL-encoded."""
        from bundlephobia_collector import encode_package_spec
        assert encode_package_spec("@babel/core") == "%40babel%2Fcore"

    def test_encode_package_with_version(self):
        """Package with version should be properly encoded."""
        from bundlephobia_collector import encode_package_spec
        assert encode_package_spec("lodash", "4.17.21") == "lodash@4.17.21"

    def test_encode_scoped_package_with_version(self):
        """Scoped package with version should be properly encoded."""
        from bundlephobia_collector import encode_package_spec
        assert encode_package_spec("@babel/core", "7.24.0") == "%40babel%2Fcore@7.24.0"


# =============================================================================
# GET BUNDLE SIZE TESTS
# =============================================================================


class TestGetBundleSize:
    """Tests for get_bundle_size function."""

    def _create_bundlephobia_response(self, name="lodash", gzip_size=25000, size=70000):
        """Create a mock Bundlephobia API response."""
        return {
            "name": name,
            "version": "4.17.21",
            "size": size,  # Minified size
            "gzip": gzip_size,  # Gzipped size
            "dependencyCount": 0,
            "hasSideEffects": False,
        }

    def test_successful_bundle_size_fetch(self):
        """Test successful bundle size fetch with all fields."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=self._create_bundlephobia_response())

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("lodash"))

            assert result["name"] == "lodash"
            assert result["version"] == "4.17.21"
            assert result["size"] == 70000
            assert result["gzip"] == 25000
            assert result["dependency_count"] == 0
            assert result["has_side_effects"] is False
            assert result["source"] == "bundlephobia"
            # Download times should be calculated
            assert result["download_time_3g"] > 0
            assert result["download_time_4g"] > 0
            # Size category should be set
            assert result["size_category"] in ["tiny", "small", "medium", "large", "huge"]

    def test_scoped_package_fetch(self):
        """Test fetching bundle size for scoped package."""
        from bundlephobia_collector import get_bundle_size

        requested_url = None

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal requested_url
            requested_url = str(request.url)
            return httpx.Response(200, json=self._create_bundlephobia_response(name="@babel/core"))

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("@babel/core"))

            assert result["name"] == "@babel/core"
            # Verify URL encoding was applied
            assert "%40babel%2Fcore" in requested_url

    def test_package_with_specific_version(self):
        """Test fetching bundle size for specific version."""
        from bundlephobia_collector import get_bundle_size

        requested_url = None

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal requested_url
            requested_url = str(request.url)
            return httpx.Response(200, json=self._create_bundlephobia_response())

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            run_async(get_bundle_size("lodash", version="4.17.20"))

            assert "lodash@4.17.20" in requested_url

    def test_package_not_found(self):
        """Test 404 handling for package not found."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("nonexistent-package-xyz"))

            assert result["error"] == "not_found"
            assert result["name"] == "nonexistent-package-xyz"
            assert result["source"] == "bundlephobia"

    def test_rate_limited(self):
        """Test 429 rate limit handling."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("lodash"))

            assert result["error"] == "rate_limited"
            assert result["name"] == "lodash"

    def test_timeout_504(self):
        """Test 504 timeout handling (large/complex packages)."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(504)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("huge-package"))

            assert result["error"] == "timeout"
            assert result["name"] == "huge-package"

    def test_generic_exception_handling(self):
        """Test generic exception handling."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            # Return invalid JSON to cause a parse error
            return httpx.Response(200, content=b"not valid json {{{")

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("test-package"))

            assert "error" in result
            assert "fetch_error" in result["error"]


# =============================================================================
# DOWNLOAD TIME ESTIMATION TESTS
# =============================================================================


class TestEstimateDownloadTime:
    """Tests for _estimate_download_time function."""

    def test_3g_download_time(self):
        """Test 3G download time estimation."""
        from bundlephobia_collector import _estimate_download_time

        # 25KB gzipped should take ~500ms on 3G (50 B/ms)
        result = _estimate_download_time(25000, network="3g")
        assert result == 500

    def test_4g_download_time(self):
        """Test 4G download time estimation."""
        from bundlephobia_collector import _estimate_download_time

        # 25KB gzipped should take ~28ms on 4G (875 B/ms)
        result = _estimate_download_time(25000, network="4g")
        assert result == 28

    def test_zero_size(self):
        """Test handling of zero size."""
        from bundlephobia_collector import _estimate_download_time

        assert _estimate_download_time(0, network="3g") == 0
        assert _estimate_download_time(0, network="4g") == 0

    def test_negative_size(self):
        """Test handling of negative size (edge case)."""
        from bundlephobia_collector import _estimate_download_time

        assert _estimate_download_time(-100, network="3g") == 0

    def test_unknown_network_defaults_to_4g(self):
        """Test that unknown network type defaults to 4G speed."""
        from bundlephobia_collector import _estimate_download_time

        result_4g = _estimate_download_time(25000, network="4g")
        result_unknown = _estimate_download_time(25000, network="unknown")
        assert result_4g == result_unknown

    def test_minimum_download_time(self):
        """Test that minimum download time is 1ms."""
        from bundlephobia_collector import _estimate_download_time

        # Very small size should still return at least 1ms
        result = _estimate_download_time(1, network="4g")
        assert result >= 1


# =============================================================================
# SIZE CATEGORIZATION TESTS
# =============================================================================


class TestCategorizeSize:
    """Tests for _categorize_size function."""

    def test_tiny_size(self):
        """Test tiny size category (< 5KB)."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(1024) == "tiny"  # 1KB
        assert _categorize_size(4096) == "tiny"  # 4KB

    def test_small_size(self):
        """Test small size category (5-20KB)."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(5120) == "small"  # 5KB
        assert _categorize_size(15360) == "small"  # 15KB
        assert _categorize_size(19456) == "small"  # 19KB

    def test_medium_size(self):
        """Test medium size category (20-100KB)."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(20480) == "medium"  # 20KB
        assert _categorize_size(51200) == "medium"  # 50KB
        assert _categorize_size(99328) == "medium"  # 97KB

    def test_large_size(self):
        """Test large size category (100-500KB)."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(102400) == "large"  # 100KB
        assert _categorize_size(256000) == "large"  # 250KB
        assert _categorize_size(499712) == "large"  # ~488KB

    def test_huge_size(self):
        """Test huge size category (> 500KB)."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(512000) == "huge"  # 500KB
        assert _categorize_size(1048576) == "huge"  # 1MB
        assert _categorize_size(5242880) == "huge"  # 5MB

    def test_zero_size(self):
        """Test zero size categorization."""
        from bundlephobia_collector import _categorize_size

        assert _categorize_size(0) == "tiny"

    def test_boundary_values(self):
        """Test exact boundary values."""
        from bundlephobia_collector import _categorize_size

        # 5KB boundary
        assert _categorize_size(5 * 1024 - 1) == "tiny"
        assert _categorize_size(5 * 1024) == "small"

        # 20KB boundary
        assert _categorize_size(20 * 1024 - 1) == "small"
        assert _categorize_size(20 * 1024) == "medium"

        # 100KB boundary
        assert _categorize_size(100 * 1024 - 1) == "medium"
        assert _categorize_size(100 * 1024) == "large"

        # 500KB boundary
        assert _categorize_size(500 * 1024 - 1) == "large"
        assert _categorize_size(500 * 1024) == "huge"


# =============================================================================
# BUNDLE SIZE CATEGORIES IN FETCH TESTS
# =============================================================================


class TestBundleSizeCategoriesInFetch:
    """Tests for size categories in get_bundle_size results."""

    def test_tiny_package(self):
        """Test tiny package categorization."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "name": "tiny-pkg",
                "version": "1.0.0",
                "size": 2000,
                "gzip": 1000,  # 1KB
                "dependencyCount": 0,
                "hasSideEffects": False,
            })

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("tiny-pkg"))
            assert result["size_category"] == "tiny"

    def test_huge_package(self):
        """Test huge package categorization."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "name": "huge-pkg",
                "version": "1.0.0",
                "size": 2000000,
                "gzip": 600000,  # 600KB
                "dependencyCount": 50,
                "hasSideEffects": True,
            })

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("huge-pkg"))
            assert result["size_category"] == "huge"


# =============================================================================
# BATCH FETCH TESTS
# =============================================================================


class TestGetBundleSizesBatch:
    """Tests for get_bundle_sizes_batch function."""

    def test_batch_fetch_multiple_packages(self):
        """Test batch fetching multiple packages."""
        from bundlephobia_collector import get_bundle_sizes_batch

        call_count = 0

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            url = str(request.url)
            if "lodash" in url:
                return httpx.Response(200, json={
                    "name": "lodash",
                    "version": "4.17.21",
                    "size": 70000,
                    "gzip": 25000,
                    "dependencyCount": 0,
                    "hasSideEffects": False,
                })
            elif "express" in url:
                return httpx.Response(200, json={
                    "name": "express",
                    "version": "4.18.2",
                    "size": 50000,
                    "gzip": 15000,
                    "dependencyCount": 30,
                    "hasSideEffects": False,
                })
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            # Use asyncio.sleep mock to speed up test
            with patch("asyncio.sleep", return_value=None):
                result = run_async(get_bundle_sizes_batch(["lodash", "express"]))

            assert "lodash" in result
            assert "express" in result
            assert result["lodash"]["gzip"] == 25000
            assert result["express"]["gzip"] == 15000
            # Should make 2 API calls
            assert call_count == 2

    def test_batch_fetch_handles_failures(self):
        """Test batch fetching handles individual failures gracefully."""
        from bundlephobia_collector import get_bundle_sizes_batch

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "lodash" in url:
                return httpx.Response(200, json={
                    "name": "lodash",
                    "version": "4.17.21",
                    "size": 70000,
                    "gzip": 25000,
                    "dependencyCount": 0,
                    "hasSideEffects": False,
                })
            elif "nonexistent" in url:
                return httpx.Response(404)  # Not found
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            with patch("asyncio.sleep", return_value=None):
                result = run_async(get_bundle_sizes_batch(["lodash", "nonexistent-pkg"]))

            assert "lodash" in result
            assert "nonexistent-pkg" in result
            assert result["lodash"]["gzip"] == 25000
            assert result["nonexistent-pkg"]["error"] == "not_found"

    def test_batch_fetch_empty_list(self):
        """Test batch fetching with empty list."""
        from bundlephobia_collector import get_bundle_sizes_batch

        result = run_async(get_bundle_sizes_batch([]))
        assert result == {}


# =============================================================================
# RETRY WITH BACKOFF TESTS
# =============================================================================


class TestRetryWithBackoff:
    """Tests for retry_with_backoff function."""

    def test_success_on_first_attempt(self):
        """Test successful execution on first attempt."""
        from bundlephobia_collector import retry_with_backoff

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
        from bundlephobia_collector import retry_with_backoff

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
        from bundlephobia_collector import retry_with_backoff

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
        from bundlephobia_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            response = httpx.Response(400, request=httpx.Request("GET", "http://test"))
            raise httpx.HTTPStatusError("Bad request", request=response.request, response=response)

        with pytest.raises(httpx.HTTPStatusError):
            run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert call_count == 1

    def test_retry_on_502_bad_gateway(self):
        """Test retry on 502 Bad Gateway."""
        from bundlephobia_collector import retry_with_backoff

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
        from bundlephobia_collector import retry_with_backoff

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
        from bundlephobia_collector import retry_with_backoff

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

    def test_retry_on_network_error(self):
        """Test retry on network/connection errors."""
        from bundlephobia_collector import retry_with_backoff

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
        from bundlephobia_collector import retry_with_backoff

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
        from bundlephobia_collector import retry_with_backoff

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
# EDGE CASES
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases in bundle size collection."""

    def test_package_with_side_effects(self):
        """Test package with side effects flag."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "name": "side-effect-pkg",
                "version": "1.0.0",
                "size": 10000,
                "gzip": 5000,
                "dependencyCount": 5,
                "hasSideEffects": True,
            })

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("side-effect-pkg"))
            assert result["has_side_effects"] is True

    def test_package_with_many_dependencies(self):
        """Test package with many dependencies."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "name": "heavy-deps-pkg",
                "version": "1.0.0",
                "size": 500000,
                "gzip": 150000,
                "dependencyCount": 100,
                "hasSideEffects": False,
            })

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("heavy-deps-pkg"))
            assert result["dependency_count"] == 100
            assert result["size_category"] == "large"

    def test_missing_fields_in_response(self):
        """Test handling of missing fields in API response."""
        from bundlephobia_collector import get_bundle_size

        def mock_handler(request: httpx.Request) -> httpx.Response:
            # Response missing some optional fields
            return httpx.Response(200, json={
                "name": "minimal-pkg",
                "version": "1.0.0",
                # size and gzip might be 0 or missing
            })

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_bundle_size("minimal-pkg"))
            # Should use defaults
            assert result["size"] == 0
            assert result["gzip"] == 0
            assert result["dependency_count"] == 0

    def test_http_500_retries_then_raises(self):
        """Test that 500 errors retry and eventually raise after max retries."""
        from bundlephobia_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            response = httpx.Response(500, request=httpx.Request("GET", "http://test"))
            raise httpx.HTTPStatusError("Server error", request=response.request, response=response)

        with pytest.raises(httpx.HTTPStatusError):
            run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))

        # Should have retried 3 times before failing
        assert call_count == 3

    def test_http_500_retry_eventual_success(self):
        """Test that 500 errors retry and can eventually succeed."""
        from bundlephobia_collector import retry_with_backoff

        call_count = 0

        async def mock_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                response = httpx.Response(500, request=httpx.Request("GET", "http://test"))
                raise httpx.HTTPStatusError("Server error", request=response.request, response=response)
            return {"name": "retry-pkg", "success": True}

        result = run_async(retry_with_backoff(mock_func, max_retries=3, base_delay=0.01))
        assert result["success"] is True
        assert call_count == 3
