"""
Tests for PyPI collector.

Tests cover:
- Package name normalization (PEP 503)
- Package name validation
- PyPI API data fetching
- Classifier parsing (development status, Python versions)
- Download stats from pypistats.org

Run with: PYTHONPATH=functions:. pytest tests/test_pypi_collector.py -v
"""

import asyncio
import json
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
# PACKAGE NAME NORMALIZATION TESTS
# =============================================================================


class TestNormalizePackageName:
    """Tests for PEP 503 package name normalization."""

    def test_normalize_lowercase(self):
        """Normalize uppercase to lowercase."""
        from pypi_collector import normalize_package_name
        assert normalize_package_name("Django") == "django"
        assert normalize_package_name("Flask") == "flask"
        assert normalize_package_name("REQUESTS") == "requests"

    def test_normalize_underscores(self):
        """Normalize underscores to hyphens."""
        from pypi_collector import normalize_package_name
        assert normalize_package_name("requests_oauthlib") == "requests-oauthlib"
        assert normalize_package_name("python_dateutil") == "python-dateutil"

    def test_normalize_periods(self):
        """Normalize periods to hyphens."""
        from pypi_collector import normalize_package_name
        assert normalize_package_name("Flask.WTF") == "flask-wtf"
        assert normalize_package_name("zope.interface") == "zope-interface"

    def test_normalize_consecutive_separators(self):
        """Collapse consecutive separators."""
        from pypi_collector import normalize_package_name
        assert normalize_package_name("foo__bar") == "foo-bar"
        assert normalize_package_name("foo--bar") == "foo-bar"
        assert normalize_package_name("foo..bar") == "foo-bar"
        assert normalize_package_name("foo_-_bar") == "foo-bar"

    def test_normalize_mixed_case_and_separators(self):
        """Normalize mixed case and separators."""
        from pypi_collector import normalize_package_name
        assert normalize_package_name("Requests_OAuthlib") == "requests-oauthlib"
        assert normalize_package_name("FLASK.WTF") == "flask-wtf"

    def test_normalize_already_normalized(self):
        """Already normalized names remain unchanged."""
        from pypi_collector import normalize_package_name
        assert normalize_package_name("requests") == "requests"
        assert normalize_package_name("flask-wtf") == "flask-wtf"


# =============================================================================
# PACKAGE NAME VALIDATION TESTS
# =============================================================================


class TestValidatePyPIPackageName:
    """Tests for package name validation."""

    def test_valid_simple_name(self):
        """Valid simple package name."""
        from pypi_collector import validate_pypi_package_name
        is_valid, error = validate_pypi_package_name("requests")
        assert is_valid is True
        assert error is None

    def test_valid_with_hyphens(self):
        """Valid name with hyphens."""
        from pypi_collector import validate_pypi_package_name
        is_valid, error = validate_pypi_package_name("my-package")
        assert is_valid is True

    def test_valid_with_numbers(self):
        """Valid name with numbers."""
        from pypi_collector import validate_pypi_package_name
        is_valid, error = validate_pypi_package_name("oauth2")
        assert is_valid is True

    def test_valid_mixed_case(self):
        """Valid mixed case name (normalized during validation)."""
        from pypi_collector import validate_pypi_package_name
        is_valid, error = validate_pypi_package_name("Django")
        assert is_valid is True

    def test_invalid_empty(self):
        """Empty name is invalid."""
        from pypi_collector import validate_pypi_package_name
        is_valid, error = validate_pypi_package_name("")
        assert is_valid is False
        assert "Empty" in error

    def test_invalid_too_long(self):
        """Name exceeding max length is invalid."""
        from pypi_collector import validate_pypi_package_name
        long_name = "a" * 200
        is_valid, error = validate_pypi_package_name(long_name)
        assert is_valid is False
        assert "too long" in error

    def test_invalid_starts_with_hyphen(self):
        """Name starting with hyphen is invalid after normalization."""
        from pypi_collector import validate_pypi_package_name
        is_valid, error = validate_pypi_package_name("-foo")
        assert is_valid is False


# =============================================================================
# CLASSIFIER PARSING TESTS
# =============================================================================


class TestExtractDevelopmentStatus:
    """Tests for development status extraction from classifiers."""

    def test_extract_stable(self):
        """Extract Production/Stable status."""
        from pypi_collector import _extract_development_status
        classifiers = [
            "Development Status :: 5 - Production/Stable",
            "Programming Language :: Python :: 3",
        ]
        assert _extract_development_status(classifiers) == "5 - Production/Stable"

    def test_extract_beta(self):
        """Extract Beta status."""
        from pypi_collector import _extract_development_status
        classifiers = ["Development Status :: 4 - Beta"]
        assert _extract_development_status(classifiers) == "4 - Beta"

    def test_extract_inactive(self):
        """Extract Inactive status."""
        from pypi_collector import _extract_development_status
        classifiers = ["Development Status :: 7 - Inactive"]
        assert _extract_development_status(classifiers) == "7 - Inactive"

    def test_no_development_status(self):
        """Return None when no development status classifier."""
        from pypi_collector import _extract_development_status
        classifiers = ["Programming Language :: Python :: 3"]
        assert _extract_development_status(classifiers) is None


class TestExtractPythonVersions:
    """Tests for Python version extraction from classifiers."""

    def test_extract_multiple_versions(self):
        """Extract multiple Python versions."""
        from pypi_collector import _extract_python_versions
        classifiers = [
            "Programming Language :: Python :: 3.9",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: 3.11",
            "Programming Language :: Python :: 3.12",
        ]
        versions = _extract_python_versions(classifiers)
        assert "3.9" in versions
        assert "3.10" in versions
        assert "3.11" in versions
        assert "3.12" in versions

    def test_extract_major_version_only(self):
        """Handle major version classifier."""
        from pypi_collector import _extract_python_versions
        classifiers = [
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.10",
        ]
        versions = _extract_python_versions(classifiers)
        assert "3" in versions
        assert "3.10" in versions

    def test_no_python_classifiers(self):
        """Return empty list when no Python classifiers."""
        from pypi_collector import _extract_python_versions
        classifiers = ["Development Status :: 5 - Production/Stable"]
        versions = _extract_python_versions(classifiers)
        assert versions == []

    def test_filter_non_version_classifiers(self):
        """Filter out non-version Python classifiers."""
        from pypi_collector import _extract_python_versions
        classifiers = [
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: Implementation :: CPython",
        ]
        versions = _extract_python_versions(classifiers)
        assert "3.10" in versions
        assert "Implementation" not in versions


class TestParseKeywords:
    """Tests for _parse_keywords function."""

    def test_parse_string_keywords(self):
        """Parse comma-separated string keywords."""
        from pypi_collector import _parse_keywords
        result = _parse_keywords("http,client,requests")
        assert result == ["http", "client", "requests"]

    def test_parse_list_keywords(self):
        """Parse list keywords."""
        from pypi_collector import _parse_keywords
        result = _parse_keywords(["http", "client", "requests"])
        assert result == ["http", "client", "requests"]

    def test_parse_none_keywords(self):
        """Return empty list for None."""
        from pypi_collector import _parse_keywords
        result = _parse_keywords(None)
        assert result == []

    def test_parse_empty_string(self):
        """Return empty list for empty string."""
        from pypi_collector import _parse_keywords
        result = _parse_keywords("")
        assert result == []

    def test_strip_whitespace(self):
        """Strip whitespace from keywords."""
        from pypi_collector import _parse_keywords
        result = _parse_keywords("  http , client , requests  ")
        assert result == ["http", "client", "requests"]

    def test_filter_empty_keywords(self):
        """Filter out empty keywords."""
        from pypi_collector import _parse_keywords
        result = _parse_keywords("http,,client,")
        assert result == ["http", "client"]

    def test_handle_non_string_in_list(self):
        """Handle non-string items in list."""
        from pypi_collector import _parse_keywords
        result = _parse_keywords(["http", 123, "client", None])
        assert result == ["http", "client"]


# =============================================================================
# API FETCH TESTS
# =============================================================================


class TestGetPyPIMetadata:
    """Tests for get_pypi_metadata function with mocked HTTP."""

    def _create_pypi_response(self, name="requests", version="2.31.0"):
        """Create a mock PyPI JSON response."""
        return {
            "info": {
                "name": name,
                "version": version,
                "author": "Kenneth Reitz",
                "maintainer": None,
                "author_email": "me@kennethreitz.org",
                "summary": "Python HTTP for Humans.",
                "license": "Apache 2.0",
                "requires_python": ">=3.7",
                "classifiers": [
                    "Development Status :: 5 - Production/Stable",
                    "Programming Language :: Python :: 3.9",
                    "Programming Language :: Python :: 3.10",
                    "Programming Language :: Python :: 3.11",
                ],
                "project_urls": {
                    "Source": "https://github.com/psf/requests",
                    "Documentation": "https://requests.readthedocs.io",
                },
                "home_page": "https://requests.readthedocs.io",
                "keywords": "http,client,requests",
            },
            "releases": {
                "2.30.0": [{"upload_time_iso_8601": "2023-05-01T00:00:00Z"}],
                "2.31.0": [{"upload_time_iso_8601": "2023-06-01T00:00:00Z"}],
                "1.0.0": [{"upload_time_iso_8601": "2012-01-01T00:00:00Z"}],
            },
        }

    def _create_pypistats_response(self):
        """Create a mock pypistats response."""
        return {
            "data": {
                "last_day": 1000000,
                "last_week": 7000000,
                "last_month": 30000000,
            },
            "package": "requests",
            "type": "recent_downloads",
        }

    def test_successful_fetch(self):
        """Test successful metadata fetch with all expected fields."""
        from pypi_collector import get_pypi_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "pypi.org" in url:
                return httpx.Response(200, json=self._create_pypi_response())
            elif "pypistats.org" in url:
                return httpx.Response(200, json=self._create_pypistats_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_pypi_metadata("requests"))

            # Verify core fields
            assert result["name"] == "requests"
            assert result["latest_version"] == "2.31.0"
            assert result["maintainer_count"] == 1
            assert result["is_deprecated"] is False
            assert result["weekly_downloads"] == 7000000
            assert result["repository_url"] == "https://github.com/psf/requests"
            assert result["requires_python"] == ">=3.7"
            assert result["source"] == "pypi"

            # Verify timestamps exist
            assert result["created_at"] is not None
            assert result["last_published"] is not None

            # Verify classifiers parsed correctly
            assert result["development_status"] == "5 - Production/Stable"
            assert "3.10" in result["python_versions"]

    def test_pypistats_failure_graceful_degradation(self):
        """Test that pypistats.org failure doesn't fail the whole request."""
        from pypi_collector import get_pypi_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "pypi.org" in url:
                return httpx.Response(200, json=self._create_pypi_response())
            elif "pypistats.org" in url:
                return httpx.Response(500)  # pypistats fails
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_pypi_metadata("requests"))

            # Should succeed with 0 downloads
            assert "error" not in result
            assert result["weekly_downloads"] == 0
            assert result["name"] == "requests"

    def test_non_github_repo_url_cleared(self):
        """Test that non-GitHub/GitLab/Bitbucket URLs are cleared."""
        from pypi_collector import get_pypi_metadata

        response = self._create_pypi_response()
        response["info"]["project_urls"] = {
            "Homepage": "https://example.com/mypackage"
        }

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "pypi.org" in url:
                return httpx.Response(200, json=response)
            elif "pypistats.org" in url:
                return httpx.Response(200, json=self._create_pypistats_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_pypi_metadata("mypackage"))

            # Non-GitHub URLs should be cleared
            assert result["repository_url"] is None

    def test_package_not_found(self):
        """Test 404 handling for non-existent package."""
        from pypi_collector import get_pypi_metadata

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_pypi_metadata("nonexistent-package-xyz"))
            assert "error" in result
            assert result["error"] == "package_not_found"

    def test_deprecated_package_detection(self):
        """Test detection of deprecated package via classifier."""
        from pypi_collector import get_pypi_metadata

        deprecated_response = self._create_pypi_response()
        deprecated_response["info"]["classifiers"] = [
            "Development Status :: 7 - Inactive"
        ]

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "pypi.org" in url:
                return httpx.Response(200, json=deprecated_response)
            elif "pypistats.org" in url:
                return httpx.Response(200, json=self._create_pypistats_response())
            return httpx.Response(404)

        original_init = httpx.AsyncClient.__init__

        def patched_init(self, *args, **kwargs):
            kwargs["transport"] = create_mock_transport(mock_handler)
            original_init(self, *args, **kwargs)

        with patch.object(httpx.AsyncClient, "__init__", patched_init):
            result = run_async(get_pypi_metadata("deprecated-package"))
            assert result.get("is_deprecated") is True


# =============================================================================
# PACKAGE COLLECTOR INTEGRATION TESTS
# =============================================================================


class TestPackageCollectorPyPIValidation:
    """Test PyPI validation in package_collector."""

    def test_validate_pypi_ecosystem(self):
        """Validate that pypi ecosystem is accepted."""
        from collectors.package_collector import validate_message

        is_valid, error = validate_message({
            "ecosystem": "pypi",
            "name": "requests",
            "tier": 1,
        })
        assert is_valid is True
        assert error is None

    def test_validate_pypi_mixed_case_name(self):
        """Validate PyPI package with mixed case name."""
        from collectors.package_collector import validate_message

        is_valid, error = validate_message({
            "ecosystem": "pypi",
            "name": "Django",
            "tier": 1,
        })
        assert is_valid is True

    def test_validate_pypi_name_with_underscores(self):
        """Validate PyPI package with underscores."""
        from collectors.package_collector import validate_message

        is_valid, error = validate_message({
            "ecosystem": "pypi",
            "name": "python_dateutil",
            "tier": 1,
        })
        assert is_valid is True

    def test_reject_invalid_pypi_name(self):
        """Reject invalid PyPI package name."""
        from collectors.package_collector import validate_message

        is_valid, error = validate_message({
            "ecosystem": "pypi",
            "name": "-invalid",
            "tier": 1,
        })
        assert is_valid is False
        assert "Invalid" in error

    def test_reject_pypi_name_too_long(self):
        """Reject PyPI package name that's too long."""
        from collectors.package_collector import validate_message

        is_valid, error = validate_message({
            "ecosystem": "pypi",
            "name": "a" * 200,
            "tier": 1,
        })
        assert is_valid is False
        assert "too long" in error

    def test_reject_pypi_path_traversal(self):
        """Reject PyPI package name with path traversal."""
        from collectors.package_collector import validate_message

        is_valid, error = validate_message({
            "ecosystem": "pypi",
            "name": "../etc/passwd",
            "tier": 1,
        })
        assert is_valid is False
        assert "path traversal" in error
