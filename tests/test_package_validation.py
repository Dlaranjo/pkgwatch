"""Tests for shared package validation module."""

from shared.package_validation import (
    normalize_npm_name,
    validate_npm_package_name,
    validate_pypi_package_name,
)


class TestNpmValidation:
    """Tests for npm package validation."""

    def test_lowercase_package(self):
        """Standard lowercase package name."""
        is_valid, error, normalized = validate_npm_package_name("lodash")
        assert is_valid is True
        assert error is None
        assert normalized == "lodash"

    def test_uppercase_legacy_package(self):
        """Server is a real npm package with uppercase."""
        is_valid, error, normalized = validate_npm_package_name("Server")
        assert is_valid is True
        assert error is None
        assert normalized == "server"

    def test_mixed_case_package(self):
        """JSONStream is a real npm package with mixed case."""
        is_valid, error, normalized = validate_npm_package_name("JSONStream")
        assert is_valid is True
        assert normalized == "jsonstream"

    def test_scoped_package(self):
        """Standard scoped package."""
        is_valid, error, normalized = validate_npm_package_name("@babel/core")
        assert is_valid is True
        assert normalized == "@babel/core"

    def test_underscore_scope(self):
        """@_ndk/motion is a real npm package with underscore in scope."""
        is_valid, error, normalized = validate_npm_package_name("@_ndk/motion")
        assert is_valid is True
        assert normalized == "@_ndk/motion"

    def test_mixed_case_scoped(self):
        """Scoped package with uppercase should be normalized."""
        is_valid, error, normalized = validate_npm_package_name("@Azure/Core")
        assert is_valid is True
        assert normalized == "@azure/core"

    def test_numeric_start(self):
        """Package name can start with number."""
        is_valid, error, normalized = validate_npm_package_name("7zip")
        assert is_valid is True
        assert normalized == "7zip"

    def test_special_chars(self):
        """Package with allowed special characters."""
        is_valid, error, normalized = validate_npm_package_name("my-pkg.v2_test~1")
        assert is_valid is True

    def test_underscore_start_rejected(self):
        """Package names cannot start with underscore (per npm rules)."""
        is_valid, error, _ = validate_npm_package_name("_private")
        assert is_valid is False
        assert "Invalid npm package name format" in error

    def test_dot_start_rejected(self):
        """Package names cannot start with dot (per npm rules)."""
        is_valid, error, _ = validate_npm_package_name(".hidden")
        assert is_valid is False
        assert "Invalid npm package name format" in error

    def test_path_traversal_rejected(self):
        """Path traversal should fail with security error."""
        is_valid, error, _ = validate_npm_package_name("../etc/passwd")
        assert is_valid is False
        assert "path traversal" in error

    def test_absolute_path_rejected(self):
        """Absolute path should fail."""
        is_valid, error, _ = validate_npm_package_name("/etc/passwd")
        assert is_valid is False
        assert "path traversal" in error

    def test_too_long_rejected(self):
        """Name exceeding 214 chars should fail."""
        is_valid, error, _ = validate_npm_package_name("a" * 215)
        assert is_valid is False
        assert "too long" in error

    def test_exact_max_length_allowed(self):
        """Name at exactly 214 chars should pass."""
        is_valid, error, normalized = validate_npm_package_name("a" * 214)
        assert is_valid is True
        assert len(normalized) == 214

    def test_double_dot_in_name_allowed(self):
        """Package names with '..' that aren't path traversal should be allowed."""
        # foo..bar is a valid npm package name pattern (double dots not at path boundary)
        is_valid, error, normalized = validate_npm_package_name("foo..bar")
        assert is_valid is True
        assert normalized == "foo..bar"

    def test_empty_name_rejected(self):
        """Empty name should fail."""
        is_valid, error, _ = validate_npm_package_name("")
        assert is_valid is False
        assert "Empty" in error

    def test_invalid_special_chars_rejected(self):
        """Invalid special characters should fail."""
        is_valid, error, _ = validate_npm_package_name("package$name")
        assert is_valid is False

        is_valid, error, _ = validate_npm_package_name("package@name")  # @ only valid for scopes
        assert is_valid is False


class TestNpmNormalization:
    """Tests for npm name normalization."""

    def test_normalize_uppercase(self):
        """Uppercase should be normalized to lowercase."""
        assert normalize_npm_name("Server") == "server"
        assert normalize_npm_name("JSONStream") == "jsonstream"

    def test_normalize_scoped_uppercase(self):
        """Scoped package uppercase should be normalized."""
        assert normalize_npm_name("@Azure/Core") == "@azure/core"

    def test_normalize_already_lowercase(self):
        """Lowercase should remain unchanged."""
        assert normalize_npm_name("lodash") == "lodash"

    def test_normalize_empty(self):
        """Empty string should return empty."""
        assert normalize_npm_name("") == ""


class TestPypiValidation:
    """Tests for PyPI package validation."""

    def test_simple_name(self):
        """Simple package name."""
        is_valid, error, normalized = validate_pypi_package_name("requests")
        assert is_valid is True

    def test_mixed_case_normalized(self):
        """Mixed case should be normalized."""
        is_valid, error, normalized = validate_pypi_package_name("Django")
        assert is_valid is True
        assert normalized == "django"

    def test_underscores_normalized(self):
        """Underscores should be normalized to hyphens per PEP 503."""
        is_valid, error, normalized = validate_pypi_package_name("python_dateutil")
        assert is_valid is True
        assert normalized == "python-dateutil"

    def test_path_traversal_rejected(self):
        """Path traversal should fail."""
        is_valid, error, _ = validate_pypi_package_name("../etc/passwd")
        assert is_valid is False
        assert "path traversal" in error

    def test_too_long_rejected(self):
        """Name exceeding 128 chars should fail."""
        is_valid, error, _ = validate_pypi_package_name("a" * 129)
        assert is_valid is False
        assert "too long" in error

    def test_exact_max_length_allowed(self):
        """Name at exactly 128 chars should pass."""
        is_valid, error, normalized = validate_pypi_package_name("a" * 128)
        assert is_valid is True
        assert len(normalized) == 128

    def test_double_dot_in_name_allowed(self):
        """Package names with '..' that aren't path traversal should be allowed."""
        is_valid, error, normalized = validate_pypi_package_name("foo..bar")
        assert is_valid is True
        # PyPI normalizes multiple separators to single hyphen
        assert normalized == "foo-bar"

    def test_empty_name_rejected(self):
        """Empty name should fail."""
        is_valid, error, _ = validate_pypi_package_name("")
        assert is_valid is False
