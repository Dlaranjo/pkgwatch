"""
Shared package name validation utilities.

npm rules:
- Scopes can start with underscore (e.g., @_ndk/motion exists)
- Package names cannot start with . or _ (per npm guidelines)
- Accepts uppercase letters (legacy packages like Server, JSONStream)
- Maximum length: 214 characters
- Case-insensitive: Server and server resolve to same package
"""

import re
from typing import Optional, Tuple

# npm validation regex (CORRECTED):
# - Scope: @[a-z0-9_][a-z0-9._~-]*/ (underscore OK in scope)
# - Package name: [a-z0-9][a-z0-9._~-]* (NO underscore/dot at start)
# - re.IGNORECASE for legacy uppercase packages
NPM_PACKAGE_PATTERN = re.compile(
    r"^(@[a-z0-9_][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.IGNORECASE
)

PYPI_PACKAGE_PATTERN = re.compile(
    r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9])$"
)

MAX_NPM_PACKAGE_LENGTH = 214
MAX_PYPI_PACKAGE_LENGTH = 128


def normalize_npm_name(name: str) -> str:
    """Normalize npm package name to lowercase (npm is case-insensitive)."""
    return name.lower() if name else ""


def validate_npm_package_name(name: str) -> Tuple[bool, Optional[str], str]:
    """
    Validate and normalize an npm package name.

    Returns: (is_valid, error_message, normalized_name)
    """
    if not name:
        return False, "Empty package name", ""

    # Security checks FIRST (before normalization)
    # Check for actual path traversal patterns, not just ".." which can appear in valid names
    if name.startswith("/") or "/../" in name or name.startswith("../") or name.endswith("/.."):
        return False, "Invalid package name (path traversal detected)", ""

    if len(name) > MAX_NPM_PACKAGE_LENGTH:
        return (
            False,
            f"Package name too long: {len(name)} > {MAX_NPM_PACKAGE_LENGTH}",
            "",
        )

    # Normalize to lowercase
    normalized = normalize_npm_name(name)

    # Pattern check (case-insensitive via flag handles original case)
    if not NPM_PACKAGE_PATTERN.match(name):
        return False, "Invalid npm package name format", normalized

    return True, None, normalized


def validate_pypi_package_name(name: str) -> Tuple[bool, Optional[str], str]:
    """Validate and normalize a PyPI package name (PEP 503)."""
    if not name:
        return False, "Empty package name", ""

    # Check for actual path traversal patterns, not just ".." which can appear in valid names
    if name.startswith("/") or "/../" in name or name.startswith("../") or name.endswith("/.."):
        return False, "Invalid package name (path traversal detected)", ""

    if len(name) > MAX_PYPI_PACKAGE_LENGTH:
        return (
            False,
            f"Package name too long: {len(name)} > {MAX_PYPI_PACKAGE_LENGTH}",
            "",
        )

    normalized = re.sub(r"[-_.]+", "-", name.lower())

    if not PYPI_PACKAGE_PATTERN.match(name):
        return False, "Invalid PyPI package name format", normalized

    return True, None, normalized
