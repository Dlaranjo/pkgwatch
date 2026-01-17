"""
Tests for POST /scan endpoint.
"""

import json
import os

import pytest
from moto import mock_aws


class TestPostScanHandler:
    """Tests for the post_scan Lambda handler."""

    @mock_aws
    def test_scans_package_json_content(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should scan dependencies from package.json content."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        package_json = json.dumps({
            "name": "test-project",
            "dependencies": {"lodash": "^4.17.21"},
        })

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({"content": package_json})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 1
        assert len(body["packages"]) == 1
        assert body["packages"][0]["package"] == "lodash"
        assert body["packages"][0]["health_score"] == 85

    @mock_aws
    def test_scans_direct_dependencies_object(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should scan dependencies from direct object."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21", "abandoned-pkg": "^1.0.0"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 2
        assert len(body["packages"]) == 2
        # Results should be sorted by risk (HIGH first)
        assert body["packages"][0]["risk_level"] == "HIGH"

    @mock_aws
    def test_returns_401_without_api_key(
        self, mock_dynamodb, api_gateway_event
    ):
        """Should return 401 for unauthenticated requests."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_api_key"

    @mock_aws
    def test_returns_400_for_invalid_json(
        self, seeded_api_keys_table, api_gateway_event
    ):
        """Should return 400 for invalid JSON body."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = "not valid json"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_returns_400_for_no_dependencies(
        self, seeded_api_keys_table, api_gateway_event
    ):
        """Should return 400 when no dependencies found."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "no_dependencies"

    @mock_aws
    def test_tracks_not_found_packages(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should track packages not found in database."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21", "unknown-pkg": "^1.0.0"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 2
        assert len(body["packages"]) == 1
        assert "unknown-pkg" in body["not_found"]

    @mock_aws
    def test_counts_risk_levels(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should count packages by risk level."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21", "abandoned-pkg": "^1.0.0"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["low"] == 1
        assert body["high"] == 1
        assert body["critical"] == 0
        assert body["medium"] == 0

    @mock_aws
    def test_includes_rate_limit_headers(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should include rate limit headers in response."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert "X-RateLimit-Limit" in result["headers"]
        assert "X-RateLimit-Remaining" in result["headers"]

    @mock_aws
    def test_handles_dev_dependencies(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should scan devDependencies as well."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        package_json = json.dumps({
            "name": "test-project",
            "dependencies": {},
            "devDependencies": {"lodash": "^4.17.21"},
        })

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({"content": package_json})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 1
        assert body["packages"][0]["package"] == "lodash"


class TestPostScanEcosystem:
    """Tests for ecosystem parameter handling."""

    @mock_aws
    def test_default_ecosystem_is_npm(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should default to npm ecosystem when not specified."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 1
        assert body["packages"][0]["package"] == "lodash"

    @mock_aws
    def test_explicit_npm_ecosystem(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should scan npm packages when ecosystem is explicitly npm."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "ecosystem": "npm",
            "dependencies": {"lodash": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 1
        assert body["packages"][0]["package"] == "lodash"

    @mock_aws
    def test_pypi_ecosystem(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should scan PyPI packages when ecosystem is pypi."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "ecosystem": "pypi",
            "dependencies": {"requests": ">=2.28.0"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 1
        assert body["packages"][0]["package"] == "requests"
        assert body["packages"][0]["health_score"] == 90

    @mock_aws
    def test_pypi_ecosystem_with_multiple_packages(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should correctly count risk levels for PyPI packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "ecosystem": "pypi",
            "dependencies": {"requests": ">=2.28.0", "old-flask-lib": ">=1.0.0"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 2
        assert body["low"] == 1
        assert body["high"] == 1

    @mock_aws
    def test_invalid_ecosystem_returns_400(
        self, seeded_api_keys_table, api_gateway_event
    ):
        """Should return 400 for invalid ecosystem value."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "ecosystem": "invalid",
            "dependencies": {"lodash": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_ecosystem"

    @mock_aws
    def test_ecosystem_case_sensitive(
        self, seeded_api_keys_table, api_gateway_event
    ):
        """Should reject uppercase ecosystem values (case-sensitive)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "ecosystem": "NPM",
            "dependencies": {"lodash": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_ecosystem"

    @mock_aws
    def test_ecosystem_non_string_returns_400(
        self, seeded_api_keys_table, api_gateway_event
    ):
        """Should return 400 when ecosystem is not a string."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "ecosystem": ["npm"],  # Array instead of string
            "dependencies": {"lodash": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_ecosystem"


class TestDataQualityInScan:
    """Tests for data_quality field in POST /scan response."""

    @mock_aws
    def test_scan_includes_data_quality_per_package(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should include data_quality for each scanned package."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert len(body["packages"]) == 1
        pkg = body["packages"][0]
        assert "data_quality" in pkg
        assert "assessment" in pkg["data_quality"]
        assert "has_repository" in pkg["data_quality"]

    @mock_aws
    def test_scan_summary_includes_quality_breakdown(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should include verified/partial/unverified counts in response."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Add packages with different data statuses
        packages_table = mock_dynamodb.Table("pkgwatch-packages")

        # Package with complete data
        packages_table.put_item(
            Item={
                "pk": "npm#verified-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "verified-pkg",
                "health_score": 90,
                "risk_level": "LOW",
                "data_status": "complete",
                "missing_sources": [],
                "repository_url": "https://github.com/owner/repo",
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        # Package with partial data
        packages_table.put_item(
            Item={
                "pk": "npm#partial-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "partial-pkg",
                "health_score": 60,
                "risk_level": "MEDIUM",
                "data_status": "partial",
                "missing_sources": ["github"],
                "repository_url": "https://github.com/owner/repo2",
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        # Package with minimal data
        packages_table.put_item(
            Item={
                "pk": "npm#minimal-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "minimal-pkg",
                "health_score": 30,
                "risk_level": "HIGH",
                "data_status": "minimal",
                "missing_sources": ["github", "depsdev"],
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {
                "verified-pkg": "^1.0.0",
                "partial-pkg": "^1.0.0",
                "minimal-pkg": "^1.0.0",
            },
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "data_quality" in body
        assert body["data_quality"]["verified_count"] == 1
        assert body["data_quality"]["partial_count"] == 1
        assert body["data_quality"]["unverified_count"] == 1
        assert body["data_quality"]["unavailable_count"] == 0

    @mock_aws
    def test_scan_summary_includes_unavailable_count(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should count abandoned_minimal packages as unavailable."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")

        # Package with abandoned_minimal status (exhausted retries)
        packages_table.put_item(
            Item={
                "pk": "npm#abandoned-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "abandoned-pkg",
                "health_score": 20,
                "risk_level": "CRITICAL",
                "data_status": "abandoned_minimal",
                "missing_sources": ["github", "depsdev", "npm"],
                "retry_count": 5,
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"abandoned-pkg": "^1.0.0"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["data_quality"]["unavailable_count"] == 1
        assert body["data_quality"]["verified_count"] == 0
        # UNAVAILABLE risk still counts toward unverified_risk
        assert body["unverified_risk_count"] == 1
        # Check per-package assessment
        pkg = body["packages"][0]
        assert pkg["data_quality"]["assessment"] == "UNAVAILABLE"

    @mock_aws
    def test_scan_counts_verified_vs_unverified_risk(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should separately count verified and unverified HIGH/CRITICAL packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")

        # HIGH risk package with verified data
        packages_table.put_item(
            Item={
                "pk": "npm#verified-high",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "verified-high",
                "health_score": 30,
                "risk_level": "HIGH",
                "data_status": "complete",
                "missing_sources": [],
                "repository_url": "https://github.com/owner/repo",
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        # CRITICAL risk package with unverified data
        packages_table.put_item(
            Item={
                "pk": "npm#unverified-critical",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "unverified-critical",
                "health_score": 20,
                "risk_level": "CRITICAL",
                "data_status": "minimal",
                "missing_sources": ["github"],
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        # LOW risk package with unverified data (should not count in risk counts)
        packages_table.put_item(
            Item={
                "pk": "npm#unverified-low",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "unverified-low",
                "health_score": 70,
                "risk_level": "LOW",
                "data_status": "minimal",
                "missing_sources": ["github"],
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {
                "verified-high": "^1.0.0",
                "unverified-critical": "^1.0.0",
                "unverified-low": "^1.0.0",
            },
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["verified_risk_count"] == 1  # verified-high
        assert body["unverified_risk_count"] == 1  # unverified-critical (not unverified-low)

    @mock_aws
    def test_scan_data_quality_verified_for_complete_package(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should return VERIFIED assessment for packages with complete data."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#complete-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "complete-pkg",
                "health_score": 85,
                "risk_level": "LOW",
                "data_status": "complete",
                "missing_sources": [],
                "repository_url": "https://github.com/owner/repo",
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"complete-pkg": "^1.0.0"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        pkg = body["packages"][0]
        assert pkg["data_quality"]["assessment"] == "VERIFIED"
        assert pkg["data_quality"]["has_repository"] is True

    @mock_aws
    def test_scan_data_quality_unverified_for_legacy_package(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should return UNVERIFIED for packages without data_status field."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # seeded_packages_table adds lodash without data_status field

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        pkg = body["packages"][0]
        # Legacy packages without data_status default to UNVERIFIED
        assert pkg["data_quality"]["assessment"] == "UNVERIFIED"
        assert pkg["data_quality"]["has_repository"] is False

    @mock_aws
    def test_scan_data_quality_partial_with_repo(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should return PARTIAL for packages with partial data and repository."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#partial-repo-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "partial-repo-pkg",
                "health_score": 65,
                "risk_level": "MEDIUM",
                "data_status": "partial",
                "missing_sources": ["github"],
                "repository_url": "https://github.com/owner/repo",
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"partial-repo-pkg": "^1.0.0"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        pkg = body["packages"][0]
        assert pkg["data_quality"]["assessment"] == "PARTIAL"
        assert pkg["data_quality"]["has_repository"] is True
