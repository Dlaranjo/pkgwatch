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


class TestExtractDependenciesEdgeCases:
    """Tests for _extract_dependencies() edge cases."""

    @mock_aws
    def test_content_not_string_is_ignored(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should ignore content field if not a string."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        # content is an object instead of a string
        api_gateway_event["body"] = json.dumps({
            "content": {"dependencies": {"lodash": "1.0.0"}},
            "dependencies": {"lodash": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Should still find lodash from direct dependencies
        assert body["total"] == 1

    @mock_aws
    def test_dependencies_as_list(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should accept dependencies as a list of package names."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": ["lodash", "abandoned-pkg"],
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 2
        assert len(body["packages"]) == 2

    @mock_aws
    def test_dev_dependencies_as_list(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should accept devDependencies as a list of package names."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "devDependencies": ["lodash"],
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 1

    @mock_aws
    def test_malformed_package_json_content(
        self, seeded_api_keys_table, api_gateway_event
    ):
        """Should handle malformed package.json content gracefully."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "content": "{ invalid json }",
        })

        result = handler(api_gateway_event, {})

        # Should return 400 since no dependencies were extracted
        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "no_dependencies"

    @mock_aws
    def test_package_json_with_non_dict_dependencies(
        self, seeded_api_keys_table, api_gateway_event
    ):
        """Should handle package.json with non-dict dependencies field."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        package_json = json.dumps({
            "name": "test-project",
            "dependencies": "invalid",  # Not a dict
            "devDependencies": 12345,   # Also invalid
        })

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({"content": package_json})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "no_dependencies"

    @mock_aws
    def test_filters_invalid_dependency_entries(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should filter out non-string dependency entries."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": ["lodash", "", None, 123, "abandoned-pkg"],
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Should only have 2 valid deps (lodash, abandoned-pkg)
        assert body["total"] == 2

    @mock_aws
    def test_direct_dev_dependencies_as_dict(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should accept devDependencies as a direct dict in body (not in content)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        # devDependencies as a dict directly in the body (not inside content)
        api_gateway_event["body"] = json.dumps({
            "devDependencies": {"lodash": "^4.17.21", "abandoned-pkg": "^1.0.0"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 2
        assert len(body["packages"]) == 2


class TestRateLimiting:
    """Tests for rate limiting behavior."""

    @mock_aws
    def test_rate_limit_exceeded(
        self, mock_dynamodb, api_gateway_event
    ):
        """Should return 429 when scanning would exceed rate limit."""
        import hashlib

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Create a user with usage near the free tier limit (5000)
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_test_ratelimit"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # API key record
        table.put_item(
            Item={
                "pk": "user_ratelimit",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "ratelimit@example.com",
                "tier": "free",  # Free tier = 5000 limit
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        # USER_META record (where usage is tracked)
        table.put_item(
            Item={
                "pk": "user_ratelimit",
                "sk": "USER_META",
                "requests_this_month": 4999,  # Already used 4999
                "total_packages_scanned": 4999,
            }
        )

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        # Try to scan 3 packages when only 1 request remains
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"pkg1": "1.0", "pkg2": "1.0", "pkg3": "1.0"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 429
        body = json.loads(result["body"])
        assert body["error"]["code"] == "rate_limit_exceeded"


class TestUsageAlerts:
    """Tests for usage alert levels."""

    @mock_aws
    def test_usage_alert_warning_level(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """Should include warning alert when usage is 80-94%."""
        import hashlib

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_test_warning"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # API key record
        table.put_item(
            Item={
                "pk": "user_warning",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "warning@example.com",
                "tier": "free",
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        # USER_META record - Free tier = 5000 limit
        # 4199 + 1 (scan) = 4200 = 84% of 5000
        table.put_item(
            Item={
                "pk": "user_warning",
                "sk": "USER_META",
                "requests_this_month": 4199,
                "total_packages_scanned": 4199,
            }
        )

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "usage_alert" in body
        assert body["usage_alert"]["level"] == "warning"
        assert "X-Usage-Alert" in result["headers"]
        assert result["headers"]["X-Usage-Alert"] == "warning"

    @mock_aws
    def test_usage_alert_critical_level(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """Should include critical alert when usage is 95-99%."""
        import hashlib

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_test_critical"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # API key record
        table.put_item(
            Item={
                "pk": "user_critical",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "critical@example.com",
                "tier": "free",
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        # USER_META record - Free tier = 5000 limit
        # 4799 + 1 (scan) = 4800 = 96% of 5000
        table.put_item(
            Item={
                "pk": "user_critical",
                "sk": "USER_META",
                "requests_this_month": 4799,
                "total_packages_scanned": 4799,
            }
        )

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "usage_alert" in body
        assert body["usage_alert"]["level"] == "critical"
        assert "X-Usage-Alert" in result["headers"]
        assert result["headers"]["X-Usage-Alert"] == "critical"

    @mock_aws
    def test_usage_alert_exceeded_level(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """Should include exceeded alert when usage is 100%."""
        import hashlib

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_test_exceeded"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # API key record
        table.put_item(
            Item={
                "pk": "user_exceeded",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "exceeded@example.com",
                "tier": "free",
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        # USER_META record - Free tier = 5000 limit
        # 4999 + 1 (scan) = 5000 = 100% of 5000
        table.put_item(
            Item={
                "pk": "user_exceeded",
                "sk": "USER_META",
                "requests_this_month": 4999,
                "total_packages_scanned": 4999,
            }
        )

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "usage_alert" in body
        assert body["usage_alert"]["level"] == "exceeded"
        assert "X-Usage-Percent" in result["headers"]


class TestPackageQueueing:
    """Tests for package discovery queueing."""

    @mock_aws
    def test_queues_not_found_packages(
        self, mock_dynamodb, api_gateway_event
    ):
        """Should queue not-found packages for collection when SQS is configured."""
        import hashlib
        import boto3

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Create SQS queue (inside same mock_aws context)
        sqs = boto3.client("sqs", region_name="us-east-1")
        queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        os.environ["PACKAGE_QUEUE_URL"] = queue_url

        # Reset the cached SQS client in post_scan module
        import api.post_scan as post_scan_module
        post_scan_module._sqs = None
        post_scan_module.PACKAGE_QUEUE_URL = queue_url

        # Create API key
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_test_queue"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_queue",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "queue@example.com",
                "tier": "free",
                "requests_this_month": 0,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        # Seed known package
        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "lodash",
                "health_score": 85,
                "risk_level": "LOW",
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {
                "lodash": "^4.17.21",
                "unknown-package-1": "^1.0.0",
                "unknown-package-2": "^2.0.0",
            },
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "discovery" in body
        assert body["discovery"]["queued"] == 2
        assert "2 package(s) queued for collection" in body["discovery"]["message"]

        # Clean up
        del os.environ["PACKAGE_QUEUE_URL"]
        post_scan_module._sqs = None
        post_scan_module.PACKAGE_QUEUE_URL = None

    @mock_aws
    def test_respects_max_queue_limit(
        self, mock_dynamodb, api_gateway_event
    ):
        """Should limit queued packages to MAX_QUEUE_PER_SCAN."""
        import hashlib
        import boto3

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Create SQS queue (inside same mock_aws context)
        sqs = boto3.client("sqs", region_name="us-east-1")
        queue_url = sqs.create_queue(QueueName="test-limit-queue")["QueueUrl"]
        os.environ["PACKAGE_QUEUE_URL"] = queue_url

        # Reset the cached SQS client
        import api.post_scan as post_scan_module
        post_scan_module._sqs = None
        post_scan_module.PACKAGE_QUEUE_URL = queue_url

        # Create user with pro tier (larger limit)
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_test_limit"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_limit",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "limit@example.com",
                "tier": "pro",  # Pro tier = 100000 limit
                "requests_this_month": 0,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        from api.post_scan import handler

        # Generate 60 unknown packages (more than MAX_QUEUE_PER_SCAN=50)
        unknown_deps = {f"unknown-pkg-{i}": "1.0.0" for i in range(60)}

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": unknown_deps,
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "discovery" in body
        # Should be capped at 50
        assert body["discovery"]["queued"] == 50
        assert body["discovery"]["skipped"] == 10

        # Clean up
        del os.environ["PACKAGE_QUEUE_URL"]
        post_scan_module._sqs = None
        post_scan_module.PACKAGE_QUEUE_URL = None

    @mock_aws
    def test_no_discovery_when_queue_not_configured(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should not include discovery field when PACKAGE_QUEUE_URL not set."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ.pop("PACKAGE_QUEUE_URL", None)

        # Reset the module-level variable
        import api.post_scan as post_scan_module
        post_scan_module.PACKAGE_QUEUE_URL = None
        post_scan_module._sqs = None

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"unknown-package": "^1.0.0"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "discovery" not in body


class TestPackageNameValidation:
    """Tests for package name validation in queueing."""

    @mock_aws
    def test_filters_invalid_npm_package_names(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should filter out invalid npm package names when queueing."""
        import boto3

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        sqs = boto3.client("sqs", region_name="us-east-1")
        queue_url = sqs.create_queue(QueueName="test-validate-queue")["QueueUrl"]
        os.environ["PACKAGE_QUEUE_URL"] = queue_url

        import api.post_scan as post_scan_module
        post_scan_module._sqs = None
        post_scan_module.PACKAGE_QUEUE_URL = queue_url

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {
                "valid-package": "1.0.0",
                "../path-traversal": "1.0.0",  # Invalid
                "_starts-with-underscore": "1.0.0",  # Invalid
                ".starts-with-dot": "1.0.0",  # Invalid
            },
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # All 4 are not found, but only 1 is valid for queueing
        assert len(body["not_found"]) == 4
        if "discovery" in body:
            assert body["discovery"]["queued"] == 1  # Only valid-package

        del os.environ["PACKAGE_QUEUE_URL"]
        post_scan_module._sqs = None

    @mock_aws
    def test_validates_pypi_package_names(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should validate PyPI package names for queueing."""
        import boto3

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        sqs = boto3.client("sqs", region_name="us-east-1")
        queue_url = sqs.create_queue(QueueName="test-pypi-queue")["QueueUrl"]
        os.environ["PACKAGE_QUEUE_URL"] = queue_url

        import api.post_scan as post_scan_module
        post_scan_module._sqs = None
        post_scan_module.PACKAGE_QUEUE_URL = queue_url

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "ecosystem": "pypi",
            "dependencies": {
                "valid-pypi-pkg": "1.0.0",
                "../invalid-path": "1.0.0",
            },
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert len(body["not_found"]) == 2
        if "discovery" in body:
            assert body["discovery"]["queued"] == 1

        del os.environ["PACKAGE_QUEUE_URL"]
        post_scan_module._sqs = None


class TestIsValidPackageName:
    """Tests for _is_valid_package_name helper function."""

    def test_invalid_name_empty(self):
        """Should return False for empty name."""
        from api.post_scan import _is_valid_package_name

        is_valid, normalized = _is_valid_package_name("", "npm")
        assert is_valid is False
        assert normalized == ""

    def test_invalid_name_none(self):
        """Should return False for None name."""
        from api.post_scan import _is_valid_package_name

        is_valid, normalized = _is_valid_package_name(None, "npm")
        assert is_valid is False
        assert normalized == ""

    def test_invalid_name_not_string(self):
        """Should return False for non-string name."""
        from api.post_scan import _is_valid_package_name

        is_valid, normalized = _is_valid_package_name(123, "npm")
        assert is_valid is False
        assert normalized == ""

    def test_invalid_ecosystem(self):
        """Should return False for unknown ecosystem."""
        from api.post_scan import _is_valid_package_name

        is_valid, normalized = _is_valid_package_name("valid-pkg", "rubygems")
        assert is_valid is False
        assert normalized == ""

    def test_valid_npm_name(self):
        """Should return True and normalized name for valid npm package."""
        from api.post_scan import _is_valid_package_name

        is_valid, normalized = _is_valid_package_name("Lodash", "npm")
        assert is_valid is True
        assert normalized == "lodash"

    def test_valid_pypi_name(self):
        """Should return True and normalized name for valid PyPI package."""
        from api.post_scan import _is_valid_package_name

        is_valid, normalized = _is_valid_package_name("Flask-RESTful", "pypi")
        assert is_valid is True
        assert normalized == "flask-restful"


class TestGetResetTimestamp:
    """Tests for get_reset_timestamp function."""

    def test_returns_integer_timestamp(self):
        """Should return an integer Unix timestamp."""
        from api.post_scan import get_reset_timestamp

        timestamp = get_reset_timestamp()
        assert isinstance(timestamp, int)
        assert timestamp > 0

    def test_timestamp_is_in_future(self):
        """Should return a timestamp in the future."""
        import time
        from api.post_scan import get_reset_timestamp

        timestamp = get_reset_timestamp()
        assert timestamp > int(time.time())


class TestCheckUsageAlerts:
    """Tests for check_usage_alerts function."""

    def test_no_alert_below_80_percent(self):
        """Should return None when usage is below 80%."""
        from api.post_scan import check_usage_alerts

        user = {"monthly_limit": 1000}
        result = check_usage_alerts(user, 790)  # 79%
        assert result is None

    def test_warning_at_80_percent(self):
        """Should return warning at 80% usage."""
        from api.post_scan import check_usage_alerts

        user = {"monthly_limit": 1000}
        result = check_usage_alerts(user, 800)  # 80%
        assert result is not None
        assert result["level"] == "warning"
        assert result["percent"] == 80.0

    def test_critical_at_95_percent(self):
        """Should return critical at 95% usage."""
        from api.post_scan import check_usage_alerts

        user = {"monthly_limit": 1000}
        result = check_usage_alerts(user, 950)  # 95%
        assert result is not None
        assert result["level"] == "critical"
        assert result["percent"] == 95.0

    def test_exceeded_at_100_percent(self):
        """Should return exceeded at 100% usage."""
        from api.post_scan import check_usage_alerts

        user = {"monthly_limit": 1000}
        result = check_usage_alerts(user, 1000)  # 100%
        assert result is not None
        assert result["level"] == "exceeded"
        assert result["percent"] == 100

    def test_exceeded_over_100_percent(self):
        """Should return exceeded when over 100% usage."""
        from api.post_scan import check_usage_alerts

        user = {"monthly_limit": 1000}
        result = check_usage_alerts(user, 1100)  # 110%
        assert result is not None
        assert result["level"] == "exceeded"

    def test_zero_limit_returns_exceeded(self):
        """Should return exceeded when limit is 0."""
        from api.post_scan import check_usage_alerts

        user = {"monthly_limit": 0}
        result = check_usage_alerts(user, 1)
        assert result is not None
        assert result["level"] == "exceeded"


class TestMediumRiskCounting:
    """Tests for MEDIUM risk level counting."""

    @mock_aws
    def test_counts_medium_risk_packages(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should correctly count MEDIUM risk packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#medium-risk-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "medium-risk-pkg",
                "health_score": 55,
                "risk_level": "MEDIUM",
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"medium-risk-pkg": "^1.0.0"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["medium"] == 1
        assert body["high"] == 0
        assert body["critical"] == 0
        assert body["low"] == 0


class TestCriticalRiskCounting:
    """Tests for CRITICAL risk level counting."""

    @mock_aws
    def test_counts_critical_risk_packages(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should correctly count CRITICAL risk packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#critical-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "critical-pkg",
                "health_score": 10,
                "risk_level": "CRITICAL",
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"critical-pkg": "^1.0.0"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["critical"] == 1


class TestNpmCaseInsensitivity:
    """Tests for npm package name case-insensitivity."""

    @mock_aws
    def test_normalizes_uppercase_npm_names(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should normalize uppercase npm package names to lowercase for lookup."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        # Use uppercase "LODASH" - should find "lodash" in DB
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"LODASH": "^4.17.21"},
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert len(body["packages"]) == 1
        assert body["packages"][0]["package"] == "lodash"


class TestNullBody:
    """Tests for handling null/None request body."""

    @mock_aws
    def test_handles_null_body(
        self, seeded_api_keys_table, api_gateway_event
    ):
        """Should handle null body gracefully."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = None

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "no_dependencies"


class TestQueueingEdgeCases:
    """Tests for edge cases in package queueing."""

    @mock_aws
    def test_all_invalid_packages_returns_zero_queued(
        self, mock_dynamodb, api_gateway_event
    ):
        """Should return 0 queued when all packages are invalid."""
        import hashlib
        import boto3

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Create SQS queue
        sqs = boto3.client("sqs", region_name="us-east-1")
        queue_url = sqs.create_queue(QueueName="test-invalid-queue")["QueueUrl"]
        os.environ["PACKAGE_QUEUE_URL"] = queue_url

        import api.post_scan as post_scan_module
        post_scan_module._sqs = None
        post_scan_module.PACKAGE_QUEUE_URL = queue_url

        # Create user
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_test_invalid"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_invalid",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "invalid@example.com",
                "tier": "free",
                "requests_this_month": 0,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        # All invalid package names
        api_gateway_event["body"] = json.dumps({
            "dependencies": {
                "../invalid1": "1.0.0",
                "_invalid2": "1.0.0",
                ".invalid3": "1.0.0",
            },
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # All packages not found
        assert len(body["not_found"]) == 3
        # But none queued because all invalid
        assert "discovery" not in body

        del os.environ["PACKAGE_QUEUE_URL"]
        post_scan_module._sqs = None
        post_scan_module.PACKAGE_QUEUE_URL = None


class TestDecemberMonthHandling:
    """Tests for December month edge case in reset timestamp."""

    def test_december_to_january_transition(self):
        """Should handle year boundary when current month is December."""
        from unittest.mock import patch
        from datetime import datetime, timezone
        from api.post_scan import get_reset_timestamp

        # Mock datetime to December 15
        mock_now = datetime(2025, 12, 15, 10, 30, 0, tzinfo=timezone.utc)
        with patch("api.post_scan.datetime") as mock_datetime:
            mock_datetime.now.return_value = mock_now
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

            timestamp = get_reset_timestamp()

            # Should be January 1, 2026
            expected = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
            assert timestamp == int(expected.timestamp())


class TestSQSErrorHandling:
    """Tests for SQS error handling during queueing."""

    @mock_aws
    def test_sqs_error_is_handled_gracefully(
        self, mock_dynamodb, api_gateway_event
    ):
        """Should handle SQS errors gracefully without failing the request."""
        import hashlib
        import boto3
        from unittest.mock import patch, MagicMock

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Don't actually create the queue - we'll mock the error
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123456789/fake-queue"

        import api.post_scan as post_scan_module
        # Create a mock SQS client that raises an exception
        mock_sqs = MagicMock()
        mock_sqs.send_message_batch.side_effect = Exception("SQS error")
        post_scan_module._sqs = mock_sqs
        post_scan_module.PACKAGE_QUEUE_URL = os.environ["PACKAGE_QUEUE_URL"]

        # Create user
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_test_sqs_error"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_sqs_error",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "sqserror@example.com",
                "tier": "free",
                "requests_this_month": 0,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"unknown-pkg": "1.0.0"},
        })

        result = handler(api_gateway_event, {})

        # Should still return 200 - SQS errors shouldn't fail the request
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "unknown-pkg" in body["not_found"]
        # Discovery won't be in response since queueing failed
        # (queued_count remains 0)

        del os.environ["PACKAGE_QUEUE_URL"]
        post_scan_module._sqs = None
        post_scan_module.PACKAGE_QUEUE_URL = None


class TestDynamoDBErrorHandling:
    """Tests for DynamoDB error handling during batch fetch."""

    @mock_aws
    def test_batch_fetch_error_marks_packages_as_not_found(
        self, mock_dynamodb, api_gateway_event
    ):
        """Should handle DynamoDB errors gracefully by marking packages as not found."""
        import hashlib
        from unittest.mock import patch, MagicMock
        from botocore.exceptions import ClientError

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Create user
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_test_ddb_error"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_ddb_error",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "ddberror@example.com",
                "tier": "free",
                "requests_this_month": 0,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        from api.post_scan import handler

        # Mock the dynamodb resource to raise an error during batch_get_item
        with patch("api.post_scan.dynamodb") as mock_ddb:
            mock_resource = MagicMock()
            mock_resource.batch_get_item.side_effect = Exception("DynamoDB error")
            mock_ddb.batch_get_item = mock_resource.batch_get_item

            api_gateway_event["httpMethod"] = "POST"
            api_gateway_event["headers"]["x-api-key"] = test_key
            api_gateway_event["body"] = json.dumps({
                "dependencies": {"some-pkg": "1.0.0"},
            })

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Package should be in not_found list
        assert "some-pkg" in body["not_found"]