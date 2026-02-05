"""
Tests for GET /packages/{ecosystem}/{name} endpoint.
"""

import json
import os

import pytest
from moto import mock_aws


class TestGetPackageHandler:
    """Tests for the get_package Lambda handler."""

    @mock_aws
    def test_returns_package_with_valid_api_key(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should return package health data for authenticated request."""
        # Set env vars before import
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "lodash"
        assert body["ecosystem"] == "npm"
        assert body["health_score"] == 85
        assert body["risk_level"] == "LOW"

    @mock_aws
    def test_returns_package_in_demo_mode(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """Should return package data for demo (unauthenticated) request."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        # No API key - should use demo mode

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "lodash"
        assert result["headers"].get("X-Demo-Mode") == "true"

    @mock_aws
    def test_returns_404_for_unknown_package(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should return 404 for packages not in database."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "nonexistent-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404
        body = json.loads(result["body"])
        assert body["error"]["code"] == "package_not_found"

    @mock_aws
    def test_returns_400_for_invalid_ecosystem(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should return 400 for unsupported ecosystem."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "maven", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_ecosystem"

    @mock_aws
    def test_returns_400_for_missing_name(
        self, seeded_api_keys_table, api_gateway_event
    ):
        """Should return 400 when package name is missing."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "missing_parameter"

    @mock_aws
    def test_decodes_url_encoded_package_name(
        self, seeded_api_keys_table, seeded_packages_table, mock_dynamodb, api_gateway_event
    ):
        """Should decode URL-encoded scoped package names."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Add a scoped package
        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#@babel/core",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "@babel/core",
                "health_score": 90,
                "risk_level": "LOW",
                "last_updated": "2024-01-01T00:00:00Z",
                "latest_version": "7.23.0",
                "weekly_downloads": 10000000,
                "data_status": "complete",
                "queryable": True,
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        # URL-encoded @babel/core
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "%40babel%2Fcore"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "@babel/core"

    @mock_aws
    def test_rate_limit_headers_in_response(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should include rate limit headers in response."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert "X-RateLimit-Limit" in result["headers"]
        assert "X-RateLimit-Remaining" in result["headers"]

    @mock_aws
    def test_increments_usage_for_authenticated_requests(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should increment usage counter for authenticated requests."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        # Make two requests
        handler(api_gateway_event, {})
        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        # Check that usage was incremented (remaining should be less)
        remaining = int(result["headers"]["X-RateLimit-Remaining"])
        limit = int(result["headers"]["X-RateLimit-Limit"])
        assert remaining < limit

    @mock_aws
    def test_returns_429_when_authenticated_limit_exceeded(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """Should return 429 when authenticated user exceeds monthly limit."""
        import hashlib

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Create a user that's already at their limit
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_overlimit1234567890"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        table.put_item(
            Item={
                "pk": "user_overlimit",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "overlimit@example.com",
                "tier": "free",
                "requests_this_month": 5000,  # Per-key counter (for analytics)
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        # Add USER_META with requests_this_month at limit (rate limiting is user-level)
        table.put_item(
            Item={
                "pk": "user_overlimit",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 5000,  # At free tier limit
            }
        )

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 429
        body = json.loads(result["body"])
        assert body["error"]["code"] == "rate_limit_exceeded"
        assert "Retry-After" in result["headers"]
        assert result["headers"]["X-RateLimit-Remaining"] == "0"
        assert "upgrade_url" in body["error"]

    @mock_aws
    def test_returns_429_when_demo_limit_exceeded(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """Should return 429 when demo mode IP exceeds hourly limit."""
        from datetime import datetime, timezone

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Seed demo rate limit data to exceed the limit
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        now = datetime.now(timezone.utc)
        current_hour = now.strftime("%Y-%m-%d-%H")
        client_ip = "127.0.0.1"

        table.put_item(
            Item={
                "pk": f"demo#{client_ip}",
                "sk": f"hour#{current_hour}",
                "requests": 21,  # Over the 20/hour demo limit
                "ttl": int(now.timestamp()) + 7200,
            }
        )

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        # No API key - should use demo mode with rate-limited IP

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 429
        body = json.loads(result["body"])
        assert body["error"]["code"] == "demo_rate_limit_exceeded"
        assert "Retry-After" in result["headers"]
        assert result["headers"]["X-RateLimit-Remaining"] == "0"
        assert "signup_url" in body["error"]


class TestDataQualityInGetPackage:
    """Tests for data_quality field in GET /packages response."""

    @mock_aws
    def test_response_includes_data_quality_field(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should include data_quality in successful response."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "data_quality" in body
        assert "assessment" in body["data_quality"]
        assert "status" in body["data_quality"]
        assert "has_repository" in body["data_quality"]
        assert "explanation" in body["data_quality"]
        assert "missing_sources" in body["data_quality"]

    @mock_aws
    def test_data_quality_verified_for_complete_package(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should return VERIFIED assessment for complete data package."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Seed a package with complete data
        packages_table = mock_dynamodb.Table("pkgwatch-packages")
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
                "latest_version": "1.0.0",
                "weekly_downloads": 1000,
                "queryable": True,
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "verified-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["data_quality"]["status"] == "complete"
        assert body["data_quality"]["assessment"] == "VERIFIED"
        assert body["data_quality"]["has_repository"] is True
        assert body["data_quality"]["missing_sources"] == []

    @mock_aws
    def test_data_quality_unverified_for_minimal_package(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should return UNVERIFIED assessment for minimal data package."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Seed a package with minimal data
        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#minimal-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "minimal-pkg",
                "health_score": 40,
                "risk_level": "CRITICAL",
                "data_status": "minimal",
                "missing_sources": ["github", "depsdev"],
                "repository_url": None,
                "last_updated": "2024-01-01T00:00:00Z",
                "latest_version": "1.0.0",
                # queryable=False by default since downloads=0 and status!=complete
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "minimal-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key
        # Use include_incomplete to bypass 202 gate for data quality testing
        api_gateway_event["queryStringParameters"] = {"include_incomplete": "true"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["data_quality"]["status"] == "minimal"
        assert body["data_quality"]["assessment"] == "UNVERIFIED"
        assert body["data_quality"]["has_repository"] is False
        assert "No repository URL" in body["data_quality"]["explanation"]

    @mock_aws
    def test_data_quality_defaults_for_legacy_package(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should return UNVERIFIED for packages without data_status field."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Seed a legacy package without data_status field
        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#legacy-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "legacy-pkg",
                "health_score": 60,
                "risk_level": "MEDIUM",
                # No data_status, no missing_sources, no repository_url
                "last_updated": "2024-01-01T00:00:00Z",
                # queryable not set - defaults to False
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "legacy-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key
        # Use include_incomplete to bypass 202 gate for data quality testing
        api_gateway_event["queryStringParameters"] = {"include_incomplete": "true"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Should default to minimal/UNVERIFIED
        assert body["data_quality"]["status"] == "minimal"
        assert body["data_quality"]["assessment"] == "UNVERIFIED"
        assert body["data_quality"]["has_repository"] is False


class TestDataQualityGate:
    """Tests for the 202 data quality gate (queryable field)."""

    @mock_aws
    def test_returns_202_for_non_queryable_package(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should return 202 for packages with queryable=False."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Seed a package that is not queryable (no downloads, no dependents, status=pending)
        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#new-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "new-pkg",
                "latest_version": "1.0.0",
                "health_score": 50,
                "data_status": "pending",
                "queryable": False,  # Explicitly not queryable
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "new-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 202
        body = json.loads(result["body"])
        assert body["status"] == "collecting"
        assert body["package"] == "new-pkg"
        assert body["data_status"] == "pending"
        assert "Retry-After" in result["headers"]
        # Pending status = short retry (60s) because collection is in progress
        assert result["headers"]["Retry-After"] == "60"
        assert body["retry_after_seconds"] == 60

    @mock_aws
    def test_returns_200_with_include_incomplete_bypass(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should return 200 with include_incomplete=true even for non-queryable packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Seed a package that is not queryable
        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#partial-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "partial-pkg",
                "latest_version": "1.0.0",
                "health_score": 60,
                "risk_level": "MEDIUM",
                "data_status": "partial",
                "queryable": False,
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "partial-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["queryStringParameters"] = {"include_incomplete": "true"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "partial-pkg"
        assert body["health_score"] == 60

    @mock_aws
    def test_returns_200_for_queryable_package(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should return 200 for packages with queryable=True."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        # lodash in seeded_packages_table has queryable=True
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "lodash"

    @mock_aws
    def test_returns_202_with_longer_retry_for_non_pending_status(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should return 202 with longer retry for non-pending statuses."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Seed a package with partial status (not pending)
        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#error-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "error-pkg",
                "latest_version": "1.0.0",
                "health_score": 40,
                "data_status": "partial",  # Non-pending status
                "queryable": False,
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "error-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 202
        body = json.loads(result["body"])
        assert body["status"] == "collecting"
        assert body["data_status"] == "partial"
        # Non-pending status = longer retry (300s) - may need manual intervention
        assert result["headers"]["Retry-After"] == "300"
        assert body["retry_after_seconds"] == 300
