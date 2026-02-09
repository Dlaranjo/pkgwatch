"""
Tests for GET /packages/{ecosystem}/{name} endpoint.
"""

import json
import os

from moto import mock_aws


class TestGetPackageHandler:
    """Tests for the get_package Lambda handler."""

    @mock_aws
    def test_returns_package_with_valid_api_key(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
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
    def test_returns_package_in_demo_mode(self, mock_dynamodb, seeded_packages_table, api_gateway_event):
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
    def test_returns_404_for_unknown_package(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
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
    def test_returns_400_for_invalid_ecosystem(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
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
    def test_returns_400_for_missing_name(self, seeded_api_keys_table, api_gateway_event):
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
    def test_rate_limit_headers_in_response(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
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
    def test_returns_429_when_demo_limit_exceeded(self, mock_dynamodb, seeded_packages_table, api_gateway_event):
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
    def test_data_quality_verified_for_complete_package(self, seeded_api_keys_table, mock_dynamodb, api_gateway_event):
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
    def test_data_quality_unverified_for_minimal_package(self, seeded_api_keys_table, mock_dynamodb, api_gateway_event):
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
    def test_data_quality_defaults_for_legacy_package(self, seeded_api_keys_table, mock_dynamodb, api_gateway_event):
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
    def test_returns_202_for_non_queryable_package(self, seeded_api_keys_table, mock_dynamodb, api_gateway_event):
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
    def test_returns_200_with_include_incomplete_bypass(self, seeded_api_keys_table, mock_dynamodb, api_gateway_event):
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
    def test_returns_200_for_queryable_package(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
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


class TestGetClientIp:
    """Tests for _get_client_ip helper (lines 85-86 uncovered)."""

    def test_returns_source_ip_from_request_context(self):
        """Should return sourceIp when present in requestContext."""
        from api.get_package import _get_client_ip

        event = {"requestContext": {"identity": {"sourceIp": "203.0.113.42"}}}
        assert _get_client_ip(event) == "203.0.113.42"

    def test_returns_unknown_when_source_ip_missing(self):
        """Should return 'unknown' and log warning when sourceIp is missing (lines 85-86)."""
        from api.get_package import _get_client_ip

        # No requestContext at all
        event = {}
        assert _get_client_ip(event) == "unknown"

    def test_returns_unknown_when_identity_missing(self):
        """Should return 'unknown' when identity block is missing."""
        from api.get_package import _get_client_ip

        event = {"requestContext": {}}
        assert _get_client_ip(event) == "unknown"

    def test_returns_unknown_when_source_ip_is_none(self):
        """Should return 'unknown' when sourceIp is explicitly None."""
        from api.get_package import _get_client_ip

        event = {"requestContext": {"identity": {"sourceIp": None}}}
        assert _get_client_ip(event) == "unknown"

    @mock_aws
    def test_demo_mode_with_missing_source_ip(self, mock_dynamodb, seeded_packages_table, api_gateway_event):
        """Should use 'unknown' IP for demo rate limiting when sourceIp is missing."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        # Remove the sourceIp from requestContext
        api_gateway_event["requestContext"] = {"identity": {}}
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        # No API key - demo mode

        result = handler(api_gateway_event, {})

        # Should still work in demo mode using "unknown" as IP
        assert result["statusCode"] == 200
        assert result["headers"].get("X-Demo-Mode") == "true"


class TestFormatOpenSSFChecks:
    """Tests for _format_openssf_checks (lines 110-128 uncovered)."""

    def test_empty_checks_returns_empty_structure(self):
        """Should return empty summary and all_checks for empty list."""
        from api.get_package import _format_openssf_checks

        result = _format_openssf_checks([])
        assert result == {"summary": {}, "all_checks": []}

    def test_none_checks_returns_empty_structure(self):
        """Should handle None gracefully."""
        from api.get_package import _format_openssf_checks

        result = _format_openssf_checks(None)
        assert result == {"summary": {}, "all_checks": []}

    def test_formats_key_check_pass(self):
        """Should mark key checks with score >= 8 as pass."""
        from api.get_package import _format_openssf_checks

        checks = [
            {"name": "Code-Review", "score": 9, "reason": "Found code reviews"},
        ]
        result = _format_openssf_checks(checks)

        assert len(result["all_checks"]) == 1
        assert result["all_checks"][0]["name"] == "Code-Review"
        assert result["all_checks"][0]["score"] == 9
        assert result["all_checks"][0]["reason"] == "Found code reviews"

        assert "Code-Review" in result["summary"]
        assert result["summary"]["Code-Review"]["score"] == 9
        assert result["summary"]["Code-Review"]["status"] == "pass"

    def test_formats_key_check_partial(self):
        """Should mark key checks with score 5-7 as partial."""
        from api.get_package import _format_openssf_checks

        checks = [
            {"name": "Branch-Protection", "score": 6, "reason": "Partial protection"},
        ]
        result = _format_openssf_checks(checks)

        assert result["summary"]["Branch-Protection"]["status"] == "partial"
        assert result["summary"]["Branch-Protection"]["score"] == 6

    def test_formats_key_check_fail(self):
        """Should mark key checks with score < 5 as fail."""
        from api.get_package import _format_openssf_checks

        checks = [
            {"name": "Signed-Releases", "score": 2, "reason": "No signed releases"},
        ]
        result = _format_openssf_checks(checks)

        assert result["summary"]["Signed-Releases"]["status"] == "fail"
        assert result["summary"]["Signed-Releases"]["score"] == 2

    def test_non_key_check_not_in_summary(self):
        """Should not include non-key checks in summary."""
        from api.get_package import _format_openssf_checks

        checks = [
            {"name": "Fuzzing", "score": 10, "reason": "Fuzzing enabled"},
        ]
        result = _format_openssf_checks(checks)

        # Should be in all_checks but NOT in summary
        assert len(result["all_checks"]) == 1
        assert result["all_checks"][0]["name"] == "Fuzzing"
        assert "Fuzzing" not in result["summary"]

    def test_multiple_checks_with_mixed_statuses(self):
        """Should correctly classify all key checks by score threshold."""
        from api.get_package import _format_openssf_checks

        checks = [
            {"name": "Code-Review", "score": 10, "reason": "All reviewed"},
            {"name": "Branch-Protection", "score": 5, "reason": "Basic"},
            {"name": "Security-Policy", "score": 3, "reason": "No policy"},
            {"name": "Vulnerabilities", "score": 8, "reason": "No vulns"},
            {"name": "Dependency-Update-Tool", "score": 0, "reason": "None found"},
            {"name": "Fuzzing", "score": 10, "reason": "OSS-Fuzz"},
        ]
        result = _format_openssf_checks(checks)

        assert len(result["all_checks"]) == 6
        assert len(result["summary"]) == 5  # 5 key checks (Fuzzing excluded)

        assert result["summary"]["Code-Review"]["status"] == "pass"
        assert result["summary"]["Branch-Protection"]["status"] == "partial"
        assert result["summary"]["Security-Policy"]["status"] == "fail"
        assert result["summary"]["Vulnerabilities"]["status"] == "pass"
        assert result["summary"]["Dependency-Update-Tool"]["status"] == "fail"

    def test_check_with_missing_fields_uses_defaults(self):
        """Should handle checks with missing name, score, or reason."""
        from api.get_package import _format_openssf_checks

        checks = [
            {},  # Empty check
            {"name": "Code-Review"},  # Missing score and reason
        ]
        result = _format_openssf_checks(checks)

        assert len(result["all_checks"]) == 2
        # Empty check: name defaults to "", score defaults to 0
        assert result["all_checks"][0]["name"] == ""
        assert result["all_checks"][0]["score"] == 0
        assert result["all_checks"][0]["reason"] == ""

        # Code-Review with score=0 (default) should be "fail"
        assert result["summary"]["Code-Review"]["status"] == "fail"
        assert result["summary"]["Code-Review"]["score"] == 0

    def test_boundary_scores(self):
        """Should handle exact boundary scores correctly (5 and 8)."""
        from api.get_package import _format_openssf_checks

        checks = [
            {"name": "Code-Review", "score": 8, "reason": "Boundary pass"},
            {"name": "Branch-Protection", "score": 7, "reason": "Below pass"},
            {"name": "Security-Policy", "score": 5, "reason": "Boundary partial"},
            {"name": "Vulnerabilities", "score": 4, "reason": "Below partial"},
        ]
        result = _format_openssf_checks(checks)

        assert result["summary"]["Code-Review"]["status"] == "pass"  # 8 >= 8 -> pass
        assert result["summary"]["Branch-Protection"]["status"] == "partial"  # 7 >= 5, < 8 -> partial
        assert result["summary"]["Security-Policy"]["status"] == "partial"  # 5 >= 5 -> partial
        assert result["summary"]["Vulnerabilities"]["status"] == "fail"  # 4 < 5 -> fail


class TestDemoRateLimitGenericException:
    """Tests for generic exception in _check_demo_rate_limit (lines 185-188)."""

    @mock_aws
    def test_generic_exception_returns_false(self, mock_dynamodb, seeded_packages_table, api_gateway_event):
        """Should fail closed (deny access) on unexpected errors (lines 185-188)."""
        from unittest.mock import patch

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import _check_demo_rate_limit

        # Patch get_dynamodb to raise a non-ClientError exception
        with patch("api.get_package.get_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value.update_item.side_effect = RuntimeError(
                "Unexpected connection error"
            )
            allowed, remaining = _check_demo_rate_limit("192.168.1.1")

        # Should fail closed (deny) on generic errors
        assert allowed is False
        assert remaining == 0

    @mock_aws
    def test_handler_returns_429_on_generic_demo_error(self, mock_dynamodb, seeded_packages_table, api_gateway_event):
        """Should return 429 when demo rate limiting encounters unexpected error."""
        from unittest.mock import patch

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        # No API key = demo mode

        with patch("api.get_package._check_demo_rate_limit", return_value=(False, 0)):
            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 429
        body = json.loads(result["body"])
        assert body["error"]["code"] == "demo_rate_limit_exceeded"


class TestUsageAlertsInGetPackage:
    """Tests for usage alert headers in authenticated response (lines 380-383)."""

    @mock_aws
    def test_warning_alert_in_response(self, mock_dynamodb, seeded_packages_table, api_gateway_event):
        """Should include usage_alert in response when usage exceeds 80%."""
        import hashlib

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_test_gp_warning"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        table.put_item(
            Item={
                "pk": "user_gp_warning",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "gpwarning@example.com",
                "tier": "free",
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )
        # 4199 + 1 = 4200 = 84% of 5000
        table.put_item(
            Item={
                "pk": "user_gp_warning",
                "sk": "USER_META",
                "requests_this_month": 4199,
                "total_packages_scanned": 4199,
            }
        )

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        # Lines 380-383: Usage alert headers and body
        assert "X-Usage-Alert" in result["headers"]
        assert result["headers"]["X-Usage-Alert"] == "warning"
        assert "X-Usage-Percent" in result["headers"]
        assert "usage_alert" in body
        assert body["usage_alert"]["level"] == "warning"

    @mock_aws
    def test_critical_alert_in_response(self, mock_dynamodb, seeded_packages_table, api_gateway_event):
        """Should include critical alert when usage exceeds 95%."""
        import hashlib

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_test_gp_critical"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        table.put_item(
            Item={
                "pk": "user_gp_critical",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "gpcritical@example.com",
                "tier": "free",
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )
        # 4799 + 1 = 4800 = 96% of 5000
        table.put_item(
            Item={
                "pk": "user_gp_critical",
                "sk": "USER_META",
                "requests_this_month": 4799,
                "total_packages_scanned": 4799,
            }
        )

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        assert result["headers"]["X-Usage-Alert"] == "critical"
        assert "usage_alert" in body
        assert body["usage_alert"]["level"] == "critical"
        assert "percent" in body["usage_alert"]
        assert "message" in body["usage_alert"]

    @mock_aws
    def test_no_alert_below_80_percent(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """Should NOT include usage_alert when usage is below 80%."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "usage_alert" not in body
        assert "X-Usage-Alert" not in result["headers"]


class TestCORSInRateLimitResponses:
    """Tests for CORS headers in rate limit responses (lines 407, 432)."""

    @mock_aws
    def test_authenticated_rate_limit_includes_cors_headers(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """Should include CORS headers in 429 response for authenticated requests (line 407)."""
        import hashlib

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["ALLOW_DEV_CORS"] = "true"

        # Reload to pick up ALLOW_DEV_CORS
        import importlib

        import api.get_package as gp_module

        importlib.reload(gp_module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_test_cors_auth"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        table.put_item(
            Item={
                "pk": "user_cors_auth",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "corsauth@example.com",
                "tier": "free",
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )
        table.put_item(
            Item={
                "pk": "user_cors_auth",
                "sk": "USER_META",
                "requests_this_month": 5000,
            }
        )

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["headers"]["origin"] = "https://pkgwatch.dev"

        result = gp_module.handler(api_gateway_event, {})

        assert result["statusCode"] == 429
        # Line 407: cors_headers should be merged into response headers
        assert result["headers"].get("Access-Control-Allow-Origin") == "https://pkgwatch.dev"

        # Clean up
        os.environ.pop("ALLOW_DEV_CORS", None)

    @mock_aws
    def test_demo_rate_limit_includes_cors_headers(self, mock_dynamodb, seeded_packages_table, api_gateway_event):
        """Should include CORS headers in 429 demo response (line 432)."""
        from datetime import datetime, timezone

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        now = datetime.now(timezone.utc)
        current_hour = now.strftime("%Y-%m-%d-%H")

        # Seed demo rate limit to trigger 429
        table.put_item(
            Item={
                "pk": "demo#127.0.0.1",
                "sk": f"hour#{current_hour}",
                "requests": 21,
                "ttl": int(now.timestamp()) + 7200,
            }
        )

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["origin"] = "https://pkgwatch.dev"
        # No API key - demo mode

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 429
        # Line 432: cors_headers should be merged into demo rate limit response
        assert result["headers"].get("Access-Control-Allow-Origin") == "https://pkgwatch.dev"


class TestResponseBodyCompleteness:
    """Tests to verify response body contains all expected fields."""

    @mock_aws
    def test_response_contains_all_signal_fields(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """Should include all signal fields in the response."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        # Core fields
        assert "package" in body
        assert "ecosystem" in body
        assert "health_score" in body
        assert "risk_level" in body
        assert "abandonment_risk" in body
        assert "components" in body
        assert "confidence" in body
        assert "latest_version" in body
        assert "last_published" in body
        assert "repository_url" in body
        assert "last_updated" in body
        assert "data_quality" in body
        assert "advisories" in body
        assert "openssf_checks" in body

        # Signals substructure
        signals = body["signals"]
        assert "weekly_downloads" in signals
        assert "dependents_count" in signals
        assert "stars" in signals
        assert "days_since_last_commit" in signals
        assert "commits_90d" in signals
        assert "active_contributors_90d" in signals
        assert "maintainer_count" in signals
        assert "is_deprecated" in signals
        assert "archived" in signals
        assert "openssf_score" in signals
        assert "true_bus_factor" in signals
        assert "bus_factor_confidence" in signals

    @mock_aws
    def test_true_bus_factor_defaults(self, seeded_api_keys_table, mock_dynamodb, api_gateway_event):
        """Should default true_bus_factor to 1 and bus_factor_confidence to LOW."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#no-bus-factor",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "no-bus-factor",
                "health_score": 70,
                "risk_level": "LOW",
                "last_updated": "2024-01-01T00:00:00Z",
                "latest_version": "1.0.0",
                "data_status": "complete",
                "queryable": True,
                # No true_bus_factor or bus_factor_confidence fields
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "no-bus-factor"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["signals"]["true_bus_factor"] == 1
        assert body["signals"]["bus_factor_confidence"] == "LOW"


class TestOpenSSFChecksIntegration:
    """Tests for openssf_checks in API response (integrating _format_openssf_checks)."""

    @mock_aws
    def test_package_with_openssf_checks_formatted_in_response(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Should format openssf_checks from DynamoDB data into API response."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#openssf-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "openssf-pkg",
                "health_score": 80,
                "risk_level": "LOW",
                "last_updated": "2024-01-01T00:00:00Z",
                "latest_version": "2.0.0",
                "data_status": "complete",
                "queryable": True,
                "openssf_checks": [
                    {"name": "Code-Review", "score": 10, "reason": "Reviewed"},
                    {"name": "Security-Policy", "score": 3, "reason": "No policy"},
                    {"name": "Fuzzing", "score": 8, "reason": "OSS-Fuzz"},
                ],
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "openssf-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        openssf = body["openssf_checks"]
        assert len(openssf["all_checks"]) == 3
        assert openssf["summary"]["Code-Review"]["status"] == "pass"
        assert openssf["summary"]["Security-Policy"]["status"] == "fail"
        assert "Fuzzing" not in openssf["summary"]


class TestPyPIPackageLookup:
    """Tests for PyPI package lookup via GET endpoint."""

    @mock_aws
    def test_returns_pypi_package(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """Should return PyPI package data correctly."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "pypi", "name": "requests"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "requests"
        assert body["ecosystem"] == "pypi"
        assert body["health_score"] == 90
        assert body["risk_level"] == "LOW"


class TestNullAndMissingPathParameters:
    """Tests for null/missing pathParameters edge cases."""

    @mock_aws
    def test_handles_null_path_parameters(self, seeded_api_keys_table, api_gateway_event):
        """Should handle None pathParameters gracefully."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = None
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        # Should return 400 because name is missing
        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "missing_parameter"

    @mock_aws
    def test_handles_missing_path_parameters_key(self, seeded_api_keys_table, api_gateway_event):
        """Should handle missing pathParameters key entirely."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        # Remove pathParameters from event entirely
        if "pathParameters" in api_gateway_event:
            del api_gateway_event["pathParameters"]
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "missing_parameter"


class TestDemoModeRateLimitHeaders:
    """Tests for demo mode rate limit headers in successful responses."""

    @mock_aws
    def test_demo_mode_includes_hourly_reset_header(self, mock_dynamodb, seeded_packages_table, api_gateway_event):
        """Should include X-RateLimit-Reset header with hourly reset timestamp."""
        import time

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        # No API key = demo mode

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        headers = result["headers"]
        assert headers["X-Demo-Mode"] == "true"
        assert "X-RateLimit-Limit" in headers
        assert headers["X-RateLimit-Limit"] == "20"
        assert "X-RateLimit-Remaining" in headers
        assert "X-RateLimit-Reset" in headers
        # Reset should be in the future
        reset_ts = int(headers["X-RateLimit-Reset"])
        assert reset_ts > int(time.time())


class TestDynamoDBErrorInGetPackage:
    """Tests for DynamoDB error handling in handler."""

    @mock_aws
    def test_returns_500_on_dynamodb_error(self, seeded_api_keys_table, api_gateway_event):
        """Should return 500 when DynamoDB fetch fails."""
        from unittest.mock import MagicMock, patch

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        # Patch get_dynamodb to return a table that raises on get_item
        with patch("api.get_package.get_dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_table.get_item.side_effect = Exception("DynamoDB connection timeout")
            mock_ddb.return_value.Table.return_value = mock_table

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"


class TestNpmCaseNormalization:
    """Tests for npm package name case normalization."""

    @mock_aws
    def test_normalizes_uppercase_npm_name(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """Should normalize uppercase npm package name to lowercase for lookup."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        # Use uppercase "LODASH" - should find "lodash" in DB
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "LODASH"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "lodash"

    @mock_aws
    def test_normalizes_pypi_name(self, seeded_api_keys_table, mock_dynamodb, api_gateway_event):
        """Should normalize PyPI package names per PEP 503."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Store with normalized name (lowercase, hyphens)
        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "pypi#flask",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "flask",
                "health_score": 85,
                "risk_level": "LOW",
                "last_updated": "2024-01-01T00:00:00Z",
                "latest_version": "3.0.0",
                "data_status": "complete",
                "queryable": True,
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        # Request with mixed case — should normalize to "flask"
        api_gateway_event["pathParameters"] = {"ecosystem": "pypi", "name": "Flask"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "flask"


class TestQueryableFieldFallback:
    """Tests for queryable field fallback logic (computed on-the-fly for pre-migration packages)."""

    @mock_aws
    def test_computes_queryable_for_premigration_package(self, seeded_api_keys_table, mock_dynamodb, api_gateway_event):
        """Should compute queryable on-the-fly when field is not set."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#premigration-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "premigration-pkg",
                "health_score": 75,
                "risk_level": "LOW",
                "last_updated": "2024-01-01T00:00:00Z",
                "latest_version": "1.0.0",
                "weekly_downloads": 5000,
                "data_status": "complete",
                # No queryable field - should be computed as True
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "premigration-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        # Should return 200 because computed queryable = True
        # (has latest_version, health_score, and weekly_downloads > 0)
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "premigration-pkg"


class TestGetPackageResponseSchema:
    """Tests verifying exact response JSON schema (field names, types, nesting)."""

    @mock_aws
    def test_200_response_has_exact_top_level_fields(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """200 response must contain exactly the expected top-level keys."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        expected_keys = {
            "package",
            "ecosystem",
            "health_score",
            "risk_level",
            "abandonment_risk",
            "components",
            "confidence",
            "signals",
            "openssf_checks",
            "advisories",
            "latest_version",
            "last_published",
            "repository_url",
            "last_updated",
            "data_quality",
            "feedback_url",
        }
        actual_keys = set(body.keys())
        # The only extra key allowed is usage_alert (present when near limit)
        assert expected_keys.issubset(actual_keys), f"Missing keys: {expected_keys - actual_keys}"

    @mock_aws
    def test_200_response_field_types(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """200 response fields must have the correct types."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        body = json.loads(result["body"])

        assert isinstance(body["package"], str)
        assert isinstance(body["ecosystem"], str)
        assert isinstance(body["health_score"], (int, float, type(None)))
        assert isinstance(body["risk_level"], (str, type(None)))
        assert isinstance(body["signals"], dict)
        assert isinstance(body["openssf_checks"], dict)
        assert isinstance(body["advisories"], list)
        assert isinstance(body["data_quality"], dict)
        assert isinstance(body["feedback_url"], str)

    @mock_aws
    def test_signals_substructure_types(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """Signals substructure must have the correct field types."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        body = json.loads(result["body"])
        signals = body["signals"]

        assert isinstance(signals["true_bus_factor"], (int, float))
        assert isinstance(signals["bus_factor_confidence"], str)
        assert signals["bus_factor_confidence"] in ("LOW", "MEDIUM", "HIGH")

    @mock_aws
    def test_feedback_url_contains_encoded_package_name(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """feedback_url must contain properly URL-encoded ecosystem and package name."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        body = json.loads(result["body"])

        assert "github.com/Dlaranjo/pkgwatch/issues/new" in body["feedback_url"]
        assert "score-feedback" in body["feedback_url"]
        assert "npm" in body["feedback_url"]
        assert "lodash" in body["feedback_url"]

    @mock_aws
    def test_202_response_has_exact_fields(self, seeded_api_keys_table, mock_dynamodb, api_gateway_event):
        """202 response must contain exactly the expected keys."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#collecting-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "collecting-pkg",
                "health_score": 50,
                "data_status": "pending",
                "queryable": False,
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "collecting-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 202
        body = json.loads(result["body"])

        expected_keys = {"status", "package", "ecosystem", "data_status", "message", "retry_after_seconds"}
        assert set(body.keys()) == expected_keys
        assert body["status"] == "collecting"
        assert isinstance(body["retry_after_seconds"], int)

    @mock_aws
    def test_202_response_content_type_is_json(self, seeded_api_keys_table, mock_dynamodb, api_gateway_event):
        """202 response must have Content-Type: application/json."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#ct-test-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "ct-test-pkg",
                "health_score": 50,
                "data_status": "pending",
                "queryable": False,
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "ct-test-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 202
        assert result["headers"]["Content-Type"] == "application/json"

    @mock_aws
    def test_404_error_response_has_exact_structure(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """404 error response must have {"error": {"code": ..., "message": ...}}."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "no-such-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 404
        body = json.loads(result["body"])

        assert "error" in body
        assert isinstance(body["error"]["code"], str)
        assert isinstance(body["error"]["message"], str)
        assert body["error"]["code"] == "package_not_found"
        assert "no-such-pkg" in body["error"]["message"]

    @mock_aws
    def test_200_response_content_type_is_json(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """200 response must have Content-Type: application/json."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 200
        assert result["headers"]["Content-Type"] == "application/json"

    @mock_aws
    def test_429_authenticated_response_has_upgrade_url(self, mock_dynamodb, seeded_packages_table, api_gateway_event):
        """429 for authenticated users must include upgrade_url and retry_after_seconds."""
        import hashlib

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_schema_test_rate_limit"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        table.put_item(
            Item={
                "pk": "user_schema_429",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "schema429@example.com",
                "tier": "free",
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )
        table.put_item(
            Item={
                "pk": "user_schema_429",
                "sk": "USER_META",
                "requests_this_month": 5000,
            }
        )

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 429
        body = json.loads(result["body"])

        assert body["error"]["code"] == "rate_limit_exceeded"
        assert "upgrade_url" in body["error"]
        assert "retry_after_seconds" in body["error"]
        assert isinstance(body["error"]["retry_after_seconds"], int)
        assert body["error"]["retry_after_seconds"] > 0

    @mock_aws
    def test_429_demo_response_has_signup_url(self, mock_dynamodb, seeded_packages_table, api_gateway_event):
        """429 for demo users must include signup_url and retry_after_seconds."""
        from datetime import datetime, timezone

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        now = datetime.now(timezone.utc)
        current_hour = now.strftime("%Y-%m-%d-%H")

        table.put_item(
            Item={
                "pk": "demo#127.0.0.1",
                "sk": f"hour#{current_hour}",
                "requests": 21,
                "ttl": int(now.timestamp()) + 7200,
            }
        )

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 429
        body = json.loads(result["body"])

        assert body["error"]["code"] == "demo_rate_limit_exceeded"
        assert "signup_url" in body["error"]
        assert "retry_after_seconds" in body["error"]
        assert body["error"]["retry_after_seconds"] == 3600


class TestGetPackageSecurityInputValidation:
    """Security tests: input validation against injection attacks."""

    @mock_aws
    def test_sql_injection_in_package_name(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """SQL injection attempt in package name should return 404, not leak data."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        injection_names = [
            "'; DROP TABLE packages; --",
            "1 OR 1=1",
            "lodash' UNION SELECT * FROM users --",
        ]

        for name in injection_names:
            api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": name}
            api_gateway_event["headers"]["x-api-key"] = test_key
            result = handler(api_gateway_event, {})
            assert result["statusCode"] == 404, f"Injection attempt should return 404: {name}"

    @mock_aws
    def test_path_traversal_in_package_name(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """Path traversal in package name should return 404, not leak files."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        traversal_names = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//etc/passwd",
        ]

        for name in traversal_names:
            api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": name}
            api_gateway_event["headers"]["x-api-key"] = test_key
            result = handler(api_gateway_event, {})
            assert result["statusCode"] == 404, f"Path traversal should return 404: {name}"
            body = json.loads(result["body"])
            # Must not leak file content
            assert "root:" not in body.get("error", {}).get("message", "")

    @mock_aws
    def test_xss_in_package_name_returns_valid_json(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """XSS attempt in package name should return valid JSON, not HTML."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        xss_name = "<script>alert('xss')</script>"
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": xss_name}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 404
        # Response must be valid JSON (Content-Type: application/json protects against XSS)
        body = json.loads(result["body"])
        assert result["headers"]["Content-Type"] == "application/json"
        assert body["error"]["code"] == "package_not_found"

    @mock_aws
    def test_null_byte_in_package_name(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """Null byte in package name should not crash the handler."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "pkg\x00evil"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        assert result["statusCode"] in (400, 404)

    @mock_aws
    def test_extremely_long_package_name_1000_chars(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Extremely long package name should not crash or cause DoS."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        long_name = "a" * 1000
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": long_name}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 404

    @mock_aws
    def test_unicode_emoji_package_name(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """Unicode emoji in package name should not crash."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "pkg-\U0001f4a9-test"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        assert result["statusCode"] in (400, 404)


class TestGetPackageCORSHeaders:
    """Tests for CORS header correctness in all response types."""

    @mock_aws
    def test_200_response_includes_cors_for_allowed_origin(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """200 response should include CORS headers for allowed origin."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["headers"]["origin"] = "https://pkgwatch.dev"

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 200
        assert result["headers"].get("Access-Control-Allow-Origin") == "https://pkgwatch.dev"
        assert "Access-Control-Allow-Methods" in result["headers"]

    @mock_aws
    def test_200_response_no_cors_for_disallowed_origin(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """200 response should NOT include CORS headers for disallowed origin."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["headers"]["origin"] = "https://evil-site.com"

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 200
        assert "Access-Control-Allow-Origin" not in result["headers"]

    @mock_aws
    def test_404_response_includes_cors_for_allowed_origin(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """404 error response should include CORS headers for allowed origin."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "no-such-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["headers"]["origin"] = "https://pkgwatch.dev"

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 404
        assert result["headers"].get("Access-Control-Allow-Origin") == "https://pkgwatch.dev"

    @mock_aws
    def test_202_response_includes_cors_for_allowed_origin(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """202 collecting response should include CORS headers."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#cors-test-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "cors-test-pkg",
                "health_score": 50,
                "data_status": "pending",
                "queryable": False,
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "cors-test-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["headers"]["origin"] = "https://pkgwatch.dev"

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 202
        assert result["headers"].get("Access-Control-Allow-Origin") == "https://pkgwatch.dev"


class TestGetPackageRateLimitReset:
    """Tests for X-RateLimit-Reset header precision."""

    @mock_aws
    def test_authenticated_rate_limit_reset_is_end_of_month(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Authenticated X-RateLimit-Reset should be end of current month."""
        import time

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 200

        reset_ts = int(result["headers"]["X-RateLimit-Reset"])
        # Should be in the future
        assert reset_ts > int(time.time())
        # Should be no more than 31 days from now
        assert reset_ts < int(time.time()) + 31 * 86400 + 86400


class TestEcosystemCaseInsensitive:
    """Tests for case-insensitive ecosystem parameter handling."""

    @mock_aws
    def test_get_package_accepts_uppercase_ecosystem(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """GET /packages should accept ecosystem in any case."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table

        for ecosystem in ["NPM", "Npm", "nPm"]:
            api_gateway_event["pathParameters"] = {"ecosystem": ecosystem, "name": "lodash"}
            api_gateway_event["headers"]["x-api-key"] = test_key

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 200, f"Ecosystem '{ecosystem}' should be accepted"
            body = json.loads(result["body"])
            assert body["ecosystem"] == "npm"

    @mock_aws
    def test_badge_accepts_uppercase_ecosystem(self, mock_dynamodb, api_gateway_event):
        """GET /badge should accept ecosystem in any case."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "lodash",
                "health_score": 85,
                "queryable": True,
                "data_status": "complete",
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.badge import handler

        for ecosystem in ["NPM", "Npm", "PYPI", "PyPI"]:
            api_gateway_event["pathParameters"] = {"ecosystem": ecosystem, "name": "lodash"}

            result = handler(api_gateway_event, {})

            # NPM variants should find lodash; PyPI variants won't find it but shouldn't return 400
            assert result["statusCode"] == 200, f"Ecosystem '{ecosystem}' should not return error"


class TestNotFoundRequestUrlHint:
    """Tests for 404 response including request_url hint."""

    @mock_aws
    def test_404_includes_request_url_hint(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """404 response should include request_url pointing to POST /packages/request."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "nonexistent-pkg-xyz"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404
        body = json.loads(result["body"])
        assert body["error"]["details"]["request_url"] == "/packages/request"


class TestAuthWarningHeader:
    """Tests for X-Auth-Warning header when invalid API key is provided."""

    @mock_aws
    def test_invalid_key_returns_auth_warning_header(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Bad key + queryable package should return 200 with X-Auth-Warning."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = "invalid-key-12345"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert result["headers"].get("X-Auth-Warning") == "api_key_not_recognized"

    @mock_aws
    def test_no_key_no_warning_header(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """No key should use demo mode without X-Auth-Warning."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        # No x-api-key header

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert "X-Auth-Warning" not in result["headers"]

    @mock_aws
    def test_valid_key_no_warning_header(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """Valid key should not include X-Auth-Warning."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert "X-Auth-Warning" not in result["headers"]

    @mock_aws
    def test_invalid_key_warning_on_202(self, seeded_api_keys_table, mock_dynamodb, api_gateway_event):
        """Bad key + non-queryable package should return 202 with X-Auth-Warning."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#incomplete-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "incomplete-pkg",
                "health_score": 50,
                "data_status": "pending",
                "queryable": False,
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "incomplete-pkg"}
        api_gateway_event["headers"]["x-api-key"] = "invalid-key-12345"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 202
        assert result["headers"].get("X-Auth-Warning") == "api_key_not_recognized"

    @mock_aws
    def test_invalid_key_warning_on_429_demo(self, seeded_api_keys_table, mock_dynamodb, api_gateway_event):
        """Bad key + demo limit hit should return 429 with X-Auth-Warning."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        # Exhaust demo rate limit (20 requests per hour)
        for _ in range(20):
            api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
            api_gateway_event["headers"]["x-api-key"] = "invalid-key-12345"
            handler(api_gateway_event, {})

        # 21st request should be rate limited
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = "invalid-key-12345"
        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 429
        assert result["headers"].get("X-Auth-Warning") == "api_key_not_recognized"

    @mock_aws
    def test_empty_string_key_no_warning(self, seeded_api_keys_table, seeded_packages_table, api_gateway_event):
        """Empty string key is falsy = no key = no warning."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = ""

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert "X-Auth-Warning" not in result["headers"]
