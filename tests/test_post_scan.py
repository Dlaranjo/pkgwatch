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
