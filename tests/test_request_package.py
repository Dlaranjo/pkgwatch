"""
Tests for the request_package API endpoint.

POST /packages/request allows users to request packages not yet tracked.
"""

import json
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from moto import mock_aws


class TestRequestPackageHandler:
    """Tests for the request package API handler."""

    @mock_aws
    def test_returns_error_for_invalid_json(self, mock_dynamodb, api_gateway_event):
        """Should return 400 for invalid JSON body."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        event = {**api_gateway_event, "body": "invalid json{"}
        result = module.handler(event, None)

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert "Invalid JSON" in body["error"]["message"]

    @mock_aws
    def test_returns_error_for_missing_name(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when package name is missing."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        event = {**api_gateway_event, "body": json.dumps({"ecosystem": "npm"})}
        result = module.handler(event, None)

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert "name is required" in body["error"]["message"]

    @mock_aws
    def test_returns_error_for_invalid_ecosystem(self, mock_dynamodb, api_gateway_event):
        """Should return 400 for invalid ecosystem."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        event = {**api_gateway_event, "body": json.dumps({"name": "test", "ecosystem": "invalid"})}
        result = module.handler(event, None)

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert "npm" in body["error"]["message"] or "pypi" in body["error"]["message"]

    @mock_aws
    def test_returns_exists_for_tracked_package(self, mock_dynamodb, api_gateway_event):
        """Should return exists status when package is already tracked."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add existing package
        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#existing-pkg",
                "sk": "LATEST",
                "name": "existing-pkg",
                "ecosystem": "npm",
                "health_score": 85,
            }
        )

        import importlib
        import api.request_package as module

        importlib.reload(module)

        event = {**api_gateway_event, "body": json.dumps({"name": "existing-pkg"})}
        result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["status"] == "exists"
        assert body["package"] == "existing-pkg"

    @mock_aws
    def test_returns_404_for_nonexistent_package(self, mock_dynamodb, api_gateway_event):
        """Should return 404 when package doesn't exist in registry."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        # Mock validate_package_exists to return False
        with patch.object(module, "validate_package_exists", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = False

            event = {**api_gateway_event, "body": json.dumps({"name": "nonexistent-pkg"})}
            result = module.handler(event, None)

            assert result["statusCode"] == 404
            body = json.loads(result["body"])
            assert "not found" in body["error"]["message"]

    @mock_aws
    def test_queues_valid_package_request(self, mock_dynamodb, api_gateway_event):
        """Should add package to DB and queue for collection."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        # Mock validate_package_exists to return True
        with patch.object(module, "validate_package_exists", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = True

            with patch.object(module, "sqs") as mock_sqs:
                event = {**api_gateway_event, "body": json.dumps({"name": "new-pkg"})}
                result = module.handler(event, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["status"] == "queued"
                assert body["package"] == "new-pkg"

                # Verify package was added to DB
                table = mock_dynamodb.Table("pkgwatch-packages")
                item = table.get_item(Key={"pk": "npm#new-pkg", "sk": "LATEST"})
                assert "Item" in item
                assert item["Item"]["source"] == "user_request"
                assert item["Item"]["tier"] == 3

                # Verify SQS was called
                mock_sqs.send_message.assert_called_once()

    @mock_aws
    def test_rate_limit_exceeded(self, mock_dynamodb, api_gateway_event):
        """Should return 429 when rate limit is exceeded."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        # Mock rate_limit_exceeded to return True
        with patch.object(module, "rate_limit_exceeded") as mock_rate_limit:
            mock_rate_limit.return_value = True

            event = {**api_gateway_event, "body": json.dumps({"name": "test-pkg"})}
            result = module.handler(event, None)

            assert result["statusCode"] == 429
            body = json.loads(result["body"])
            assert "Rate limit" in body["error"]["message"]

    @mock_aws
    def test_handles_pypi_ecosystem(self, mock_dynamodb, api_gateway_event):
        """Should correctly handle pypi ecosystem."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        with patch.object(module, "validate_package_exists", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = True

            with patch.object(module, "sqs"):
                event = {
                    **api_gateway_event,
                    "body": json.dumps({"name": "requests", "ecosystem": "pypi"}),
                }
                result = module.handler(event, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["ecosystem"] == "pypi"

                # Verify correct pk format
                table = mock_dynamodb.Table("pkgwatch-packages")
                item = table.get_item(Key={"pk": "pypi#requests", "sk": "LATEST"})
                assert "Item" in item


class TestRateLimitHelpers:
    """Tests for rate limit helper functions."""

    @mock_aws
    def test_rate_limit_not_exceeded_initially(self, mock_dynamodb):
        """Rate limit should not be exceeded for first request."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        result = module.rate_limit_exceeded("192.168.1.1")
        assert result is False

    @mock_aws
    def test_rate_limit_exceeded_after_limit(self, mock_dynamodb):
        """Rate limit should be exceeded after 10 requests."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        # Add rate limit record at the limit
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        table.put_item(
            Item={
                "pk": f"RATE_LIMIT#192.168.1.1#{today}",
                "sk": "request_package",
                "request_count": 10,
            }
        )

        result = module.rate_limit_exceeded("192.168.1.1")
        assert result is True

    @mock_aws
    def test_record_rate_limit_usage(self, mock_dynamodb):
        """Should increment request count for IP."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        module.record_rate_limit_usage("192.168.1.2")

        # Verify count was incremented
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        item = table.get_item(
            Key={"pk": f"RATE_LIMIT#192.168.1.2#{today}", "sk": "request_package"}
        )
        assert item["Item"]["request_count"] == 1

    def test_get_client_ip_from_forwarded_header(self, api_gateway_event):
        """Should extract IP from X-Forwarded-For header."""
        import importlib
        import api.request_package as module

        importlib.reload(module)

        event = {
            **api_gateway_event,
            "headers": {"X-Forwarded-For": "203.0.113.1, 70.41.3.18"},
        }
        ip = module.get_client_ip(event)
        assert ip == "203.0.113.1"

    def test_get_client_ip_from_source_ip(self, api_gateway_event):
        """Should fall back to sourceIp when no forwarded header."""
        import importlib
        import api.request_package as module

        importlib.reload(module)

        event = {
            **api_gateway_event,
            "headers": {},
            "requestContext": {"identity": {"sourceIp": "10.0.0.1"}},
        }
        ip = module.get_client_ip(event)
        assert ip == "10.0.0.1"
