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

            # Create a mock SQS client
            mock_sqs = MagicMock()

            # Patch the lazy getter to return our mock
            with patch.object(module, "_get_sqs", return_value=mock_sqs):
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

        # Mock check_and_record_rate_limit to return False (rate limited)
        with patch.object(module, "check_and_record_rate_limit") as mock_rate_limit:
            mock_rate_limit.return_value = False

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

            # Patch the lazy SQS getter
            with patch.object(module, "_get_sqs", return_value=MagicMock()):
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

        result = module.check_and_record_rate_limit("192.168.1.1")
        assert result is True

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

        result = module.check_and_record_rate_limit("192.168.1.1")
        assert result is False

    @mock_aws
    def test_check_and_record_rate_limit_increments_count(self, mock_dynamodb):
        """Should atomically check and increment request count for IP."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        result = module.check_and_record_rate_limit("192.168.1.2")
        assert result is True

        # Verify count was incremented
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        item = table.get_item(
            Key={"pk": f"RATE_LIMIT#192.168.1.2#{today}", "sk": "request_package"}
        )
        assert item["Item"]["request_count"] == 1

    def test_get_client_ip_uses_source_ip_not_forwarded_header(self, api_gateway_event):
        """Should use sourceIp and ignore X-Forwarded-For to prevent spoofing."""
        import importlib
        import api.request_package as module

        importlib.reload(module)

        # Even when X-Forwarded-For is present, sourceIp should be used
        # This prevents rate limit bypass via header spoofing
        event = {
            **api_gateway_event,
            "headers": {"X-Forwarded-For": "203.0.113.1, 70.41.3.18"},  # Spoofed header
            "requestContext": {"identity": {"sourceIp": "10.0.0.1"}},  # Real IP
        }
        ip = module.get_client_ip(event)
        # Should use the verified sourceIp, not the spoofable X-Forwarded-For
        assert ip == "10.0.0.1"

    def test_get_client_ip_from_source_ip(self, api_gateway_event):
        """Should use sourceIp from API Gateway's verified identity."""
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

    def test_get_client_ip_returns_unknown_when_missing(self, api_gateway_event):
        """Should return 'unknown' when sourceIp is not available."""
        import importlib
        import api.request_package as module

        importlib.reload(module)

        event = {
            **api_gateway_event,
            "headers": {"X-Forwarded-For": "203.0.113.1"},  # This should be ignored
            "requestContext": {"identity": {}},  # No sourceIp
        }
        ip = module.get_client_ip(event)
        assert ip == "unknown"


class TestRequestPackageErrorPaths:
    """Tests for error handling and edge cases in request_package."""

    @mock_aws
    def test_package_exists_check_error_continues_to_validation(self, mock_dynamodb, api_gateway_event):
        """Should continue to registry validation when DynamoDB get_item fails (lines 104-105)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        # Mock _get_dynamodb to return a resource where the packages table raises on get_item
        mock_packages_table = MagicMock()
        mock_packages_table.get_item.side_effect = Exception("DynamoDB unavailable")
        mock_packages_table.put_item.return_value = {}

        mock_api_keys_table = MagicMock()
        mock_api_keys_table.get_item.return_value = {}  # No rate limit record

        def mock_table_factory(table_name):
            if table_name == "pkgwatch-packages":
                return mock_packages_table
            return mock_api_keys_table

        mock_db = MagicMock()
        mock_db.Table.side_effect = mock_table_factory

        with patch.object(module, "_get_dynamodb", return_value=mock_db):
            with patch.object(module, "validate_package_exists", new_callable=AsyncMock) as mock_validate:
                mock_validate.return_value = True
                with patch.object(module, "_get_sqs", return_value=MagicMock()):
                    event = {**api_gateway_event, "body": json.dumps({"name": "test-pkg"})}
                    result = module.handler(event, None)

                    # Should still succeed since the error is caught and processing continues
                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["status"] == "queued"

    @mock_aws
    def test_conditional_check_failed_returns_exists(self, mock_dynamodb, api_gateway_event):
        """Should return exists when put_item hits ConditionalCheckFailedException (lines 134-144)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import api.request_package as module
        from botocore.exceptions import ClientError

        importlib.reload(module)

        # Mock _get_dynamodb so put_item raises ConditionalCheckFailedException
        mock_packages_table = MagicMock()
        mock_packages_table.get_item.return_value = {}  # Package not found initially
        mock_packages_table.put_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Already exists"}},
            "PutItem",
        )

        mock_api_keys_table = MagicMock()
        mock_api_keys_table.get_item.return_value = {}  # No rate limit

        def mock_table_factory(table_name):
            if table_name == "pkgwatch-packages":
                return mock_packages_table
            return mock_api_keys_table

        mock_db = MagicMock()
        mock_db.Table.side_effect = mock_table_factory

        with patch.object(module, "_get_dynamodb", return_value=mock_db):
            with patch.object(module, "validate_package_exists", new_callable=AsyncMock) as mock_validate:
                mock_validate.return_value = True

                event = {**api_gateway_event, "body": json.dumps({"name": "race-pkg"})}
                result = module.handler(event, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["status"] == "exists"
                assert "another request" in body["message"]

    @mock_aws
    def test_put_item_generic_error_returns_500(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when put_item raises a non-conditional error (lines 146-148)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        mock_packages_table = MagicMock()
        mock_packages_table.get_item.return_value = {}  # Package not found
        mock_packages_table.put_item.side_effect = Exception("Generic DB failure")

        mock_api_keys_table = MagicMock()
        mock_api_keys_table.get_item.return_value = {}  # No rate limit

        def mock_table_factory(table_name):
            if table_name == "pkgwatch-packages":
                return mock_packages_table
            return mock_api_keys_table

        mock_db = MagicMock()
        mock_db.Table.side_effect = mock_table_factory

        with patch.object(module, "_get_dynamodb", return_value=mock_db):
            with patch.object(module, "validate_package_exists", new_callable=AsyncMock) as mock_validate:
                mock_validate.return_value = True

                event = {**api_gateway_event, "body": json.dumps({"name": "fail-pkg"})}
                result = module.handler(event, None)

                assert result["statusCode"] == 500
                body = json.loads(result["body"])
                assert body["error"]["code"] == "db_error"

    @mock_aws
    def test_sqs_send_failure_does_not_block_response(self, mock_dynamodb, api_gateway_event):
        """Should return success even when SQS send_message fails (lines 166-167)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        mock_sqs = MagicMock()
        mock_sqs.send_message.side_effect = Exception("SQS unavailable")

        with patch.object(module, "validate_package_exists", new_callable=AsyncMock) as mock_validate:
            mock_validate.return_value = True
            with patch.object(module, "_get_sqs", return_value=mock_sqs):
                event = {**api_gateway_event, "body": json.dumps({"name": "sqs-fail-pkg"})}
                result = module.handler(event, None)

                # Should still return 200 - SQS failure is non-fatal
                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["status"] == "queued"

    @mock_aws
    def test_rate_limit_check_error_returns_false(self, mock_dynamodb):
        """Should return False (fail closed) when rate limit check fails."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        # Mock _get_dynamodb so the rate limit table raises an error on update_item
        mock_table = MagicMock()
        mock_table.update_item.side_effect = Exception("DynamoDB timeout")

        mock_db = MagicMock()
        mock_db.Table.return_value = mock_table

        with patch.object(module, "_get_dynamodb", return_value=mock_db):
            result = module.check_and_record_rate_limit("192.168.1.1")
            assert result is False

    @mock_aws
    def test_check_and_record_rate_limit_error_does_not_raise(self, mock_dynamodb):
        """Should silently handle errors and return False (fail closed)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import importlib
        import api.request_package as module

        importlib.reload(module)

        mock_table = MagicMock()
        mock_table.update_item.side_effect = Exception("DynamoDB write failure")

        mock_db = MagicMock()
        mock_db.Table.return_value = mock_table

        with patch.object(module, "_get_dynamodb", return_value=mock_db):
            # Should not raise, and should return False (fail closed)
            result = module.check_and_record_rate_limit("192.168.1.1")
            assert result is False

    def test_validate_package_exists_returns_false_on_exception(self):
        """Should return False when deps.dev lookup raises an exception (lines 251-258)."""
        import importlib
        import api.request_package as module
        import asyncio

        importlib.reload(module)

        with patch("collectors.depsdev_collector.get_package_info", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = Exception("Network error")

            result = asyncio.run(module.validate_package_exists("some-pkg", "npm"))
            assert result is False

    def test_validate_package_exists_returns_true_when_found(self):
        """Should return True when deps.dev lookup returns package info."""
        import importlib
        import api.request_package as module
        import asyncio

        importlib.reload(module)

        with patch("collectors.depsdev_collector.get_package_info", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = {"name": "lodash", "version": "4.17.21"}

            result = asyncio.run(module.validate_package_exists("lodash", "npm"))
            assert result is True

    def test_validate_package_exists_returns_false_when_not_found(self):
        """Should return False when deps.dev lookup returns None."""
        import importlib
        import api.request_package as module
        import asyncio

        importlib.reload(module)

        with patch("collectors.depsdev_collector.get_package_info", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = None

            result = asyncio.run(module.validate_package_exists("nonexistent", "npm"))
            assert result is False

    @mock_aws
    def test_put_item_reraises_non_conditional_client_error(self, mock_dynamodb, api_gateway_event):
        """Should re-raise ClientErrors that are not ConditionalCheckFailedException (line 145)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import api.request_package as module
        from botocore.exceptions import ClientError

        importlib.reload(module)

        mock_packages_table = MagicMock()
        mock_packages_table.get_item.return_value = {}  # Package not found
        mock_packages_table.put_item.side_effect = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Rate exceeded"}},
            "PutItem",
        )

        mock_api_keys_table = MagicMock()
        mock_api_keys_table.get_item.return_value = {}

        def mock_table_factory(table_name):
            if table_name == "pkgwatch-packages":
                return mock_packages_table
            return mock_api_keys_table

        mock_db = MagicMock()
        mock_db.Table.side_effect = mock_table_factory

        with patch.object(module, "_get_dynamodb", return_value=mock_db):
            with patch.object(module, "validate_package_exists", new_callable=AsyncMock) as mock_validate:
                mock_validate.return_value = True

                event = {**api_gateway_event, "body": json.dumps({"name": "throttled-pkg"})}
                with pytest.raises(ClientError):
                    module.handler(event, None)
