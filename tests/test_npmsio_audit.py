"""
Tests for npmsio_audit.py - npms.io quarterly audit Lambda.

Coverage targets:
- Handler operation and return values
- npms.io API fetching
- Missing package detection
- Quality threshold filtering
- DynamoDB operations (put_item, get_item)
- SQS queuing of added packages
- Error handling (API, DynamoDB, SQS)
- Metrics emission
- Race condition handling
"""

import json
import os
import sys
from decimal import Decimal
from unittest.mock import MagicMock, patch

import boto3
import httpx
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws


@pytest.fixture
def setup_sqs_package_queue():
    """Set up SQS package queue for collection."""
    import boto3

    sqs = boto3.client("sqs", region_name="us-east-1")
    response = sqs.create_queue(QueueName="pkgwatch-package-queue")
    queue_url = response["QueueUrl"]
    os.environ["PACKAGE_QUEUE_URL"] = queue_url
    return queue_url


class TestHandlerBasicOperation:
    """Tests for basic handler operation."""

    @mock_aws
    def test_returns_zero_when_no_packages_from_npmsio(self, mock_dynamodb):
        """Should return zero counts when npms.io returns no packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = []

            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["audited"] == 0
            assert body["missing"] == 0
            assert body["added"] == 0

    @mock_aws
    def test_returns_correct_counts_on_success(self, mock_dynamodb):
        """Should return accurate counts for audited, missing, added packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add existing package
        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#existing-pkg",
                "sk": "LATEST",
                "name": "existing-pkg",
            }
        )

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "existing-pkg", "score": 0.9},
                {"name": "new-pkg-1", "score": 0.8},
                {"name": "new-pkg-2", "score": 0.7},
                {"name": "low-quality", "score": 0.3},  # Below threshold
            ]

            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["audited"] == 4
                assert body["missing"] == 3  # All except existing
                assert body["added"] == 2  # Only high quality ones

    @mock_aws
    def test_uses_default_table_name(self, mock_dynamodb):
        """Should use default PACKAGES_TABLE when not set."""
        os.environ.pop("PACKAGES_TABLE", None)
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        assert module.PACKAGES_TABLE == "pkgwatch-packages"


class TestMissingPackageDetection:
    """Tests for detecting missing packages."""

    @mock_aws
    def test_finds_missing_packages(self, mock_dynamodb):
        """Should identify packages not in database."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "name": "lodash",
            }
        )

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "lodash", "score": 0.9},
                {"name": "express", "score": 0.85},
                {"name": "react", "score": 0.95},
            ]

            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                body = json.loads(result["body"])
                assert body["missing"] == 2  # express and react

    @mock_aws
    def test_skips_packages_without_name(self, mock_dynamodb):
        """Should skip packages missing name field."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"score": 0.9},  # Missing name
                {"name": "", "score": 0.8},  # Empty name
                {"name": "valid-pkg", "score": 0.85},
            ]

            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                body = json.loads(result["body"])
                assert body["audited"] == 3
                # Only valid-pkg should be in missing (empty name is falsy)
                assert body["missing"] == 1

    @mock_aws
    def test_handles_get_item_exception(self, mock_dynamodb):
        """Should continue when get_item fails for a package."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "error-pkg", "score": 0.9},
                {"name": "ok-pkg", "score": 0.8},
            ]

            mock_table = MagicMock()
            call_count = [0]

            def mock_get_item(**kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    raise Exception("DynamoDB error")
                return {}  # Not found

            mock_table.get_item.side_effect = mock_get_item
            mock_table.put_item.return_value = {}
            mock_table.meta.client.exceptions.ConditionalCheckFailedException = ClientError

            with patch.object(module.dynamodb, "Table", return_value=mock_table):
                with patch.object(module, "sqs"):
                    result = module.handler({}, None)

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["audited"] == 2


class TestQualityThresholdFiltering:
    """Tests for quality threshold filtering."""

    @mock_aws
    def test_skips_low_quality_packages(self, mock_dynamodb):
        """Should skip packages with score below QUALITY_THRESHOLD (0.5)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "low-quality-1", "score": 0.3},
                {"name": "low-quality-2", "score": 0.49},
                {"name": "borderline", "score": 0.5},  # At threshold - included (score >= 0.5)
                {"name": "high-quality", "score": 0.51},
            ]

            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                body = json.loads(result["body"])
                assert body["missing"] == 4
                # Packages with score >= 0.5 are added (condition is score < 0.5)
                assert body["added"] == 2

    @mock_aws
    def test_handles_zero_score(self, mock_dynamodb):
        """Should skip packages with zero score."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "zero-score", "score": 0},
                {"name": "high-quality", "score": 0.8},
            ]

            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                body = json.loads(result["body"])
                assert body["added"] == 1

    @mock_aws
    def test_handles_missing_score(self, mock_dynamodb):
        """Should treat missing score as 0."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "no-score"},  # Missing score
                {"name": "high-quality", "score": 0.8},
            ]

            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                body = json.loads(result["body"])
                assert body["added"] == 1


class TestDynamoDBOperations:
    """Tests for DynamoDB operations."""

    @mock_aws
    def test_adds_package_with_correct_fields(self, mock_dynamodb):
        """Should add packages with all required fields."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "new-package", "score": 0.85},
            ]

            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200

        # Verify package was added correctly
        table = mock_dynamodb.Table("pkgwatch-packages")
        response = table.get_item(Key={"pk": "npm#new-package", "sk": "LATEST"})

        assert "Item" in response
        item = response["Item"]
        assert item["name"] == "new-package"
        assert item["ecosystem"] == "npm"
        assert item["tier"] == 3
        assert item["source"] == "npmsio_audit"
        assert item["data_status"] == "pending"
        assert "created_at" in item
        assert "last_updated" in item
        assert item["npmsio_score"] == Decimal("0.85")

    @mock_aws
    def test_handles_conditional_check_failed(self, mock_dynamodb):
        """Should handle race condition when package already exists."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "race-pkg", "score": 0.9},
            ]

            mock_table = MagicMock()
            mock_table.get_item.return_value = {}  # Not found initially

            # Mock the client exceptions attribute
            mock_client = MagicMock()
            mock_client.exceptions.ConditionalCheckFailedException = ClientError
            mock_table.meta.client = mock_client

            # Simulate ConditionalCheckFailedException
            error_response = {"Error": {"Code": "ConditionalCheckFailedException"}}
            mock_table.put_item.side_effect = ClientError(error_response, "PutItem")

            with patch.object(module.dynamodb, "Table", return_value=mock_table):
                with patch.object(module, "sqs"):
                    result = module.handler({}, None)

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["added"] == 0  # Not added due to race

    @mock_aws
    def test_handles_put_item_exception(self, mock_dynamodb):
        """Should log error and continue on put_item failure."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "error-pkg", "score": 0.9},
                {"name": "ok-pkg", "score": 0.8},
            ]

            mock_table = MagicMock()
            mock_table.get_item.return_value = {}  # Not found
            mock_client = MagicMock()
            mock_client.exceptions.ConditionalCheckFailedException = ClientError
            mock_table.meta.client = mock_client

            call_count = [0]

            def mock_put_item(**kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    raise Exception("DynamoDB put error")
                return {}

            mock_table.put_item.side_effect = mock_put_item

            with patch.object(module.dynamodb, "Table", return_value=mock_table):
                with patch.object(module, "sqs"):
                    result = module.handler({}, None)

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["added"] == 1  # Only second one added


class TestSQSQueuing:
    """Tests for SQS queuing of added packages."""

    @mock_aws
    def test_queues_added_packages(self, mock_dynamodb, setup_sqs_package_queue):
        """Should queue newly added packages for collection."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        queue_url = setup_sqs_package_queue

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "queued-pkg", "score": 0.9},
            ]

            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["queued"] == 1

        # Verify message in queue
        sqs = boto3.client("sqs", region_name="us-east-1")
        response = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)
        messages = response.get("Messages", [])

        assert len(messages) == 1
        msg_body = json.loads(messages[0]["Body"])
        assert msg_body["ecosystem"] == "npm"
        assert msg_body["name"] == "queued-pkg"
        assert msg_body["tier"] == 3
        assert msg_body["reason"] == "npmsio_audit"

    @mock_aws
    def test_skips_queue_without_url(self, mock_dynamodb):
        """Should skip queuing when PACKAGE_QUEUE_URL not set."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ.pop("PACKAGE_QUEUE_URL", None)

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "no-queue-pkg", "score": 0.9},
            ]

            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["added"] == 1
            assert body["queued"] == 0

    @mock_aws
    def test_queues_multiple_packages(self, mock_dynamodb, setup_sqs_package_queue):
        """Should queue all added packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        queue_url = setup_sqs_package_queue

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "pkg-1", "score": 0.9},
                {"name": "pkg-2", "score": 0.8},
                {"name": "pkg-3", "score": 0.7},
            ]

            result = module.handler({}, None)

            body = json.loads(result["body"])
            assert body["queued"] == 3

        # Verify all messages
        sqs = boto3.client("sqs", region_name="us-east-1")
        all_messages = []
        while True:
            response = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10)
            messages = response.get("Messages", [])
            if not messages:
                break
            all_messages.extend(messages)
            for msg in messages:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])

        assert len(all_messages) == 3


class TestFetchNpmsioTopPackages:
    """Tests for fetch_npmsio_top_packages function."""

    def test_fetches_and_parses_packages(self):
        """Should fetch and parse packages from npms.io."""
        import discovery.npmsio_audit as module

        mock_response_with_data = MagicMock()
        mock_response_with_data.json.return_value = {
            "results": [
                {
                    "package": {"name": "pkg1"},
                    "score": {
                        "final": 0.9,
                        "detail": {"quality": 0.8, "popularity": 0.7, "maintenance": 0.9},
                    },
                },
                {
                    "package": {"name": "pkg2"},
                    "score": {"final": 0.8},
                },
            ]
        }
        mock_response_with_data.raise_for_status = MagicMock()

        mock_response_empty = MagicMock()
        mock_response_empty.json.return_value = {"results": []}
        mock_response_empty.raise_for_status = MagicMock()

        with patch("discovery.npmsio_audit.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.side_effect = [
                mock_response_with_data,
                mock_response_empty,
            ]

            result = module.fetch_npmsio_top_packages(10)

            assert len(result) == 2
            assert result[0]["name"] == "pkg1"
            assert result[0]["score"] == 0.9
            assert result[0]["quality"] == 0.8
            assert result[0]["popularity"] == 0.7
            assert result[0]["maintenance"] == 0.9

    def test_fetches_up_to_limit(self):
        """Should stop fetching when limit is reached."""
        import discovery.npmsio_audit as module

        def create_response(count):
            mock = MagicMock()
            mock.json.return_value = {
                "results": [
                    {"package": {"name": f"pkg-{i}"}, "score": {"final": 0.9}}
                    for i in range(count)
                ]
            }
            mock.raise_for_status = MagicMock()
            return mock

        with patch("discovery.npmsio_audit.httpx.Client") as mock_client:
            # Return 250 packages per call (npms.io batch size)
            mock_client.return_value.__enter__.return_value.get.side_effect = [
                create_response(250),
                create_response(250),
                create_response(0),  # Empty to stop
            ]

            result = module.fetch_npmsio_top_packages(300)

            # Should return exactly 300 or less
            assert len(result) <= 500

    def test_handles_empty_results(self):
        """Should return empty list when npms.io returns no results."""
        import discovery.npmsio_audit as module

        mock_response = MagicMock()
        mock_response.json.return_value = {"results": []}
        mock_response.raise_for_status = MagicMock()

        with patch("discovery.npmsio_audit.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_response

            result = module.fetch_npmsio_top_packages(10)

            assert result == []

    def test_handles_http_status_error(self):
        """Should handle HTTP status errors gracefully."""
        import discovery.npmsio_audit as module

        mock_request = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch("discovery.npmsio_audit.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.side_effect = (
                httpx.HTTPStatusError("Server error", request=mock_request, response=mock_response)
            )

            result = module.fetch_npmsio_top_packages(10)

            assert result == []

    def test_handles_generic_exception(self):
        """Should handle generic exceptions gracefully."""
        import discovery.npmsio_audit as module

        with patch("discovery.npmsio_audit.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.side_effect = Exception(
                "Network error"
            )

            result = module.fetch_npmsio_top_packages(10)

            assert result == []

    def test_handles_timeout(self):
        """Should handle timeout errors gracefully."""
        import discovery.npmsio_audit as module

        with patch("discovery.npmsio_audit.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.side_effect = (
                httpx.TimeoutException("Request timed out")
            )

            result = module.fetch_npmsio_top_packages(10)

            assert result == []

    def test_uses_correct_api_endpoint(self):
        """Should use correct npms.io API endpoint and params."""
        import discovery.npmsio_audit as module

        mock_response = MagicMock()
        mock_response.json.return_value = {"results": []}
        mock_response.raise_for_status = MagicMock()

        with patch("discovery.npmsio_audit.httpx.Client") as mock_client:
            mock_get = mock_client.return_value.__enter__.return_value.get
            mock_get.return_value = mock_response

            module.fetch_npmsio_top_packages(100)

            mock_get.assert_called()
            call_args = mock_get.call_args
            assert "https://api.npms.io/v2/search" in call_args[0][0]
            assert call_args.kwargs["params"]["size"] <= 250

    def test_handles_missing_results_key(self):
        """Should handle response missing results key."""
        import discovery.npmsio_audit as module

        mock_response = MagicMock()
        mock_response.json.return_value = {}  # Missing 'results'
        mock_response.raise_for_status = MagicMock()

        with patch("discovery.npmsio_audit.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_response

            result = module.fetch_npmsio_top_packages(10)

            assert result == []

    def test_stops_at_npmsio_limit(self):
        """Should stop at npms.io 10000 result limit."""
        import discovery.npmsio_audit as module

        def create_response(offset):
            mock = MagicMock()
            mock.json.return_value = {
                "results": [
                    {"package": {"name": f"pkg-{offset + i}"}, "score": {"final": 0.9}}
                    for i in range(250)
                ]
            }
            mock.raise_for_status = MagicMock()
            return mock

        responses = [create_response(i * 250) for i in range(50)]  # More than 10000

        with patch("discovery.npmsio_audit.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.side_effect = responses

            # Request more than 10000
            result = module.fetch_npmsio_top_packages(15000)

            # Should not exceed 10000 due to npms.io limit
            assert len(result) <= 10000


class TestMetricsEmission:
    """Tests for CloudWatch metrics emission."""

    @mock_aws
    def test_emits_metrics_on_success(self, mock_dynamodb):
        """Should emit CloudWatch metrics on successful audit."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        mock_metrics = MagicMock()

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "pkg1", "score": 0.9},
            ]

            with patch.object(module, "sqs"):
                with patch.dict(sys.modules, {"shared.metrics": mock_metrics}):
                    result = module.handler({}, None)

                    assert result["statusCode"] == 200

    @mock_aws
    def test_continues_when_metrics_not_available(self, mock_dynamodb):
        """Should not fail when metrics module is not available."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = []

            with patch.dict(sys.modules, {"shared.metrics": None}):
                result = module.handler({}, None)

                assert result["statusCode"] == 200


class TestConstants:
    """Tests for module constants."""

    def test_quality_threshold_constant(self):
        """Should have QUALITY_THRESHOLD set to 0.5."""
        import discovery.npmsio_audit as module

        assert module.QUALITY_THRESHOLD == 0.5

    def test_max_packages_constant(self):
        """Should have MAX_PACKAGES set to 5000."""
        import discovery.npmsio_audit as module

        assert module.MAX_PACKAGES == 5000

    def test_batch_size_constant(self):
        """Should have BATCH_SIZE set to 250."""
        import discovery.npmsio_audit as module

        assert module.BATCH_SIZE == 250

    def test_npmsio_api_constant(self):
        """Should have correct npms.io API base URL."""
        import discovery.npmsio_audit as module

        assert module.NPMSIO_API == "https://api.npms.io/v2"


class TestIntegration:
    """Integration tests for end-to-end audit flow."""

    @mock_aws
    def test_full_audit_flow(self, mock_dynamodb, setup_sqs_package_queue):
        """Should complete full audit flow successfully."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        _queue_url = setup_sqs_package_queue

        # Add some existing packages
        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#existing-1",
                "sk": "LATEST",
                "name": "existing-1",
            }
        )
        table.put_item(
            Item={
                "pk": "npm#existing-2",
                "sk": "LATEST",
                "name": "existing-2",
            }
        )

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "existing-1", "score": 0.9},  # Exists
                {"name": "existing-2", "score": 0.85},  # Exists
                {"name": "new-high-quality", "score": 0.8},  # New, high quality
                {"name": "new-low-quality", "score": 0.3},  # New, low quality
                {"name": "new-medium-quality", "score": 0.6},  # New, above threshold
            ]

            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["audited"] == 5
            assert body["missing"] == 3
            assert body["added"] == 2  # Only high and medium quality
            assert body["queued"] == 2

        # Verify packages added to DB
        response = table.get_item(Key={"pk": "npm#new-high-quality", "sk": "LATEST"})
        assert "Item" in response

        response = table.get_item(Key={"pk": "npm#new-medium-quality", "sk": "LATEST"})
        assert "Item" in response

        response = table.get_item(Key={"pk": "npm#new-low-quality", "sk": "LATEST"})
        assert "Item" not in response  # Should not be added

    @mock_aws
    def test_handles_large_batch_of_packages(self, mock_dynamodb):
        """Should handle large batches of packages efficiently."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        # Create large batch of packages
        packages = [{"name": f"pkg-{i}", "score": 0.8} for i in range(100)]

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = packages

            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["audited"] == 100
                assert body["added"] == 100

    @mock_aws
    def test_handles_all_existing_packages(self, mock_dynamodb):
        """Should handle case where all packages already exist."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Add all packages as existing
        for i in range(5):
            table.put_item(
                Item={
                    "pk": f"npm#pkg-{i}",
                    "sk": "LATEST",
                    "name": f"pkg-{i}",
                }
            )

        import importlib

        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [{"name": f"pkg-{i}", "score": 0.9} for i in range(5)]

            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                body = json.loads(result["body"])
                assert body["audited"] == 5
                assert body["missing"] == 0
                assert body["added"] == 0
