"""
Tests for the retry dispatcher Lambda handler.

The retry dispatcher finds packages with incomplete data (partial/minimal status)
that are due for retry and dispatches them to SQS for reprocessing.
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from moto import mock_aws


class TestRetryDispatcherHandler:
    """Tests for the retry dispatcher Lambda handler."""

    @mock_aws
    def test_returns_error_without_package_queue_url(self, mock_dynamodb):
        """Should return 500 error when PACKAGE_QUEUE_URL is not configured."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = ""

        # Reload to pick up env var
        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 500
        assert "PACKAGE_QUEUE_URL not configured" in result.get("error", "")

    @mock_aws
    def test_skips_dispatch_when_github_circuit_open(self, mock_dynamodb):
        """Should skip dispatch when GitHub circuit breaker is open."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        # Mock the circuit breaker import inside the handler
        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = False

        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body.get("skipped") == "circuit_open"

    @mock_aws
    def test_returns_zero_when_no_packages_found(self, mock_dynamodb):
        """Should return zero counts when no incomplete packages need retry."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        # Mock circuit breaker to allow execution
        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["found"] == 0
            assert body["dispatched"] == 0

    @mock_aws
    def test_happy_path_dispatches_packages(self, mock_dynamodb):
        """Should find incomplete packages and dispatch them to SQS."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add a package that is due for retry
        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "npm#incomplete-pkg",
                "sk": "LATEST",
                "data_status": "partial",
                "next_retry_at": (now - timedelta(hours=1)).isoformat(),
                "retry_count": 2,
                "missing_sources": ["github", "bundlephobia"],
                "tier": 2,
            }
        )

        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        # Mock circuit breaker
        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs") as mock_sqs:
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["found"] >= 1
                assert body["dispatched"] >= 1

                # Verify SQS send_message was called with correct params
                mock_sqs.send_message.assert_called()
                call_args = mock_sqs.send_message.call_args
                msg_body = json.loads(call_args.kwargs["MessageBody"])
                assert msg_body["ecosystem"] == "npm"
                assert msg_body["name"] == "incomplete-pkg"
                assert msg_body["force_refresh"] is True
                assert msg_body["reason"] == "incomplete_data_retry"
                assert "DelaySeconds" in call_args.kwargs
                assert 0 <= call_args.kwargs["DelaySeconds"] <= 300

    @mock_aws
    def test_dispatches_minimal_status_packages(self, mock_dynamodb):
        """Should also dispatch packages with 'minimal' data_status."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add a package with minimal status
        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "pypi#minimal-pkg",
                "sk": "LATEST",
                "data_status": "minimal",
                "next_retry_at": (now - timedelta(hours=1)).isoformat(),
                "retry_count": 1,
                "tier": 3,
            }
        )

        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs") as mock_sqs:
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["dispatched"] >= 1

                # Verify ecosystem parsed correctly
                call_args = mock_sqs.send_message.call_args
                msg_body = json.loads(call_args.kwargs["MessageBody"])
                assert msg_body["ecosystem"] == "pypi"
                assert msg_body["name"] == "minimal-pkg"

    @mock_aws
    def test_skips_packages_at_max_retry_count(self, mock_dynamodb):
        """Should not dispatch packages that have reached max retries."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add a package at max retries (should be filtered out)
        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "npm#maxed-out",
                "sk": "LATEST",
                "data_status": "partial",
                "next_retry_at": (now - timedelta(hours=1)).isoformat(),
                "retry_count": 5,  # At MAX_RETRY_COUNT
                "tier": 2,
            }
        )

        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs") as mock_sqs:
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                # Package should be filtered by retry_count < MAX_RETRY_COUNT
                assert body["dispatched"] == 0
                mock_sqs.send_message.assert_not_called()

    @mock_aws
    def test_skips_packages_with_invalid_pk_format(self, mock_dynamodb):
        """Should skip packages with invalid pk format (no # separator)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add a package with invalid pk (no ecosystem#name format)
        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "invalid-pk-no-hash",
                "sk": "LATEST",
                "data_status": "partial",
                "next_retry_at": (now - timedelta(hours=1)).isoformat(),
                "retry_count": 1,
            }
        )

        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs") as mock_sqs:
                result = module.handler({}, None)

                # Should complete without error
                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                # Invalid pk should be skipped, not dispatched
                assert body["dispatched"] == 0
                mock_sqs.send_message.assert_not_called()

    @mock_aws
    def test_handles_sqs_send_errors_gracefully(self, mock_dynamodb):
        """Should continue processing after SQS send errors."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add packages
        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "npm#failing-pkg",
                "sk": "LATEST",
                "data_status": "partial",
                "next_retry_at": (now - timedelta(hours=1)).isoformat(),
                "retry_count": 1,
                "tier": 2,
            }
        )

        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs") as mock_sqs:
                mock_sqs.send_message.side_effect = Exception("SQS unavailable")

                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["errors"] >= 1

    @mock_aws
    def test_handles_dynamodb_query_errors_gracefully(self, mock_dynamodb):
        """Should handle DynamoDB query errors gracefully."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "dynamodb") as mock_db:
                mock_table = MagicMock()
                mock_table.query.side_effect = Exception("DynamoDB unavailable")
                mock_db.Table.return_value = mock_table

                result = module.handler({}, None)

                # Should complete but with no packages found
                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["found"] == 0

    @mock_aws
    def test_updates_retry_dispatched_at(self, mock_dynamodb):
        """Should update retry_dispatched_at to prevent duplicate dispatches."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add a package that is due for retry
        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "npm#update-test",
                "sk": "LATEST",
                "data_status": "partial",
                "next_retry_at": (now - timedelta(hours=1)).isoformat(),
                "retry_count": 1,
                "tier": 2,
            }
        )

        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs") as mock_sqs:
                result = module.handler({}, None)

                assert result["statusCode"] == 200

                # Verify retry_dispatched_at was updated
                item = table.get_item(Key={"pk": "npm#update-test", "sk": "LATEST"})
                assert "retry_dispatched_at" in item["Item"]

    @mock_aws
    def test_skips_recently_dispatched_packages(self, mock_dynamodb):
        """Should skip packages that were dispatched within the last hour."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add a package that was recently dispatched (30 minutes ago)
        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "npm#recent-dispatch",
                "sk": "LATEST",
                "data_status": "partial",
                "next_retry_at": (now - timedelta(hours=2)).isoformat(),
                "retry_count": 1,
                "retry_dispatched_at": (now - timedelta(minutes=30)).isoformat(),
                "tier": 2,
            }
        )

        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs") as mock_sqs:
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                # Recently dispatched package should be filtered out
                assert body["dispatched"] == 0
                mock_sqs.send_message.assert_not_called()

    @mock_aws
    def test_respects_max_dispatch_limit(self, mock_dynamodb):
        """Should not dispatch more than MAX_DISPATCH_PER_RUN packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"
        # Set explicit limit for this test (default is now 300)
        os.environ["MAX_DISPATCH_PER_RUN"] = "100"

        # Add 150 packages (more than MAX_DISPATCH_PER_RUN=100)
        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        for i in range(150):
            table.put_item(
                Item={
                    "pk": f"npm#pkg-{i}",
                    "sk": "LATEST",
                    "data_status": "partial",
                    "next_retry_at": (now - timedelta(hours=1)).isoformat(),
                    "retry_count": 1,
                    "tier": 2,
                }
            )

        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs") as mock_sqs:
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                # Should be capped at MAX_DISPATCH_PER_RUN (set to 100 for this test)
                assert body["dispatched"] <= 100
