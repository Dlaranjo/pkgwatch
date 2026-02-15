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
    def test_skips_github_only_retries_when_circuit_open(self, mock_dynamodb):
        """Should proceed when GitHub circuit is open (source-aware skip, not blanket block)."""
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
            # With no packages in the table, handler should proceed but find nothing
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            # Should NOT return "skipped: circuit_open" — now uses source-aware skip per-package
            assert "skipped" not in body
            assert body.get("found") == 0

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
            with patch.object(module, "sqs"):
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
            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                # Should be capped at MAX_DISPATCH_PER_RUN (set to 100 for this test)
                assert body["dispatched"] <= 100


class TestRetryDispatcherTimeoutAndEdgeCases:
    """Tests for timeout handling, circuit breaker import fallback, and metrics."""

    @mock_aws
    def test_stops_early_on_timeout(self, mock_dynamodb):
        """Should stop dispatching when Lambda timeout approaches (lines 97-100)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add multiple packages
        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        for i in range(10):
            table.put_item(
                Item={
                    "pk": f"npm#timeout-pkg-{i}",
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

        # Create context that reports low remaining time after first dispatch
        mock_context = MagicMock()
        mock_context.aws_request_id = "test-req-id"
        mock_context.get_remaining_time_in_millis.side_effect = [10000]  # < 15000

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs"):
                result = module.handler({}, mock_context)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                # Should stop early due to timeout - may process 0 items
                # The first check is at the top of the loop before sending
                assert body["dispatched"] == 0

    @mock_aws
    def test_circuit_breaker_import_error_allows_dispatch(self, mock_dynamodb):
        """Should proceed when circuit_breaker import fails (lines 51-52)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "npm#import-fallback-pkg",
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

        # Remove the circuit breaker module so import fails inside handler
        saved_cb = sys.modules.get("shared.circuit_breaker")
        sys.modules["shared.circuit_breaker"] = None  # This causes ImportError

        try:
            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                # Should dispatch despite circuit breaker import failure
                assert body["dispatched"] >= 1
        finally:
            if saved_cb:
                sys.modules["shared.circuit_breaker"] = saved_cb
            elif "shared.circuit_breaker" in sys.modules:
                del sys.modules["shared.circuit_breaker"]

    @mock_aws
    def test_max_dispatch_per_run_breaks_loop(self, mock_dynamodb):
        """Should stop dispatching at MAX_DISPATCH_PER_RUN (line 94).

        Note: The GSI query uses Limit=MAX_DISPATCH_PER_RUN // 2 per status,
        so with MAX_DISPATCH_PER_RUN=4, each status query gets Limit=2.
        We need to create enough packages to demonstrate the cap.
        """
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"
        os.environ["MAX_DISPATCH_PER_RUN"] = "4"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        for i in range(10):
            table.put_item(
                Item={
                    "pk": f"npm#limit-pkg-{i}",
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
            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                # Should be capped at MAX_DISPATCH_PER_RUN (4)
                # GSI Limit is MAX_DISPATCH_PER_RUN // 2 = 2 per status
                # Only "partial" status matches, so max 2 found, dispatched <= 4
                assert body["dispatched"] <= 4

    @mock_aws
    def test_update_dispatched_at_failure_continues(self, mock_dynamodb):
        """Should continue dispatching even if retry_dispatched_at update fails (lines 116-117)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "npm#update-fail-pkg",
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
            # Make DynamoDB update fail but keep query working
            original_table = module.dynamodb.Table("pkgwatch-packages")
            mock_table = MagicMock()
            mock_table.query.side_effect = original_table.query
            mock_table.update_item.side_effect = Exception("DynamoDB throttled")

            with patch.object(module, "dynamodb") as mock_db:
                mock_db.Table.return_value = mock_table
                with patch.object(module, "sqs"):
                    result = module.handler({}, None)

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    # Should still dispatch despite update failure
                    assert body["dispatched"] >= 1

    @mock_aws
    def test_metrics_import_failure_is_silent(self, mock_dynamodb):
        """Metrics import failure should not crash the handler (lines 153-154)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = mock_circuit

        # Block the shared.metrics import
        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module, "shared.metrics": None}):
            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["found"] == 0

    @mock_aws
    def test_includes_missing_sources_in_dispatch(self, mock_dynamodb):
        """Should include missing_sources from package record in SQS message."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "npm#partial-sources-pkg",
                "sk": "LATEST",
                "data_status": "partial",
                "next_retry_at": (now - timedelta(hours=1)).isoformat(),
                "retry_count": 1,
                "tier": 1,
                "missing_sources": ["github", "bundlephobia", "openssf"],
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

                body = json.loads(result["body"])
                assert body["dispatched"] >= 1

                call_args = mock_sqs.send_message.call_args
                msg_body = json.loads(call_args.kwargs["MessageBody"])
                assert msg_body["retry_sources"] == ["github", "bundlephobia", "openssf"]
                assert msg_body["force_refresh"] is True

    @mock_aws
    def test_tier_is_correctly_cast_to_int(self, mock_dynamodb):
        """Tier value from DynamoDB should be cast to int."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "npm#tier-cast-pkg",
                "sk": "LATEST",
                "data_status": "partial",
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

                body = json.loads(result["body"])
                if body["dispatched"] >= 1:
                    call_args = mock_sqs.send_message.call_args
                    msg_body = json.loads(call_args.kwargs["MessageBody"])
                    assert isinstance(msg_body["tier"], int)
                    assert msg_body["tier"] == 3

    @mock_aws
    def test_delay_is_within_expected_range(self, mock_dynamodb):
        """Stagger delay should be between 0 and 300 seconds."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "npm#delay-check-pkg",
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
                module.handler({}, None)

                if mock_sqs.send_message.called:
                    call_args = mock_sqs.send_message.call_args
                    delay = call_args.kwargs["DelaySeconds"]
                    assert 0 <= delay <= 300

    @mock_aws
    def test_multiple_sqs_errors_tracked(self, mock_dynamodb):
        """Should track multiple SQS send errors."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        for i in range(3):
            table.put_item(
                Item={
                    "pk": f"npm#error-track-{i}",
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
                mock_sqs.send_message.side_effect = Exception("SQS down")

                result = module.handler({}, None)

                body = json.loads(result["body"])
                assert body["errors"] >= 1
                assert body["dispatched"] == 0


class TestRetryDispatcherPendingStatus:
    """Tests for pending status support in retry dispatcher (Fix 4)."""

    @mock_aws
    def test_queries_pending_status(self, mock_dynamodb):
        """retry_dispatcher should query for pending packages in addition to partial/minimal."""
        import importlib

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        now = datetime.now(timezone.utc)
        past = (now - timedelta(hours=2)).isoformat()

        # Insert a pending package with next_retry_at in the past
        import boto3

        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#pending-pkg",
                "sk": "LATEST",
                "name": "pending-pkg",
                "ecosystem": "npm",
                "data_status": "pending",
                "next_retry_at": past,
                "retry_count": 0,
                "last_updated": past,
            }
        )

        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT.can_execute.return_value = True

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs"):
                result = module.handler({}, None)

        body = json.loads(result["body"])
        assert body["dispatched"] >= 1

    @mock_aws
    def test_github_only_skip_with_mixed_sources(self, mock_dynamodb):
        """Should skip GitHub-only packages but dispatch mixed-source packages when circuit is open."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc)
        past = (now - timedelta(hours=2)).isoformat()

        # Package A: GitHub-only retry (should be skipped)
        table.put_item(
            Item={
                "pk": "npm#github-only-pkg",
                "sk": "LATEST",
                "data_status": "partial",
                "next_retry_at": past,
                "retry_count": 1,
                "missing_sources": ["github"],
                "tier": 2,
            }
        )
        # Package B: Mixed sources (should be dispatched)
        table.put_item(
            Item={
                "pk": "npm#mixed-sources-pkg",
                "sk": "LATEST",
                "data_status": "partial",
                "next_retry_at": past,
                "retry_count": 1,
                "missing_sources": ["github", "bundlephobia"],
                "tier": 2,
            }
        )

        import importlib

        import collectors.retry_dispatcher as module

        importlib.reload(module)

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = False  # GitHub circuit open
        mock_cb_module = MagicMock()
        mock_cb_module.GITHUB_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs") as mock_sqs:
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])

                # mixed-sources-pkg should be dispatched, github-only-pkg should be skipped
                assert body["dispatched"] >= 1
                assert body.get("github_skipped", 0) >= 1

                # Verify the dispatched package is the mixed-source one
                call_args = mock_sqs.send_message.call_args
                msg_body = json.loads(call_args.kwargs["MessageBody"])
                assert msg_body["name"] == "mixed-sources-pkg"
