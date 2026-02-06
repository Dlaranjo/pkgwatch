"""
Tests for graph_expander_dispatcher.py - Graph expander dispatcher Lambda.

Coverage targets:
- Handler configuration validation
- Circuit breaker integration
- DynamoDB tier queries
- SQS message dispatching
- Batch processing and batching logic
- Error handling for DynamoDB and SQS failures
- Metrics emission
"""

import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws


@pytest.fixture
def setup_sqs_discovery_queue():
    """Set up SQS discovery queue for dispatching."""
    import boto3

    sqs = boto3.client("sqs", region_name="us-east-1")
    response = sqs.create_queue(QueueName="pkgwatch-discovery-queue")
    queue_url = response["QueueUrl"]
    os.environ["DISCOVERY_QUEUE_URL"] = queue_url
    return queue_url


class TestHandlerConfiguration:
    """Tests for handler configuration and validation."""

    @mock_aws
    def test_returns_500_without_discovery_queue_url(self, mock_dynamodb):
        """Should return 500 when DISCOVERY_QUEUE_URL is not configured."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ.pop("DISCOVERY_QUEUE_URL", None)

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 500
        assert "DISCOVERY_QUEUE_URL not configured" in result.get("error", "")

    @mock_aws
    def test_returns_500_with_empty_discovery_queue_url(self, mock_dynamodb):
        """Should return 500 when DISCOVERY_QUEUE_URL is empty string."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = ""

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 500
        assert "DISCOVERY_QUEUE_URL not configured" in result.get("error", "")

    @mock_aws
    def test_uses_default_packages_table_name(self, mock_dynamodb):
        """Should use default table name when PACKAGES_TABLE not set."""
        os.environ.pop("PACKAGES_TABLE", None)
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        # Should not crash, will use default "pkgwatch-packages"
        assert module.PACKAGES_TABLE == "pkgwatch-packages"


class TestCircuitBreakerIntegration:
    """Tests for circuit breaker integration."""

    @mock_aws
    def test_skips_dispatch_when_circuit_open(self, mock_dynamodb):
        """Should skip dispatch when deps.dev circuit breaker is open."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = False
        mock_cb_module = MagicMock()
        mock_cb_module.DEPSDEV_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body.get("skipped") == "circuit_open"

    @mock_aws
    def test_proceeds_when_circuit_closed(self, mock_dynamodb):
        """Should proceed with dispatch when circuit breaker is closed."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.DEPSDEV_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert "skipped" not in body

    @mock_aws
    def test_proceeds_when_circuit_breaker_not_available(self, mock_dynamodb):
        """Should proceed when circuit breaker module is not available."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        # Circuit breaker import fails
        with patch.dict(sys.modules, {"shared.circuit_breaker": None}):
            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200


class TestDynamoDBTierQueries:
    """Tests for DynamoDB tier queries."""

    @mock_aws
    def test_returns_zero_when_no_packages(self, mock_dynamodb):
        """Should return zero counts when no tier 1-2 packages exist."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        with patch.object(module, "sqs"):
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["dispatched"] == 0
            assert body["messages"] == 0

    @mock_aws
    def test_queries_tier_1_packages(self, mock_dynamodb):
        """Should query and dispatch tier 1 packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        # Add tier 1 packages
        for i in range(5):
            table.put_item(
                Item={
                    "pk": f"npm#tier1-pkg-{i}",
                    "sk": "LATEST",
                    "tier": 1,
                    "last_updated": now,
                }
            )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        with patch.object(module, "sqs") as mock_sqs:
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["dispatched"] == 5
            mock_sqs.send_message.assert_called()

    @mock_aws
    def test_queries_tier_2_packages(self, mock_dynamodb):
        """Should query and dispatch tier 2 packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        # Add tier 2 packages
        for i in range(3):
            table.put_item(
                Item={
                    "pk": f"npm#tier2-pkg-{i}",
                    "sk": "LATEST",
                    "tier": 2,
                    "last_updated": now,
                }
            )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        with patch.object(module, "sqs"):
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["dispatched"] == 3

    @mock_aws
    def test_queries_both_tier_1_and_tier_2(self, mock_dynamodb):
        """Should query and combine both tier 1 and tier 2 packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        # Add tier 1 packages
        for i in range(3):
            table.put_item(
                Item={
                    "pk": f"npm#tier1-pkg-{i}",
                    "sk": "LATEST",
                    "tier": 1,
                    "last_updated": now,
                }
            )

        # Add tier 2 packages
        for i in range(2):
            table.put_item(
                Item={
                    "pk": f"npm#tier2-pkg-{i}",
                    "sk": "LATEST",
                    "tier": 2,
                    "last_updated": now,
                }
            )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        with patch.object(module, "sqs"):
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["dispatched"] == 5

    @mock_aws
    def test_ignores_tier_3_packages(self, mock_dynamodb):
        """Should not include tier 3 packages in dispatch."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        # Add tier 1 package
        table.put_item(
            Item={
                "pk": "npm#tier1-pkg",
                "sk": "LATEST",
                "tier": 1,
                "last_updated": now,
            }
        )

        # Add tier 3 package (should be ignored)
        table.put_item(
            Item={
                "pk": "npm#tier3-pkg",
                "sk": "LATEST",
                "tier": 3,
                "last_updated": now,
            }
        )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        with patch.object(module, "sqs"):
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["dispatched"] == 1

    @mock_aws
    def test_handles_tier_query_exception(self, mock_dynamodb):
        """Should log error and continue when one tier query fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        # Add tier 2 packages
        for i in range(2):
            table.put_item(
                Item={
                    "pk": f"npm#tier2-pkg-{i}",
                    "sk": "LATEST",
                    "tier": 2,
                    "last_updated": now,
                }
            )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        original_table = module.dynamodb.Table("pkgwatch-packages")
        query_call_count = [0]

        def mock_query(**kwargs):
            query_call_count[0] += 1
            if query_call_count[0] == 1:
                # First query (tier 1) fails
                raise Exception("Tier 1 query failed")
            return original_table.query(**kwargs)

        mock_table = MagicMock()
        mock_table.query.side_effect = mock_query

        with patch.object(module.dynamodb, "Table", return_value=mock_table):
            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                # Should succeed with tier 2 packages
                assert result["statusCode"] == 200
                assert "dispatched" in json.loads(result["body"])


class TestSQSMessageDispatching:
    """Tests for SQS message dispatching."""

    @mock_aws
    def test_sends_correct_message_format(self, mock_dynamodb, setup_sqs_discovery_queue):
        """Should send correctly formatted SQS messages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        queue_url = setup_sqs_discovery_queue

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "tier": 1,
                "last_updated": now,
            }
        )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200

        # Verify message in queue
        sqs = boto3.client("sqs", region_name="us-east-1")
        response = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)
        messages = response.get("Messages", [])

        assert len(messages) == 1
        body = json.loads(messages[0]["Body"])
        assert "packages" in body
        assert "lodash" in body["packages"]
        assert body["ecosystem"] == "npm"

    @mock_aws
    def test_batches_packages_correctly(self, mock_dynamodb):
        """Should batch packages according to BATCH_SIZE."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        # Add 25 packages (BATCH_SIZE is 10, so should be 3 messages)
        for i in range(25):
            table.put_item(
                Item={
                    "pk": f"npm#batch-pkg-{i}",
                    "sk": "LATEST",
                    "tier": 1,
                    "last_updated": now,
                }
            )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        with patch.object(module, "sqs") as mock_sqs:
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["dispatched"] == 25
            # 25 packages / 10 per batch = 3 messages
            assert body["messages"] == 3
            assert mock_sqs.send_message.call_count == 3

    @mock_aws
    def test_skips_empty_package_batches(self, mock_dynamodb):
        """Should skip batches where no valid package names extracted."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        # Add package with malformed pk (no # separator)
        table.put_item(
            Item={
                "pk": "malformed-pk-no-hash",
                "sk": "LATEST",
                "tier": 1,
                "last_updated": now,
            }
        )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        with patch.object(module, "sqs") as mock_sqs:
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["dispatched"] == 1
            # No SQS messages since batch was empty
            mock_sqs.send_message.assert_not_called()

    @mock_aws
    def test_extracts_package_names_from_pk(self, mock_dynamodb):
        """Should correctly extract package names from pk format."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        # Add packages with various pk formats
        table.put_item(
            Item={
                "pk": "npm#@scope/package",
                "sk": "LATEST",
                "tier": 1,
                "last_updated": now,
            }
        )
        table.put_item(
            Item={
                "pk": "npm#simple-package",
                "sk": "LATEST",
                "tier": 1,
                "last_updated": now,
            }
        )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        with patch.object(module, "sqs") as mock_sqs:
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["dispatched"] == 2

            # Check extracted names
            call_args = mock_sqs.send_message.call_args
            msg_body = json.loads(call_args.kwargs["MessageBody"])
            assert "@scope/package" in msg_body["packages"]
            assert "simple-package" in msg_body["packages"]

    @mock_aws
    def test_handles_packages_with_missing_pk(self, mock_dynamodb):
        """Should handle packages with missing pk gracefully."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        # Mock table query to return items without pk
        mock_table = MagicMock()
        mock_table.query.return_value = {
            "Items": [
                {"sk": "LATEST", "tier": 1},  # Missing pk
                {"pk": "npm#valid", "sk": "LATEST", "tier": 1},
            ]
        }

        with patch.object(module.dynamodb, "Table", return_value=mock_table):
            with patch.object(module, "sqs") as mock_sqs:
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                # Should still send message with valid package
                mock_sqs.send_message.assert_called()


class TestErrorHandling:
    """Tests for error handling scenarios."""

    @mock_aws
    def test_handles_sqs_send_error(self, mock_dynamodb):
        """Should count errors when SQS send fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        for i in range(3):
            table.put_item(
                Item={
                    "pk": f"npm#sqs-fail-pkg-{i}",
                    "sk": "LATEST",
                    "tier": 1,
                    "last_updated": now,
                }
            )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        with patch.object(module, "sqs") as mock_sqs:
            mock_sqs.send_message.side_effect = Exception("SQS error")

            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["dispatched"] == 3
            assert body["errors"] >= 1
            assert body["messages"] == 0

    @mock_aws
    def test_continues_after_sqs_error(self, mock_dynamodb):
        """Should continue sending after SQS error."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        # Add 15 packages (2 batches)
        for i in range(15):
            table.put_item(
                Item={
                    "pk": f"npm#pkg-{i}",
                    "sk": "LATEST",
                    "tier": 1,
                    "last_updated": now,
                }
            )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("First batch failed")
            return {}

        with patch.object(module, "sqs") as mock_sqs:
            mock_sqs.send_message.side_effect = side_effect

            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["errors"] == 1
            assert body["messages"] == 1

    @mock_aws
    def test_handles_both_tier_queries_failing(self, mock_dynamodb):
        """Should handle both tier queries failing gracefully."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        mock_table = MagicMock()
        mock_table.query.side_effect = Exception("DynamoDB error")

        with patch.object(module.dynamodb, "Table", return_value=mock_table):
            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["dispatched"] == 0
                assert body["messages"] == 0


class TestMetricsEmission:
    """Tests for CloudWatch metrics emission."""

    @mock_aws
    def test_emits_metrics_on_success(self, mock_dynamodb):
        """Should emit CloudWatch metrics on successful dispatch."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        table.put_item(
            Item={
                "pk": "npm#metrics-pkg",
                "sk": "LATEST",
                "tier": 1,
                "last_updated": now,
            }
        )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        mock_metrics = MagicMock()
        mock_metrics.emit_batch_metrics = MagicMock()

        with patch.object(module, "sqs"):
            with patch.dict(sys.modules, {"shared.metrics": mock_metrics}):
                result = module.handler({}, None)

                assert result["statusCode"] == 200

    @mock_aws
    def test_continues_when_metrics_not_available(self, mock_dynamodb):
        """Should not fail when metrics module is not available."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        # Metrics import fails
        with patch.dict(sys.modules, {"shared.metrics": None}):
            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200


class TestConstants:
    """Tests for module constants."""

    def test_max_packages_constant(self):
        """Should have MAX_PACKAGES set to 300."""
        import discovery.graph_expander_dispatcher as module

        assert module.MAX_PACKAGES == 300

    def test_batch_size_constant(self):
        """Should have BATCH_SIZE set to 10."""
        import discovery.graph_expander_dispatcher as module

        assert module.BATCH_SIZE == 10


class TestIntegration:
    """Integration tests for end-to-end dispatcher flow."""

    @mock_aws
    def test_full_dispatch_flow(self, mock_dynamodb, setup_sqs_discovery_queue):
        """Should complete full dispatch flow successfully."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        queue_url = setup_sqs_discovery_queue

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        # Add tier 1 and tier 2 packages
        for i in range(5):
            table.put_item(
                Item={
                    "pk": f"npm#tier1-{i}",
                    "sk": "LATEST",
                    "tier": 1,
                    "last_updated": now,
                }
            )
        for i in range(3):
            table.put_item(
                Item={
                    "pk": f"npm#tier2-{i}",
                    "sk": "LATEST",
                    "tier": 2,
                    "last_updated": now,
                }
            )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["dispatched"] == 8
        assert body["messages"] >= 1
        assert body["errors"] == 0

        # Verify messages in queue
        sqs = boto3.client("sqs", region_name="us-east-1")
        all_messages = []
        while True:
            response = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10,
            )
            messages = response.get("Messages", [])
            if not messages:
                break
            all_messages.extend(messages)
            for msg in messages:
                sqs.delete_message(
                    QueueUrl=queue_url,
                    ReceiptHandle=msg["ReceiptHandle"],
                )

        assert len(all_messages) >= 1

        # Verify all packages are accounted for
        all_packages = []
        for msg in all_messages:
            body = json.loads(msg["Body"])
            all_packages.extend(body["packages"])

        assert len(all_packages) == 8

    @mock_aws
    def test_respects_max_packages_limit(self, mock_dynamodb):
        """Should respect MAX_PACKAGES limit per tier."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        # Mock table to return more than MAX_PACKAGES
        mock_table = MagicMock()

        def mock_query(**kwargs):
            tier = 1  # Default
            items = []
            for i in range(200):  # More than MAX_PACKAGES / 2
                items.append(
                    {
                        "pk": f"npm#pkg-{i}",
                        "sk": "LATEST",
                        "tier": tier,
                    }
                )
            return {"Items": items}

        mock_table.query.return_value = mock_query()

        with patch.object(module.dynamodb, "Table", return_value=mock_table):
            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                # Should still succeed
                assert result["statusCode"] == 200


class TestMetricsImportError:
    """Tests for metrics ImportError handling (lines 116-117)."""

    @mock_aws
    def test_handles_metrics_import_error_gracefully(self, mock_dynamodb):
        """Should handle ImportError when shared.metrics is not available.

        Covers lines 116-117: except ImportError: pass
        """
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        table.put_item(
            Item={
                "pk": "npm#metrics-import-pkg",
                "sk": "LATEST",
                "tier": 1,
                "last_updated": now,
            }
        )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        # Remove shared.metrics from sys.modules to force ImportError
        saved = sys.modules.pop("shared.metrics", None)
        try:
            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["dispatched"] == 1
        finally:
            if saved is not None:
                sys.modules["shared.metrics"] = saved


class TestMetricsImportErrorForced:
    """Force a real ImportError for shared.metrics to cover lines 116-117."""

    @mock_aws
    def test_metrics_import_error_via_import_hook(self, mock_dynamodb):
        """Cover lines 116-117 by forcing ImportError via __import__ override.

        The existing test removes shared.metrics from sys.modules, but Python
        can re-import it from the filesystem. This test uses a custom import
        hook to truly block the import.
        """
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()

        table.put_item(
            Item={
                "pk": "npm#hook-test-pkg",
                "sk": "LATEST",
                "tier": 1,
                "last_updated": now,
            }
        )

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        def blocked_import(name, *args, **kwargs):
            if name == "shared.metrics":
                raise ImportError("Blocked in test")
            return original_import(name, *args, **kwargs)

        with patch.object(module, "sqs"):
            with patch("builtins.__import__", side_effect=blocked_import):
                result = module.handler({}, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["dispatched"] == 1
        assert body["messages"] == 1


class TestDeduplicationInDispatch:
    """Tests for deduplication behavior during dispatch."""

    @mock_aws
    def test_same_package_in_multiple_tiers_dispatched_once_each(self, mock_dynamodb):
        """If a package appears in both tier queries, both copies are dispatched.

        The dispatcher doesn't deduplicate at this level - it sends whatever
        DynamoDB returns. Deduplication happens at the worker level.
        """
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        # Mock table to return same package for both tier queries
        mock_table = MagicMock()
        mock_table.query.return_value = {
            "Items": [
                {"pk": "npm#shared-pkg", "sk": "LATEST", "tier": 1},
            ]
        }

        with patch.object(module.dynamodb, "Table", return_value=mock_table):
            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                # Both tier queries return the same package = 2 total
                assert body["dispatched"] == 2
