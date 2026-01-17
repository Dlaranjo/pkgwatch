"""
Tests for the package discovery system.

Tests cover:
- Graph expander dispatcher
- Graph expander worker
- Publish top packages
- npms.io audit
"""

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from moto import mock_aws


class TestGraphExpanderDispatcher:
    """Tests for the graph expander dispatcher Lambda."""

    @mock_aws
    def test_returns_error_without_discovery_queue_url(self, mock_dynamodb):
        """Should return 500 when DISCOVERY_QUEUE_URL is not configured."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = ""

        import importlib
        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 500
        assert "DISCOVERY_QUEUE_URL not configured" in result.get("error", "")

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
    def test_returns_zero_when_no_packages(self, mock_dynamodb):
        """Should return zero counts when no tier 1-2 packages exist."""
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
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["dispatched"] == 0
            assert body["messages"] == 0

    @mock_aws
    def test_dispatches_tier_1_packages(self, mock_dynamodb):
        """Should dispatch tier 1 packages for discovery."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add tier 1 packages
        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()
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

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.DEPSDEV_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs") as mock_sqs:
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["dispatched"] == 5
                assert body["messages"] >= 1

                # Verify SQS message format
                mock_sqs.send_message.assert_called()
                call_args = mock_sqs.send_message.call_args
                msg_body = json.loads(call_args.kwargs["MessageBody"])
                assert "packages" in msg_body
                assert msg_body["ecosystem"] == "npm"

    @mock_aws
    def test_handles_tier_query_exception(self, mock_dynamodb):
        """Should log error and continue when one tier query fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add tier 2 packages only
        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()
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

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.DEPSDEV_CIRCUIT = mock_circuit

        # Create a mock table that fails on tier 1 query
        original_table = module.dynamodb.Table("pkgwatch-packages")
        query_call_count = [0]

        def mock_query(**kwargs):
            query_call_count[0] += 1
            if kwargs.get("KeyConditionExpression") and query_call_count[0] == 1:
                # First query (tier 1) fails
                raise Exception("Tier 1 query failed")
            # Tier 2 query succeeds
            return original_table.query(**kwargs)

        mock_table = MagicMock()
        mock_table.query.side_effect = mock_query

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module.dynamodb, "Table", return_value=mock_table):
                with patch.object(module, "sqs") as mock_sqs:
                    result = module.handler({}, None)

                    # Should still succeed with tier 2 packages
                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    # May have 0 or some packages depending on mock behavior
                    assert "dispatched" in body

    @mock_aws
    def test_skips_empty_package_batches(self, mock_dynamodb):
        """Should skip batches where no valid package names extracted."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add packages with malformed pk (no # separator)
        table = mock_dynamodb.Table("pkgwatch-packages")
        now = datetime.now(timezone.utc).isoformat()
        table.put_item(
            Item={
                "pk": "malformed-pk-no-hash",  # Missing # separator
                "sk": "LATEST",
                "tier": 1,
                "last_updated": now,
            }
        )

        import importlib
        import discovery.graph_expander_dispatcher as module

        importlib.reload(module)

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.DEPSDEV_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs") as mock_sqs:
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                # Dispatched count is the raw packages found
                assert body["dispatched"] == 1
                # But no SQS messages sent since batch was empty
                mock_sqs.send_message.assert_not_called()

    @mock_aws
    def test_handles_sqs_send_error(self, mock_dynamodb):
        """Should count errors when SQS send fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["DISCOVERY_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add valid tier 1 packages
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

        mock_circuit = MagicMock()
        mock_circuit.can_execute.return_value = True
        mock_cb_module = MagicMock()
        mock_cb_module.DEPSDEV_CIRCUIT = mock_circuit

        with patch.dict(sys.modules, {"shared.circuit_breaker": mock_cb_module}):
            with patch.object(module, "sqs") as mock_sqs:
                mock_sqs.send_message.side_effect = Exception("SQS error")

                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["dispatched"] == 3
                assert body["errors"] >= 1
                assert body["messages"] == 0


class TestGraphExpanderWorker:
    """Tests for the graph expander worker Lambda."""

    @mock_aws
    def test_processes_empty_records(self, mock_dynamodb):
        """Should handle empty records gracefully."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import discovery.graph_expander_worker as module

        importlib.reload(module)

        result = module.handler({"Records": []}, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["processed"] == 0
        assert body["discovered"] == 0

    @mock_aws
    def test_processes_sqs_message(self, mock_dynamodb):
        """Should process SQS messages and call process_package."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {
                    "body": json.dumps({
                        "packages": ["lodash", "express"],
                        "ecosystem": "npm",
                    })
                }
            ]
        }

        with patch.object(module, "process_package", new_callable=AsyncMock) as mock_process:
            mock_process.return_value = 1  # 1 package discovered

            result = module.handler(event, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["processed"] == 2
            assert mock_process.call_count == 2

    @mock_aws
    def test_package_exists_check(self, mock_dynamodb):
        """Should correctly check if package exists."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        # Add existing package
        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#existing",
                "sk": "LATEST",
                "name": "existing",
            }
        )

        import importlib
        import discovery.graph_expander_worker as module

        importlib.reload(module)

        assert module.package_exists(table, "npm", "existing") is True
        assert module.package_exists(table, "npm", "nonexistent") is False

    @mock_aws
    def test_queue_for_collection(self, mock_dynamodb):
        """Should queue package for collection via SQS."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import discovery.graph_expander_worker as module

        importlib.reload(module)

        with patch.object(module, "sqs") as mock_sqs:
            module.queue_for_collection("npm", "new-package")

            mock_sqs.send_message.assert_called_once()
            call_args = mock_sqs.send_message.call_args
            msg_body = json.loads(call_args.kwargs["MessageBody"])
            assert msg_body["ecosystem"] == "npm"
            assert msg_body["name"] == "new-package"
            assert msg_body["reason"] == "graph_expansion_discovery"


class TestPublishTopPackages:
    """Tests for the publish top packages Lambda."""

    @mock_aws
    def test_returns_error_without_public_bucket(self, mock_dynamodb):
        """Should return 500 when PUBLIC_BUCKET is not configured."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = ""

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 500
        assert "PUBLIC_BUCKET not configured" in result.get("error", "")

    @mock_aws
    def test_returns_zero_when_no_packages(self, mock_dynamodb):
        """Should return zero when no packages exist."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        with patch.object(module, "s3"):
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["published"] == 0

    @mock_aws
    def test_publishes_packages_to_s3(self, mock_dynamodb):
        """Should publish packages list to S3."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        # Add packages with downloads
        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "name": "lodash",
                "ecosystem": "npm",
                "weekly_downloads": 5000000,
                "health_score": 90,
                "risk_level": "LOW",
            }
        )
        table.put_item(
            Item={
                "pk": "npm#express",
                "sk": "LATEST",
                "name": "express",
                "ecosystem": "npm",
                "weekly_downloads": 3000000,
                "health_score": 85,
                "risk_level": "LOW",
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        with patch.object(module, "s3") as mock_s3:
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["published"] == 2

            # Verify S3 put_object was called (both main and top-100)
            assert mock_s3.put_object.call_count >= 1
            # Check that the main file was uploaded
            call_keys = [call.kwargs["Key"] for call in mock_s3.put_object.call_args_list]
            assert "data/top-npm-packages.json" in call_keys

    @mock_aws
    def test_skips_packages_without_downloads(self, mock_dynamodb):
        """Should skip packages missing weekly_downloads field."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        # Add package without weekly_downloads
        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#no-downloads",
                "sk": "LATEST",
                "name": "no-downloads",
                "ecosystem": "npm",
                "health_score": 50,
            }
        )
        # Add package with weekly_downloads
        table.put_item(
            Item={
                "pk": "npm#with-downloads",
                "sk": "LATEST",
                "name": "with-downloads",
                "ecosystem": "npm",
                "weekly_downloads": 1000,
                "health_score": 60,
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        with patch.object(module, "s3") as mock_s3:
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            # Only the package with downloads should be published
            assert body["published"] == 1

    @mock_aws
    def test_handles_query_exception(self, mock_dynamodb):
        """Should return 500 when DynamoDB query fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        mock_table = MagicMock()
        mock_table.query.side_effect = Exception("DynamoDB error")

        with patch.object(module.dynamodb, "Table", return_value=mock_table):
            result = module.handler({}, None)

            assert result["statusCode"] == 500
            assert "DynamoDB error" in result.get("error", "")

    @mock_aws
    def test_handles_s3_upload_error(self, mock_dynamodb):
        """Should return 500 when S3 upload fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "LATEST",
                "name": "test-pkg",
                "ecosystem": "npm",
                "weekly_downloads": 1000,
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = Exception("S3 upload failed")

        with patch.object(module, "s3", mock_s3):
            result = module.handler({}, None)

            assert result["statusCode"] == 500
            assert "S3 upload failed" in result.get("error", "")

    @mock_aws
    def test_handles_top100_upload_error(self, mock_dynamodb):
        """Should succeed even when top-100 upload fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "LATEST",
                "name": "test-pkg",
                "ecosystem": "npm",
                "weekly_downloads": 1000,
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        call_count = [0]

        def side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 2:  # Second call is top-100
                raise Exception("Top-100 upload failed")
            return {}

        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = side_effect

        with patch.object(module, "s3", mock_s3):
            result = module.handler({}, None)

            # Should still succeed since main file was uploaded
            assert result["statusCode"] == 200

    @mock_aws
    def test_converts_decimal_health_score(self, mock_dynamodb):
        """Should convert Decimal health_score to int."""
        from decimal import Decimal

        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#decimal-pkg",
                "sk": "LATEST",
                "name": "decimal-pkg",
                "ecosystem": "npm",
                "weekly_downloads": Decimal("5000"),
                "health_score": Decimal("85"),
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        with patch.object(module, "s3") as mock_s3:
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            # Verify S3 was called with JSON that contains int (not Decimal)
            call_args = mock_s3.put_object.call_args_list[0]
            body = json.loads(call_args.kwargs["Body"])
            assert body["rows"][0]["health_score"] == 85
            assert isinstance(body["rows"][0]["health_score"], int)

    @mock_aws
    def test_handles_pagination(self, mock_dynamodb):
        """Should paginate through large result sets."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        # Mock table.query to return paginated results
        first_page = {
            "Items": [
                {
                    "pk": "npm#pkg1",
                    "name": "pkg1",
                    "ecosystem": "npm",
                    "weekly_downloads": 1000,
                }
            ],
            "LastEvaluatedKey": {"pk": "npm#pkg1"},
        }
        second_page = {
            "Items": [
                {
                    "pk": "npm#pkg2",
                    "name": "pkg2",
                    "ecosystem": "npm",
                    "weekly_downloads": 500,
                }
            ],
        }

        mock_table = MagicMock()
        mock_table.query.side_effect = [first_page, second_page]

        with patch.object(module.dynamodb, "Table", return_value=mock_table):
            with patch.object(module, "s3") as mock_s3:
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["published"] == 2

                # Verify query was called twice (pagination)
                assert mock_table.query.call_count == 2


class TestNpmsioAudit:
    """Tests for the npms.io audit Lambda."""

    @mock_aws
    def test_returns_zero_when_no_packages_from_npmsio(self, mock_dynamodb):
        """Should return zero when npms.io returns no packages."""
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
    def test_finds_missing_packages(self, mock_dynamodb):
        """Should identify packages we don't have."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        # Add one existing package
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
                {"name": "lodash", "score": 0.9},  # Exists
                {"name": "express", "score": 0.85},  # Missing
                {"name": "react", "score": 0.95},  # Missing
            ]

            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["audited"] == 3
                assert body["missing"] == 2
                assert body["added"] == 2

    @mock_aws
    def test_skips_low_quality_packages(self, mock_dynamodb):
        """Should skip packages with score below threshold."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "low-quality-pkg", "score": 0.3},  # Below 0.5 threshold
                {"name": "high-quality-pkg", "score": 0.8},  # Above threshold
            ]

            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["missing"] == 2
                assert body["added"] == 1  # Only high quality added

    @mock_aws
    def test_queues_added_packages(self, mock_dynamodb):
        """Should queue added packages for collection."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "new-pkg", "score": 0.9},
            ]

            with patch.object(module, "sqs") as mock_sqs:
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["queued"] == 1

                # Verify SQS was called
                mock_sqs.send_message.assert_called_once()
                call_args = mock_sqs.send_message.call_args
                msg_body = json.loads(call_args.kwargs["MessageBody"])
                assert msg_body["name"] == "new-pkg"
                assert msg_body["reason"] == "npmsio_audit"

    @mock_aws
    def test_skips_packages_without_name(self, mock_dynamodb):
        """Should skip packages without name field."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import discovery.npmsio_audit as module

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"score": 0.9},  # Missing name
                {"name": "valid-pkg", "score": 0.8},
            ]

            with patch.object(module, "sqs"):
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["audited"] == 2
                # Only valid-pkg should be in missing count
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

            with patch.object(module.dynamodb, "Table", return_value=mock_table):
                with patch.object(module, "sqs"):
                    result = module.handler({}, None)

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    # Should still process ok-pkg
                    assert body["audited"] == 2

    @mock_aws
    def test_handles_conditional_check_failed(self, mock_dynamodb):
        """Should handle race condition when package already exists."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib
        import discovery.npmsio_audit as module
        from botocore.exceptions import ClientError

        importlib.reload(module)

        with patch.object(module, "fetch_npmsio_top_packages") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "race-pkg", "score": 0.9},
            ]

            mock_table = MagicMock()
            mock_table.get_item.return_value = {}  # Not found initially

            # Simulate ConditionalCheckFailedException
            error_response = {"Error": {"Code": "ConditionalCheckFailedException"}}
            mock_table.put_item.side_effect = ClientError(error_response, "PutItem")

            with patch.object(module.dynamodb, "Table", return_value=mock_table):
                with patch.object(module, "sqs"):
                    result = module.handler({}, None)

                    # Should succeed even with race condition
                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["added"] == 0  # Not added due to race


class TestFetchNpmsioTopPackages:
    """Tests for fetch_npmsio_top_packages function."""

    def test_fetch_returns_packages(self):
        """Should fetch and parse packages from npms.io."""
        import discovery.npmsio_audit as module

        # First response with packages, second response empty to stop loop
        mock_response_with_data = MagicMock()
        mock_response_with_data.json.return_value = {
            "results": [
                {
                    "package": {"name": "pkg1"},
                    "score": {"final": 0.9, "detail": {"quality": 0.8, "popularity": 0.7, "maintenance": 0.9}},
                },
                {
                    "package": {"name": "pkg2"},
                    "score": {"final": 0.8},
                },
            ]
        }

        mock_response_empty = MagicMock()
        mock_response_empty.json.return_value = {"results": []}

        with patch("discovery.npmsio_audit.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.side_effect = [
                mock_response_with_data,
                mock_response_empty,
            ]

            result = module.fetch_npmsio_top_packages(10)

            assert len(result) == 2
            assert result[0]["name"] == "pkg1"
            assert result[0]["score"] == 0.9

    def test_fetch_handles_empty_results(self):
        """Should handle empty results from npms.io."""
        import discovery.npmsio_audit as module

        mock_response = MagicMock()
        mock_response.json.return_value = {"results": []}

        with patch("discovery.npmsio_audit.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_response

            result = module.fetch_npmsio_top_packages(10)

            assert result == []

    def test_fetch_handles_http_error(self):
        """Should handle HTTP errors gracefully."""
        import discovery.npmsio_audit as module

        with patch("discovery.npmsio_audit.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.side_effect = httpx.HTTPStatusError(
                "Server error", request=MagicMock(), response=MagicMock()
            )

            result = module.fetch_npmsio_top_packages(10)

            assert result == []

    def test_fetch_handles_generic_exception(self):
        """Should handle generic exceptions gracefully."""
        import discovery.npmsio_audit as module

        with patch("discovery.npmsio_audit.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.side_effect = Exception("Network error")

            result = module.fetch_npmsio_top_packages(10)

            assert result == []


class TestGetDependencies:
    """Tests for the get_dependencies function in depsdev_collector."""

    @pytest.mark.asyncio
    async def test_returns_empty_for_nonexistent_package(self):
        """Should return empty list for package not found."""
        import httpx
        from collectors.depsdev_collector import get_dependencies

        with patch("collectors.depsdev_collector.retry_with_backoff") as mock_retry:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_retry.return_value = mock_response

            result = await get_dependencies("nonexistent-pkg", "npm")

            assert result == []

    @pytest.mark.asyncio
    async def test_returns_direct_dependencies(self):
        """Should return list of direct dependency names."""
        from collectors.depsdev_collector import get_dependencies

        # Mock the API responses
        pkg_response = MagicMock()
        pkg_response.status_code = 200
        pkg_response.json.return_value = {
            "versions": [
                {"versionKey": {"version": "1.0.0"}, "isDefault": True}
            ]
        }

        deps_response = MagicMock()
        deps_response.status_code = 200
        deps_response.json.return_value = {
            "nodes": [
                {"relation": "SELF", "versionKey": {"name": "test-pkg", "system": "NPM"}},
                {"relation": "DIRECT", "versionKey": {"name": "dep1", "system": "NPM"}},
                {"relation": "DIRECT", "versionKey": {"name": "dep2", "system": "NPM"}},
                {"relation": "INDIRECT", "versionKey": {"name": "transitive", "system": "NPM"}},
            ]
        }

        with patch("collectors.depsdev_collector.retry_with_backoff") as mock_retry:
            mock_retry.side_effect = [pkg_response, deps_response]

            result = await get_dependencies("test-pkg", "npm")

            assert "dep1" in result
            assert "dep2" in result
            assert "transitive" not in result  # Should not include indirect
            assert "test-pkg" not in result  # Should not include self

    @pytest.mark.asyncio
    async def test_handles_empty_versions(self):
        """Should return empty list when package has no versions."""
        from collectors.depsdev_collector import get_dependencies

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"versions": []}

        with patch("collectors.depsdev_collector.retry_with_backoff") as mock_retry:
            mock_retry.return_value = mock_response

            result = await get_dependencies("empty-pkg", "npm")

            assert result == []
