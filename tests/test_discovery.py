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
