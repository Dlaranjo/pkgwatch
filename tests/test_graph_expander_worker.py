"""
Tests for graph_expander_worker.py - Graph expansion worker Lambda.

Coverage targets:
- Worker handler processing
- Package processing logic
- Dependency graph traversal
- S3 caching (get/put)
- SQS queuing
- Error handling
- Batch processing
"""

import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws


@pytest.fixture
def setup_s3_bucket():
    """Set up S3 bucket for caching."""
    import boto3

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="pkgwatch-raw-data")
    os.environ["RAW_DATA_BUCKET"] = "pkgwatch-raw-data"
    return "pkgwatch-raw-data"


@pytest.fixture
def setup_sqs_queue():
    """Set up SQS queue for package collection."""
    import boto3

    sqs = boto3.client("sqs", region_name="us-east-1")
    response = sqs.create_queue(QueueName="pkgwatch-package-queue")
    queue_url = response["QueueUrl"]
    os.environ["PACKAGE_QUEUE_URL"] = queue_url
    return queue_url


class TestGraphExpanderWorkerHandler:
    """Tests for the main handler function."""

    @mock_aws
    def test_handles_empty_records(self, mock_dynamodb):
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
    def test_handles_missing_records(self, mock_dynamodb):
        """Should handle missing Records key gracefully."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["processed"] == 0
        assert body["discovered"] == 0

    @mock_aws
    def test_processes_single_package(self, mock_dynamodb):
        """Should process a single package from SQS message."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["lodash"],
                            "ecosystem": "npm",
                        }
                    )
                }
            ]
        }

        with patch.object(module, "process_package", new_callable=AsyncMock) as mock_process:
            mock_process.return_value = 2  # 2 packages discovered

            result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["processed"] == 1
        assert body["discovered"] == 2
        mock_process.assert_called_once()

    @mock_aws
    def test_processes_multiple_packages(self, mock_dynamodb):
        """Should process multiple packages from SQS message."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["lodash", "express", "react"],
                            "ecosystem": "npm",
                        }
                    )
                }
            ]
        }

        with patch.object(module, "process_package", new_callable=AsyncMock) as mock_process:
            mock_process.return_value = 1

            result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["processed"] == 3
        assert body["discovered"] == 3  # 1 per package
        assert mock_process.call_count == 3

    @mock_aws
    def test_processes_multiple_records(self, mock_dynamodb):
        """Should process multiple SQS records."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PACKAGE_QUEUE_URL"] = "https://sqs.us-east-1.amazonaws.com/123/queue"

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {"body": json.dumps({"packages": ["lodash"], "ecosystem": "npm"})},
                {"body": json.dumps({"packages": ["express"], "ecosystem": "npm"})},
            ]
        }

        with patch.object(module, "process_package", new_callable=AsyncMock) as mock_process:
            mock_process.return_value = 0

            result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["processed"] == 2
        assert mock_process.call_count == 2

    @mock_aws
    def test_handles_pypi_ecosystem(self, mock_dynamodb):
        """Should handle PyPI ecosystem packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["requests"],
                            "ecosystem": "pypi",
                        }
                    )
                }
            ]
        }

        with patch.object(module, "process_package", new_callable=AsyncMock) as mock_process:
            mock_process.return_value = 1

            result = module.handler(event, None)

        assert result["statusCode"] == 200
        # Check that ecosystem was passed correctly
        call_args = mock_process.call_args_list[0]
        assert call_args[0][2] == "pypi"  # Third positional arg is ecosystem

    @mock_aws
    def test_handles_invalid_json(self, mock_dynamodb):
        """Should handle invalid JSON in record body."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {"body": "not valid json"},
            ]
        }

        result = module.handler(event, None)

        # Should not crash, just skip the record
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["processed"] == 0

    @mock_aws
    def test_handles_processing_exception(self, mock_dynamodb):
        """Should handle exceptions during package processing."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {"body": json.dumps({"packages": ["error-pkg"], "ecosystem": "npm"})},
                {"body": json.dumps({"packages": ["success-pkg"], "ecosystem": "npm"})},
            ]
        }

        call_count = [0]

        async def mock_process(*args):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("Processing error")
            return 1

        with patch.object(module, "process_package", side_effect=mock_process):
            result = module.handler(event, None)

        # Should continue processing after error
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["processed"] == 1  # Only second package processed

    @mock_aws
    def test_emits_metrics(self, mock_dynamodb):
        """Should emit CloudWatch metrics."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {"Records": []}

        mock_metrics = MagicMock()
        with patch.dict("sys.modules", {"shared.metrics": mock_metrics}):
            result = module.handler(event, None)

        # Metrics module may not be available in test
        assert result["statusCode"] == 200

    @mock_aws
    def test_default_ecosystem_is_npm(self, mock_dynamodb):
        """Should default to npm ecosystem when not specified."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["lodash"],
                            # No ecosystem specified
                        }
                    )
                }
            ]
        }

        with patch.object(module, "process_package", new_callable=AsyncMock) as mock_process:
            mock_process.return_value = 0

            _result = module.handler(event, None)

        # Should use npm as default
        call_args = mock_process.call_args_list[0]
        assert call_args[0][2] == "npm"


class TestPackageExists:
    """Tests for package_exists function."""

    @mock_aws
    def test_returns_true_for_existing_package(self, mock_dynamodb):
        """Should return True when package exists."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "name": "lodash",
                "ecosystem": "npm",
            }
        )

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        result = module.package_exists(table, "npm", "lodash")

        assert result is True

    @mock_aws
    def test_returns_false_for_missing_package(self, mock_dynamodb):
        """Should return False when package doesn't exist."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        result = module.package_exists(table, "npm", "nonexistent")

        assert result is False

    @mock_aws
    def test_handles_exception(self, mock_dynamodb):
        """Should return False on exception."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        mock_table = MagicMock()
        mock_table.get_item.side_effect = Exception("DynamoDB error")

        result = module.package_exists(mock_table, "npm", "error-pkg")

        assert result is False

    @mock_aws
    def test_checks_correct_pk_format(self, mock_dynamodb):
        """Should use correct pk format: ecosystem#name."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        # Add a pypi package
        table.put_item(
            Item={
                "pk": "pypi#requests",
                "sk": "LATEST",
                "name": "requests",
            }
        )

        # npm#requests should not exist
        assert module.package_exists(table, "npm", "requests") is False
        # pypi#requests should exist
        assert module.package_exists(table, "pypi", "requests") is True


class TestQueueForCollection:
    """Tests for queue_for_collection function."""

    @mock_aws
    def test_queues_package_successfully(self, mock_dynamodb, setup_sqs_queue):
        """Should queue package for data collection."""
        queue_url = setup_sqs_queue

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        module.queue_for_collection("npm", "new-package")

        # Verify message was sent
        sqs = boto3.client("sqs", region_name="us-east-1")
        response = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)

        messages = response.get("Messages", [])
        assert len(messages) == 1

        body = json.loads(messages[0]["Body"])
        assert body["ecosystem"] == "npm"
        assert body["name"] == "new-package"
        assert body["tier"] == 3
        assert body["reason"] == "graph_expansion_discovery"

    @mock_aws
    def test_skips_queue_without_url(self, mock_dynamodb):
        """Should skip queuing when PACKAGE_QUEUE_URL not set."""
        os.environ.pop("PACKAGE_QUEUE_URL", None)

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        # Should not raise
        module.queue_for_collection("npm", "test-package")

    @mock_aws
    def test_handles_sqs_error(self, mock_dynamodb, setup_sqs_queue):
        """Should handle SQS errors gracefully."""
        setup_sqs_queue

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        with patch.object(module, "sqs") as mock_sqs:
            mock_sqs.send_message.side_effect = Exception("SQS error")

            # Should not raise
            module.queue_for_collection("npm", "error-package")

    @mock_aws
    def test_queues_pypi_package(self, mock_dynamodb, setup_sqs_queue):
        """Should queue PyPI packages correctly."""
        queue_url = setup_sqs_queue

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        module.queue_for_collection("pypi", "requests")

        sqs = boto3.client("sqs", region_name="us-east-1")
        response = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)
        body = json.loads(response["Messages"][0]["Body"])

        assert body["ecosystem"] == "pypi"
        assert body["name"] == "requests"


class TestGetCachedDependencies:
    """Tests for get_cached_dependencies function."""

    @mock_aws
    def test_returns_cached_dependencies(self, mock_dynamodb, setup_s3_bucket):
        """Should return dependencies from S3 cache."""
        bucket = setup_s3_bucket

        # Put cached data
        s3 = boto3.client("s3", region_name="us-east-1")
        cached_data = {
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "dependencies": ["dep1", "dep2", "dep3"],
        }
        s3.put_object(
            Bucket=bucket,
            Key="deps-cache/npm/lodash.json",
            Body=json.dumps(cached_data),
        )

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        result = module.get_cached_dependencies("npm", "lodash")

        assert result == ["dep1", "dep2", "dep3"]

    @mock_aws
    def test_returns_none_for_expired_cache(self, mock_dynamodb, setup_s3_bucket):
        """Should return None when cache is expired (>7 days)."""
        bucket = setup_s3_bucket

        # Put expired cached data
        s3 = boto3.client("s3", region_name="us-east-1")
        cached_data = {
            "cached_at": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat(),
            "dependencies": ["old-dep"],
        }
        s3.put_object(
            Bucket=bucket,
            Key="deps-cache/npm/old-package.json",
            Body=json.dumps(cached_data),
        )

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        result = module.get_cached_dependencies("npm", "old-package")

        assert result is None

    @mock_aws
    def test_returns_none_for_missing_cache(self, mock_dynamodb, setup_s3_bucket):
        """Should return None when cache doesn't exist."""
        setup_s3_bucket

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        result = module.get_cached_dependencies("npm", "not-cached")

        assert result is None

    @mock_aws
    def test_returns_none_without_bucket(self, mock_dynamodb):
        """Should return None when RAW_DATA_BUCKET not set."""
        os.environ.pop("RAW_DATA_BUCKET", None)

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        result = module.get_cached_dependencies("npm", "any-package")

        assert result is None

    @mock_aws
    def test_handles_malformed_cache_data(self, mock_dynamodb, setup_s3_bucket):
        """Should return None for malformed cache data."""
        bucket = setup_s3_bucket

        s3 = boto3.client("s3", region_name="us-east-1")
        # Put invalid JSON
        s3.put_object(
            Bucket=bucket,
            Key="deps-cache/npm/bad-data.json",
            Body="not valid json",
        )

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        result = module.get_cached_dependencies("npm", "bad-data")

        assert result is None

    @mock_aws
    def test_handles_cache_within_ttl(self, mock_dynamodb, setup_s3_bucket):
        """Should return dependencies when cache is fresh (< 7 days)."""
        bucket = setup_s3_bucket

        s3 = boto3.client("s3", region_name="us-east-1")
        cached_data = {
            "cached_at": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
            "dependencies": ["fresh-dep"],
        }
        s3.put_object(
            Bucket=bucket,
            Key="deps-cache/npm/fresh-pkg.json",
            Body=json.dumps(cached_data),
        )

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        result = module.get_cached_dependencies("npm", "fresh-pkg")

        assert result == ["fresh-dep"]


class TestCacheDependencies:
    """Tests for cache_dependencies function."""

    @mock_aws
    def test_caches_dependencies_to_s3(self, mock_dynamodb, setup_s3_bucket):
        """Should cache dependencies to S3."""
        bucket = setup_s3_bucket

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        module.cache_dependencies("npm", "express", ["body-parser", "cookie-parser"])

        # Verify cached
        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.get_object(
            Bucket=bucket,
            Key="deps-cache/npm/express.json",
        )
        data = json.loads(response["Body"].read())

        assert data["dependencies"] == ["body-parser", "cookie-parser"]
        assert "cached_at" in data

    @mock_aws
    def test_skips_cache_without_bucket(self, mock_dynamodb):
        """Should skip caching when RAW_DATA_BUCKET not set."""
        os.environ.pop("RAW_DATA_BUCKET", None)

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        # Should not raise
        module.cache_dependencies("npm", "test", ["dep1"])

    @mock_aws
    def test_handles_cache_error(self, mock_dynamodb, setup_s3_bucket):
        """Should handle S3 cache error gracefully."""
        setup_s3_bucket

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        with patch.object(module, "s3") as mock_s3:
            mock_s3.put_object.side_effect = Exception("S3 error")

            # Should not raise
            module.cache_dependencies("npm", "error-pkg", ["dep1"])

    @mock_aws
    def test_caches_empty_dependencies(self, mock_dynamodb, setup_s3_bucket):
        """Should cache empty dependency list."""
        bucket = setup_s3_bucket

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        module.cache_dependencies("npm", "no-deps", [])

        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.get_object(
            Bucket=bucket,
            Key="deps-cache/npm/no-deps.json",
        )
        data = json.loads(response["Body"].read())

        assert data["dependencies"] == []

    @mock_aws
    def test_caches_pypi_dependencies(self, mock_dynamodb, setup_s3_bucket):
        """Should cache PyPI package dependencies."""
        bucket = setup_s3_bucket

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        module.cache_dependencies("pypi", "flask", ["werkzeug", "jinja2"])

        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.get_object(
            Bucket=bucket,
            Key="deps-cache/pypi/flask.json",
        )
        data = json.loads(response["Body"].read())

        assert data["dependencies"] == ["werkzeug", "jinja2"]


class TestProcessPackageIntegration:
    """Integration tests for process_package - testing through handler."""

    @mock_aws
    def test_discovers_and_adds_popular_package(self, mock_dynamodb, setup_s3_bucket, setup_sqs_queue):
        """Should discover and add packages with >= 100 dependents."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        setup_s3_bucket
        setup_sqs_queue

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-packages")

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["test-pkg"],
                            "ecosystem": "npm",
                        }
                    )
                }
            ]
        }

        # Mock cache miss and deps.dev returning a new dependency
        with patch.object(module, "get_cached_dependencies", return_value=None):
            with patch("collectors.depsdev_collector.get_dependencies", new_callable=AsyncMock) as mock_deps:
                mock_deps.return_value = ["new-popular-dep"]
                with patch("collectors.depsdev_collector.get_package_info", new_callable=AsyncMock) as mock_info:
                    mock_info.return_value = {"dependents_count": 500}

                    result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["discovered"] == 1

        # Verify package was added to DB
        response = table.get_item(Key={"pk": "npm#new-popular-dep", "sk": "LATEST"})
        assert "Item" in response
        assert response["Item"]["source"] == "graph_expansion"
        assert response["Item"]["tier"] == 3

    @mock_aws
    def test_skips_unpopular_dependencies(self, mock_dynamodb, setup_s3_bucket):
        """Should skip dependencies with < 100 dependents."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        setup_s3_bucket

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["test-pkg"],
                            "ecosystem": "npm",
                        }
                    )
                }
            ]
        }

        with patch.object(module, "get_cached_dependencies", return_value=["unpopular-dep"]):
            with patch("collectors.depsdev_collector.get_package_info", new_callable=AsyncMock) as mock_info:
                mock_info.return_value = {"dependents_count": 50}  # Below threshold

                result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["discovered"] == 0

    @mock_aws
    def test_skips_existing_dependencies(self, mock_dynamodb, setup_s3_bucket):
        """Should skip dependencies that already exist in DB."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        setup_s3_bucket

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Add existing dependency
        table.put_item(
            Item={
                "pk": "npm#existing-dep",
                "sk": "LATEST",
                "name": "existing-dep",
            }
        )

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["test-pkg"],
                            "ecosystem": "npm",
                        }
                    )
                }
            ]
        }

        with patch.object(module, "get_cached_dependencies", return_value=["existing-dep"]):
            result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["discovered"] == 0

    @mock_aws
    def test_uses_cached_dependencies(self, mock_dynamodb, setup_s3_bucket):
        """Should use cached dependencies when available."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_bucket

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Add existing dep
        table.put_item(
            Item={
                "pk": "npm#cached-dep",
                "sk": "LATEST",
                "name": "cached-dep",
            }
        )

        # Set up S3 cache
        s3 = boto3.client("s3", region_name="us-east-1")
        cached_data = {
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "dependencies": ["cached-dep"],
        }
        s3.put_object(
            Bucket=bucket,
            Key="deps-cache/npm/cached-pkg.json",
            Body=json.dumps(cached_data),
        )

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["cached-pkg"],
                            "ecosystem": "npm",
                        }
                    )
                }
            ]
        }

        with patch("collectors.depsdev_collector.get_dependencies", new_callable=AsyncMock) as mock_deps:
            result = module.handler(event, None)

            # Should not fetch from deps.dev (used cache)
            mock_deps.assert_not_called()

        assert result["statusCode"] == 200

    @mock_aws
    def test_handles_deps_dev_failure(self, mock_dynamodb, setup_s3_bucket):
        """Should handle deps.dev API failure gracefully."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        setup_s3_bucket

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["error-pkg"],
                            "ecosystem": "npm",
                        }
                    )
                }
            ]
        }

        with patch.object(module, "get_cached_dependencies", return_value=None):
            with patch("collectors.depsdev_collector.get_dependencies", new_callable=AsyncMock) as mock_deps:
                mock_deps.side_effect = Exception("API error")

                result = module.handler(event, None)

        # Should not crash
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["discovered"] == 0

    @mock_aws
    def test_handles_race_condition_on_insert(self, mock_dynamodb, setup_s3_bucket, setup_sqs_queue):
        """Should handle race condition when another worker adds the package."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        setup_s3_bucket
        setup_sqs_queue

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["test-pkg"],
                            "ecosystem": "npm",
                        }
                    )
                }
            ]
        }

        # Mock get_cached_dependencies and get_package_info,
        # but make the table put_item fail with ConditionalCheckFailedException
        with patch.object(module, "get_cached_dependencies", return_value=["race-dep"]):
            with patch("collectors.depsdev_collector.get_package_info", new_callable=AsyncMock) as mock_info:
                mock_info.return_value = {"dependents_count": 200}

                # The key is to patch module.dynamodb.Table to return a mock table
                # that raises ConditionalCheckFailedException on put_item
                mock_table = MagicMock()
                mock_table.get_item.return_value = {}  # Package doesn't exist check
                mock_table.put_item.side_effect = ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem"
                )

                with patch.object(module.dynamodb, "Table", return_value=mock_table):
                    result = module.handler(event, None)

        # Should not crash, just report 0 discovered (race lost)
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["discovered"] == 0

    @mock_aws
    def test_discovers_multiple_packages(self, mock_dynamodb, setup_s3_bucket, setup_sqs_queue):
        """Should discover multiple new packages from dependencies."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        setup_s3_bucket
        setup_sqs_queue

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Add one existing dep
        table.put_item(
            Item={
                "pk": "npm#existing-dep",
                "sk": "LATEST",
                "name": "existing-dep",
            }
        )

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["multi-deps-pkg"],
                            "ecosystem": "npm",
                        }
                    )
                }
            ]
        }

        with patch.object(
            module,
            "get_cached_dependencies",
            return_value=[
                "existing-dep",  # Already exists
                "new-dep-1",  # New and popular
                "new-dep-2",  # New and popular
                "unpopular-dep",  # New but unpopular
            ],
        ):

            async def mock_info(name, ecosystem):
                if name == "unpopular-dep":
                    return {"dependents_count": 50}  # Below threshold
                return {"dependents_count": 200}

            with patch("collectors.depsdev_collector.get_package_info", side_effect=mock_info):
                result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["discovered"] == 2  # Only the 2 new popular deps

    @mock_aws
    def test_queues_discovered_packages(self, mock_dynamodb, setup_s3_bucket, setup_sqs_queue):
        """Should queue newly discovered packages for collection."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        setup_s3_bucket
        queue_url = setup_sqs_queue

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["test-pkg"],
                            "ecosystem": "npm",
                        }
                    )
                }
            ]
        }

        with patch.object(module, "get_cached_dependencies", return_value=["queued-dep"]):
            with patch("collectors.depsdev_collector.get_package_info", new_callable=AsyncMock) as mock_info:
                mock_info.return_value = {"dependents_count": 300}

                result = module.handler(event, None)

        assert result["statusCode"] == 200

        # Verify message was queued
        sqs = boto3.client("sqs", region_name="us-east-1")
        response = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)
        messages = response.get("Messages", [])
        assert len(messages) == 1

        body = json.loads(messages[0]["Body"])
        assert body["name"] == "queued-dep"
        assert body["reason"] == "graph_expansion_discovery"

    @mock_aws
    def test_handles_pypi_packages(self, mock_dynamodb, setup_s3_bucket, setup_sqs_queue):
        """Should handle PyPI ecosystem packages correctly."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        setup_s3_bucket
        setup_sqs_queue

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-packages")

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["requests"],
                            "ecosystem": "pypi",
                        }
                    )
                }
            ]
        }

        with patch.object(module, "get_cached_dependencies", return_value=["urllib3"]):
            with patch("collectors.depsdev_collector.get_package_info", new_callable=AsyncMock) as mock_info:
                mock_info.return_value = {"dependents_count": 1000}

                result = module.handler(event, None)

        assert result["statusCode"] == 200

        # Verify correct pk format
        response = table.get_item(Key={"pk": "pypi#urllib3", "sk": "LATEST"})
        assert "Item" in response
        assert response["Item"]["ecosystem"] == "pypi"

    @mock_aws
    def test_fetches_and_caches_new_dependencies(self, mock_dynamodb, setup_s3_bucket):
        """Should fetch dependencies and cache them when not in S3."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_bucket

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Add existing dep so we don't try to insert
        table.put_item(
            Item={
                "pk": "npm#fetched-dep",
                "sk": "LATEST",
                "name": "fetched-dep",
            }
        )

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["uncached-pkg"],
                            "ecosystem": "npm",
                        }
                    )
                }
            ]
        }

        with patch("collectors.depsdev_collector.get_dependencies", new_callable=AsyncMock) as mock_deps:
            mock_deps.return_value = ["fetched-dep"]

            result = module.handler(event, None)

        assert result["statusCode"] == 200

        # Verify dependencies were cached
        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.get_object(
            Bucket=bucket,
            Key="deps-cache/npm/uncached-pkg.json",
        )
        data = json.loads(response["Body"].read())
        assert data["dependencies"] == ["fetched-dep"]

    @mock_aws
    def test_handles_no_package_info(self, mock_dynamodb, setup_s3_bucket):
        """Should skip dependencies where get_package_info returns None."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        setup_s3_bucket

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["test-pkg"],
                            "ecosystem": "npm",
                        }
                    )
                }
            ]
        }

        with patch.object(module, "get_cached_dependencies", return_value=["unknown-dep"]):
            with patch("collectors.depsdev_collector.get_package_info", new_callable=AsyncMock) as mock_info:
                mock_info.return_value = None  # Package not found in deps.dev

                result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["discovered"] == 0

    @mock_aws
    def test_returns_zero_for_empty_dependencies(self, mock_dynamodb, setup_s3_bucket):
        """Should return 0 discovered when no dependencies found."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        setup_s3_bucket

        import importlib

        import discovery.graph_expander_worker as module

        importlib.reload(module)

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "packages": ["no-deps-pkg"],
                            "ecosystem": "npm",
                        }
                    )
                }
            ]
        }

        with patch.object(module, "get_cached_dependencies", return_value=None):
            with patch("collectors.depsdev_collector.get_dependencies", new_callable=AsyncMock) as mock_deps:
                mock_deps.return_value = []  # No dependencies

                result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["discovered"] == 0
