"""
Tests for DynamoDB helper functions.
"""

import os
import pytest
from moto import mock_aws
import boto3


@pytest.fixture
def packages_table():
    """Create a mock packages table."""
    with mock_aws():
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.create_table(
            TableName="pkgwatch-packages",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "tier", "AttributeType": "N"},
                {"AttributeName": "risk_level", "AttributeType": "S"},
                {"AttributeName": "last_updated", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "tier-index",
                    "KeySchema": [
                        {"AttributeName": "tier", "KeyType": "HASH"},
                        {"AttributeName": "last_updated", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "KEYS_ONLY"},
                },
                {
                    "IndexName": "risk-level-index",
                    "KeySchema": [
                        {"AttributeName": "risk_level", "KeyType": "HASH"},
                        {"AttributeName": "last_updated", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        table.wait_until_exists()

        # Reload module to pick up mocked boto3
        import importlib
        import shared.dynamo
        importlib.reload(shared.dynamo)

        yield table


class TestGetPackage:
    """Tests for get_package function."""

    @mock_aws
    def test_returns_existing_package(self, packages_table):
        """get_package should return existing package data."""
        from shared.dynamo import get_package

        # Insert test data
        packages_table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "lodash",
                "health_score": 85,
            }
        )

        result = get_package("npm", "lodash")

        assert result is not None
        assert result["name"] == "lodash"
        assert result["health_score"] == 85

    @mock_aws
    def test_returns_none_for_missing_package(self, packages_table):
        """get_package should return None for non-existent package."""
        from shared.dynamo import get_package

        result = get_package("npm", "nonexistent-package")

        assert result is None


class TestPutPackage:
    """Tests for put_package function."""

    @mock_aws
    def test_creates_new_package(self, packages_table):
        """put_package should create a new package."""
        from shared.dynamo import put_package, get_package

        put_package("npm", "new-package", {"health_score": 75})

        result = get_package("npm", "new-package")
        assert result is not None
        assert result["health_score"] == 75

    @mock_aws
    def test_updates_existing_package(self, packages_table):
        """put_package should update existing package."""
        from shared.dynamo import put_package, get_package

        put_package("npm", "test-pkg", {"health_score": 50})
        put_package("npm", "test-pkg", {"health_score": 80})

        result = get_package("npm", "test-pkg")
        assert result["health_score"] == 80

    @mock_aws
    def test_sets_default_tier(self, packages_table):
        """put_package should set default tier to 3."""
        from shared.dynamo import put_package, get_package

        put_package("npm", "tier-test", {"health_score": 50})

        result = get_package("npm", "tier-test")
        assert result["tier"] == 3

    @mock_aws
    def test_sets_custom_tier(self, packages_table):
        """put_package should accept custom tier."""
        from shared.dynamo import put_package, get_package

        put_package("npm", "custom-tier", {"health_score": 90}, tier=1)

        result = get_package("npm", "custom-tier")
        assert result["tier"] == 1

    @mock_aws
    def test_sets_last_updated(self, packages_table):
        """put_package should set last_updated timestamp."""
        from shared.dynamo import put_package, get_package

        put_package("npm", "timestamp-test", {})

        result = get_package("npm", "timestamp-test")
        assert "last_updated" in result

    @mock_aws
    def test_removes_none_values(self, packages_table):
        """put_package should remove None values."""
        from shared.dynamo import put_package, get_package

        put_package("npm", "none-test", {"health_score": 50, "optional": None})

        result = get_package("npm", "none-test")
        assert "optional" not in result


class TestQueryPackagesByRisk:
    """Tests for query_packages_by_risk function."""

    @mock_aws
    def test_returns_packages_by_risk_level(self, packages_table):
        """query_packages_by_risk should return packages with matching risk."""
        from shared.dynamo import put_package, query_packages_by_risk

        # Create packages with different risk levels
        packages_table.put_item(
            Item={
                "pk": "npm#critical1",
                "sk": "LATEST",
                "name": "critical1",
                "risk_level": "CRITICAL",
                "last_updated": "2026-01-09T10:00:00Z",
            }
        )
        packages_table.put_item(
            Item={
                "pk": "npm#critical2",
                "sk": "LATEST",
                "name": "critical2",
                "risk_level": "CRITICAL",
                "last_updated": "2026-01-09T11:00:00Z",
            }
        )
        packages_table.put_item(
            Item={
                "pk": "npm#low1",
                "sk": "LATEST",
                "name": "low1",
                "risk_level": "LOW",
                "last_updated": "2026-01-09T12:00:00Z",
            }
        )

        result = query_packages_by_risk("CRITICAL")

        assert len(result) == 2
        assert all(p["risk_level"] == "CRITICAL" for p in result)

    @mock_aws
    def test_respects_limit(self, packages_table):
        """query_packages_by_risk should respect limit parameter."""
        from shared.dynamo import query_packages_by_risk

        # Create multiple packages
        for i in range(10):
            packages_table.put_item(
                Item={
                    "pk": f"npm#high{i}",
                    "sk": "LATEST",
                    "name": f"high{i}",
                    "risk_level": "HIGH",
                    "last_updated": f"2026-01-09T{i:02d}:00:00Z",
                }
            )

        result = query_packages_by_risk("HIGH", limit=5)

        assert len(result) == 5


class TestQueryPackagesByTier:
    """Tests for query_packages_by_tier function."""

    @mock_aws
    def test_returns_packages_by_tier(self, packages_table):
        """query_packages_by_tier should return packages with matching tier."""
        from shared.dynamo import query_packages_by_tier

        # Create packages with different tiers
        packages_table.put_item(
            Item={
                "pk": "npm#tier1-pkg",
                "sk": "LATEST",
                "name": "tier1-pkg",
                "tier": 1,
                "last_updated": "2026-01-09T10:00:00Z",
            }
        )
        packages_table.put_item(
            Item={
                "pk": "npm#tier2-pkg",
                "sk": "LATEST",
                "name": "tier2-pkg",
                "tier": 2,
                "last_updated": "2026-01-09T11:00:00Z",
            }
        )
        packages_table.put_item(
            Item={
                "pk": "npm#tier3-pkg",
                "sk": "LATEST",
                "name": "tier3-pkg",
                "tier": 3,
                "last_updated": "2026-01-09T12:00:00Z",
            }
        )

        result = query_packages_by_tier(1)

        assert len(result) == 1
        assert result[0]["pk"] == "npm#tier1-pkg"


class TestUpdatePackageTier:
    """Tests for update_package_tier function."""

    @mock_aws
    def test_updates_tier(self, packages_table):
        """update_package_tier should change package tier."""
        from shared.dynamo import put_package, get_package, update_package_tier

        put_package("npm", "tier-update", {"health_score": 50}, tier=3)

        update_package_tier("npm", "tier-update", 1)

        result = get_package("npm", "tier-update")
        assert result["tier"] == 1


class TestUpdatePackageScores:
    """Tests for update_package_scores function."""

    @mock_aws
    def test_updates_scores(self, packages_table):
        """update_package_scores should update all score fields."""
        from decimal import Decimal
        from shared.dynamo import put_package, get_package, update_package_scores

        put_package("npm", "score-update", {})

        update_package_scores(
            ecosystem="npm",
            name="score-update",
            health_score=Decimal("85.5"),
            risk_level="LOW",
            components={"maintainer": Decimal("90"), "evolution": Decimal("80")},
            confidence={"level": "HIGH", "score": Decimal("95")},
            abandonment_risk={"probability": Decimal("5"), "time_horizon_months": 12},
        )

        result = get_package("npm", "score-update")
        assert result["health_score"] == Decimal("85.5")
        assert result["risk_level"] == "LOW"
        assert result["score_components"]["maintainer"] == Decimal("90")
        assert result["confidence"]["level"] == "HIGH"
        assert result["abandonment_risk"]["probability"] == Decimal("5")
        assert "scored_at" in result


class TestBatchGetPackages:
    """Tests for batch_get_packages function."""

    @mock_aws
    def test_returns_multiple_packages(self, packages_table):
        """batch_get_packages should return multiple packages."""
        from shared.dynamo import put_package, batch_get_packages

        put_package("npm", "batch1", {"health_score": 80})
        put_package("npm", "batch2", {"health_score": 70})
        put_package("npm", "batch3", {"health_score": 60})

        result = batch_get_packages("npm", ["batch1", "batch2", "batch3"])

        assert len(result) == 3
        assert "batch1" in result
        assert "batch2" in result
        assert "batch3" in result

    @mock_aws
    def test_returns_empty_for_empty_list(self, packages_table):
        """batch_get_packages should return empty dict for empty list."""
        from shared.dynamo import batch_get_packages

        result = batch_get_packages("npm", [])

        assert result == {}

    @mock_aws
    def test_handles_missing_packages(self, packages_table):
        """batch_get_packages should handle missing packages."""
        from shared.dynamo import put_package, batch_get_packages

        put_package("npm", "exists", {"health_score": 80})

        result = batch_get_packages("npm", ["exists", "missing"])

        assert len(result) == 1
        assert "exists" in result
        assert "missing" not in result


class TestGetPackageRetryBehavior:
    """Tests for get_package retry behavior on DynamoDB errors."""

    @mock_aws
    def test_retries_on_throttling_error(self, packages_table):
        """get_package should retry on ProvisionedThroughputExceededException."""
        from unittest.mock import patch, MagicMock
        from botocore.exceptions import ClientError
        import shared.dynamo as dynamo_module
        import importlib

        # Reload to get fresh module state
        importlib.reload(dynamo_module)
        import shared.aws_clients; shared.aws_clients._dynamodb = None

        # Insert test data first
        packages_table.put_item(
            Item={
                "pk": "npm#retry-test",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "retry-test",
                "health_score": 85,
            }
        )

        # Create a mock that fails twice then succeeds
        call_count = [0]
        original_get_item = packages_table.get_item

        def mock_get_item(**kwargs):
            call_count[0] += 1
            if call_count[0] <= 2:
                raise ClientError(
                    {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Throttled"}},
                    "GetItem",
                )
            return original_get_item(**kwargs)

        with patch.object(packages_table, "get_item", side_effect=mock_get_item):
            with patch("shared.dynamo.get_dynamodb") as mock_dynamo:
                mock_dynamo.return_value.Table.return_value = packages_table
                with patch("time.sleep"):  # Don't actually sleep in tests
                    result = dynamo_module.get_package("npm", "retry-test")

        assert result is not None
        assert result["name"] == "retry-test"
        assert call_count[0] == 3  # Failed twice, succeeded on third

    @mock_aws
    def test_returns_none_after_max_retries(self, packages_table):
        """get_package should return None after max retries exceeded."""
        from unittest.mock import patch, MagicMock
        from botocore.exceptions import ClientError
        import shared.dynamo as dynamo_module
        import importlib

        importlib.reload(dynamo_module)
        import shared.aws_clients; shared.aws_clients._dynamodb = None

        # Create mock that always fails with throttling
        def always_throttle(**kwargs):
            raise ClientError(
                {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Throttled"}},
                "GetItem",
            )

        mock_table = MagicMock()
        mock_table.get_item = always_throttle

        with patch("shared.dynamo.get_dynamodb") as mock_dynamo:
            mock_dynamo.return_value.Table.return_value = mock_table
            with patch("time.sleep"):  # Don't actually sleep
                result = dynamo_module.get_package("npm", "always-throttled", max_retries=3)

        assert result is None

    @mock_aws
    def test_no_retry_on_access_denied(self, packages_table):
        """get_package should not retry on AccessDeniedException."""
        from unittest.mock import patch, MagicMock
        from botocore.exceptions import ClientError
        import shared.dynamo as dynamo_module
        import importlib

        importlib.reload(dynamo_module)
        import shared.aws_clients; shared.aws_clients._dynamodb = None

        call_count = [0]

        def access_denied(**kwargs):
            call_count[0] += 1
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Access Denied"}},
                "GetItem",
            )

        mock_table = MagicMock()
        mock_table.get_item = access_denied

        with patch("shared.dynamo.get_dynamodb") as mock_dynamo:
            mock_dynamo.return_value.Table.return_value = mock_table
            result = dynamo_module.get_package("npm", "access-denied")

        assert result is None
        assert call_count[0] == 1  # Should not retry

    @mock_aws
    def test_handles_generic_exception(self, packages_table):
        """get_package should handle non-ClientError exceptions."""
        from unittest.mock import patch, MagicMock
        import shared.dynamo as dynamo_module
        import importlib

        importlib.reload(dynamo_module)
        import shared.aws_clients; shared.aws_clients._dynamodb = None

        def raise_generic(**kwargs):
            raise RuntimeError("Something unexpected happened")

        mock_table = MagicMock()
        mock_table.get_item = raise_generic

        with patch("shared.dynamo.get_dynamodb") as mock_dynamo:
            mock_dynamo.return_value.Table.return_value = mock_table
            result = dynamo_module.get_package("npm", "generic-error")

        assert result is None


class TestQueryPackagesByTierPagination:
    """Tests for query_packages_by_tier pagination handling."""

    @mock_aws
    def test_handles_paginated_results(self, packages_table):
        """query_packages_by_tier should handle paginated responses."""
        from unittest.mock import patch, MagicMock
        import shared.dynamo as dynamo_module
        import importlib

        importlib.reload(dynamo_module)
        import shared.aws_clients; shared.aws_clients._dynamodb = None

        # Simulate paginated response
        page1 = {
            "Items": [{"pk": "npm#pkg1"}, {"pk": "npm#pkg2"}],
            "LastEvaluatedKey": {"pk": "npm#pkg2", "tier": 1},
        }
        page2 = {
            "Items": [{"pk": "npm#pkg3"}, {"pk": "npm#pkg4"}],
            # No LastEvaluatedKey = last page
        }

        call_count = [0]

        def mock_query(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return page1
            return page2

        mock_table = MagicMock()
        mock_table.query = mock_query

        with patch("shared.dynamo.get_dynamodb") as mock_dynamo:
            mock_dynamo.return_value.Table.return_value = mock_table
            result = dynamo_module.query_packages_by_tier(1)

        assert len(result) == 4
        assert call_count[0] == 2  # Two queries made


class TestBatchGetPackagesRetry:
    """Tests for batch_get_packages UnprocessedKeys handling."""

    @mock_aws
    def test_handles_unprocessed_keys_with_retry(self, packages_table):
        """batch_get_packages should retry for UnprocessedKeys."""
        from unittest.mock import patch, MagicMock
        import shared.dynamo as dynamo_module
        import importlib

        importlib.reload(dynamo_module)
        import shared.aws_clients; shared.aws_clients._dynamodb = None

        # First call returns some unprocessed, second call completes
        call_count = [0]

        def mock_batch_get(RequestItems):
            call_count[0] += 1
            table_name = list(RequestItems.keys())[0]
            if call_count[0] == 1:
                return {
                    "Responses": {
                        table_name: [
                            {"pk": "npm#pkg1", "name": "pkg1"},
                            {"pk": "npm#pkg2", "name": "pkg2"},
                        ]
                    },
                    "UnprocessedKeys": {
                        table_name: {
                            "Keys": [{"pk": "npm#pkg3", "sk": "LATEST"}]
                        }
                    },
                }
            else:
                return {
                    "Responses": {
                        table_name: [{"pk": "npm#pkg3", "name": "pkg3"}]
                    },
                    "UnprocessedKeys": {},
                }

        mock_dynamodb = MagicMock()
        mock_dynamodb.batch_get_item = mock_batch_get
        mock_dynamodb.Table.return_value = packages_table

        with patch("shared.dynamo.get_dynamodb", return_value=mock_dynamodb):
            with patch("time.sleep"):  # Don't actually sleep
                result = dynamo_module.batch_get_packages("npm", ["pkg1", "pkg2", "pkg3"])

        assert len(result) == 3
        assert "pkg1" in result
        assert "pkg2" in result
        assert "pkg3" in result
        assert call_count[0] == 2

    @mock_aws
    def test_stops_after_max_retries_for_unprocessed(self, packages_table):
        """batch_get_packages should stop after max retries for persistent UnprocessedKeys."""
        from unittest.mock import patch, MagicMock
        import shared.dynamo as dynamo_module
        import importlib

        importlib.reload(dynamo_module)
        import shared.aws_clients; shared.aws_clients._dynamodb = None

        call_count = [0]

        def always_unprocessed(RequestItems):
            call_count[0] += 1
            table_name = list(RequestItems.keys())[0]
            return {
                "Responses": {
                    table_name: [{"pk": "npm#pkg1", "name": "pkg1"}]
                },
                "UnprocessedKeys": {
                    table_name: {
                        "Keys": [{"pk": "npm#pkg2", "sk": "LATEST"}]
                    }
                },
            }

        mock_dynamodb = MagicMock()
        mock_dynamodb.batch_get_item = always_unprocessed

        with patch("shared.dynamo.get_dynamodb", return_value=mock_dynamodb):
            with patch("time.sleep"):  # Don't actually sleep
                result = dynamo_module.batch_get_packages("npm", ["pkg1", "pkg2"])

        # Should have pkg1 but give up on pkg2 after max retries
        assert "pkg1" in result
        assert call_count[0] == 5  # max_retries = 5
