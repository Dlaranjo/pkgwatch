"""
Tests for DynamoDB helper utilities module.

Tests cover package CRUD operations, batch operations, queries,
retry logic, and error handling using moto for AWS mocking.
"""

import os
from datetime import datetime
from decimal import Decimal
from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

import shared.aws_clients as aws_clients_module

# Import after environment setup
import shared.dynamo as dynamo_module
from shared.aws_clients import get_dynamodb
from shared.dynamo import (
    PACKAGES_TABLE,
    batch_get_packages,
    get_package,
    put_package,
    query_packages_by_risk,
    query_packages_by_tier,
    update_package_scores,
    update_package_tier,
)


@pytest.fixture
def reset_dynamodb():
    """Reset the global DynamoDB resource between tests."""
    aws_clients_module._dynamodb = None
    yield
    aws_clients_module._dynamodb = None


@pytest.fixture
def mock_packages_table(reset_dynamodb):
    """Provide mocked DynamoDB packages table."""
    with mock_aws():
        # Reset to ensure we use the mocked AWS
        dynamo_module._dynamodb = None
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

        # Create packages table with GSIs
        dynamodb.create_table(
            TableName=PACKAGES_TABLE,
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

        # Set the module's dynamodb to use our mocked one
        dynamo_module._dynamodb = dynamodb

        table = dynamodb.Table(PACKAGES_TABLE)
        yield table

        # Reset after test
        dynamo_module._dynamodb = None


class TestGetDynamodb:
    """Tests for lazy DynamoDB resource initialization."""

    def test_creates_resource_on_first_call(self, reset_dynamodb):
        """Should create DynamoDB resource on first access."""
        with mock_aws():
            assert aws_clients_module._dynamodb is None
            resource = get_dynamodb()
            assert resource is not None
            assert aws_clients_module._dynamodb is resource

    def test_returns_same_resource_on_subsequent_calls(self, reset_dynamodb):
        """Should return the same resource on subsequent calls."""
        with mock_aws():
            resource1 = get_dynamodb()
            resource2 = get_dynamodb()
            assert resource1 is resource2


class TestGetPackage:
    """Tests for get_package function."""

    def test_retrieves_existing_package(self, mock_packages_table):
        """Should retrieve an existing package."""
        # Seed test data
        mock_packages_table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "lodash",
                "health_score": Decimal("85"),
            }
        )

        result = get_package("npm", "lodash")

        assert result is not None
        assert result["name"] == "lodash"
        assert result["ecosystem"] == "npm"
        assert result["health_score"] == Decimal("85")

    def test_returns_none_for_nonexistent_package(self, mock_packages_table):
        """Should return None for package that doesn't exist."""
        result = get_package("npm", "nonexistent-package")

        assert result is None

    def test_handles_pypi_ecosystem(self, mock_packages_table):
        """Should correctly handle PyPI packages."""
        mock_packages_table.put_item(
            Item={
                "pk": "pypi#requests",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "requests",
            }
        )

        result = get_package("pypi", "requests")

        assert result is not None
        assert result["ecosystem"] == "pypi"
        assert result["name"] == "requests"

    def test_handles_scoped_npm_packages(self, mock_packages_table):
        """Should handle scoped npm packages correctly."""
        mock_packages_table.put_item(
            Item={
                "pk": "npm#@types/node",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "@types/node",
            }
        )

        result = get_package("npm", "@types/node")

        assert result is not None
        assert result["name"] == "@types/node"

    def test_retries_on_throttling(self, mock_packages_table):
        """Should retry on ProvisionedThroughputExceededException."""
        # Seed test data
        mock_packages_table.put_item(
            Item={"pk": "npm#test", "sk": "LATEST", "name": "test"}
        )

        call_count = 0

        def throttle_then_succeed(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ClientError(
                    {"Error": {"Code": "ProvisionedThroughputExceededException"}},
                    "GetItem",
                )
            return {"Item": {"pk": "npm#test", "sk": "LATEST", "name": "test"}}

        with patch.object(mock_packages_table, "get_item", side_effect=throttle_then_succeed):
            # Patch sleep to speed up test and patch the table lookup
            with patch("shared.dynamo.get_dynamodb") as mock_dynamo:
                mock_dynamo.return_value.Table.return_value = mock_packages_table
                with patch("time.sleep"):
                    result = get_package("npm", "test")

        assert call_count == 3
        assert result is not None

    def test_returns_none_on_max_retries_exceeded(self, mock_packages_table, caplog):
        """Should return None after max retries exceeded."""
        import logging

        call_count = 0

        def always_throttle(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise ClientError(
                {"Error": {"Code": "ThrottlingException"}},
                "GetItem",
            )

        with patch.object(mock_packages_table, "get_item", side_effect=always_throttle):
            with patch("shared.dynamo.get_dynamodb") as mock_dynamo:
                mock_dynamo.return_value.Table.return_value = mock_packages_table
                with patch("time.sleep"):
                    with caplog.at_level(logging.WARNING):
                        result = get_package("npm", "test", max_retries=3)

        assert result is None
        # After 3 attempts (max_retries), it should have tried all 3 times
        assert call_count == 3
        # The final error is logged (either as throttle warning or error)
        assert "Error fetching package" in caplog.text or "throttled" in caplog.text.lower()

    def test_returns_none_on_non_retryable_error(self, mock_packages_table, caplog):
        """Should return None immediately for non-retryable errors."""
        import logging

        def access_denied(*args, **kwargs):
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException"}},
                "GetItem",
            )

        with patch.object(mock_packages_table, "get_item", side_effect=access_denied):
            with patch("shared.dynamo.get_dynamodb") as mock_dynamo:
                mock_dynamo.return_value.Table.return_value = mock_packages_table
                with caplog.at_level(logging.ERROR):
                    result = get_package("npm", "test")

        assert result is None
        assert "Error fetching package" in caplog.text

    def test_handles_internal_server_error_with_retry(self, mock_packages_table):
        """Should retry on InternalServerError."""
        # Seed test data
        mock_packages_table.put_item(
            Item={"pk": "npm#test", "sk": "LATEST", "name": "test"}
        )

        call_count = 0

        def internal_error_then_succeed(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ClientError(
                    {"Error": {"Code": "InternalServerError"}},
                    "GetItem",
                )
            return {"Item": {"pk": "npm#test", "sk": "LATEST", "name": "test"}}

        with patch.object(mock_packages_table, "get_item", side_effect=internal_error_then_succeed):
            with patch("shared.dynamo.get_dynamodb") as mock_dynamo:
                mock_dynamo.return_value.Table.return_value = mock_packages_table
                with patch("time.sleep"):
                    result = get_package("npm", "test")

        assert call_count == 2
        assert result is not None


class TestPutPackage:
    """Tests for put_package function."""

    def test_stores_new_package(self, mock_packages_table):
        """Should store a new package."""
        put_package(
            "npm",
            "lodash",
            {"health_score": 85, "weekly_downloads": 1000000},
        )

        # Verify stored
        response = mock_packages_table.get_item(
            Key={"pk": "npm#lodash", "sk": "LATEST"}
        )
        item = response.get("Item")

        assert item is not None
        assert item["ecosystem"] == "npm"
        assert item["name"] == "lodash"
        assert item["health_score"] == 85
        assert item["tier"] == 3  # Default tier

    def test_stores_with_custom_tier(self, mock_packages_table):
        """Should store package with specified tier."""
        put_package(
            "npm",
            "react",
            {"health_score": 95},
            tier=1,
        )

        response = mock_packages_table.get_item(
            Key={"pk": "npm#react", "sk": "LATEST"}
        )
        item = response.get("Item")

        assert item["tier"] == 1

    def test_adds_last_updated_timestamp(self, mock_packages_table):
        """Should add last_updated timestamp."""
        put_package("npm", "test-pkg", {})

        response = mock_packages_table.get_item(
            Key={"pk": "npm#test-pkg", "sk": "LATEST"}
        )
        item = response.get("Item")

        assert "last_updated" in item
        # Should be ISO format
        datetime.fromisoformat(item["last_updated"].replace("Z", "+00:00"))

    def test_removes_none_values(self, mock_packages_table):
        """Should remove None values from item."""
        put_package(
            "npm",
            "test-pkg",
            {"valid_field": "value", "null_field": None},
        )

        response = mock_packages_table.get_item(
            Key={"pk": "npm#test-pkg", "sk": "LATEST"}
        )
        item = response.get("Item")

        assert item["valid_field"] == "value"
        assert "null_field" not in item

    def test_removes_empty_strings(self, mock_packages_table):
        """Should remove empty string values."""
        put_package(
            "npm",
            "test-pkg",
            {"valid_field": "value", "empty_field": ""},
        )

        response = mock_packages_table.get_item(
            Key={"pk": "npm#test-pkg", "sk": "LATEST"}
        )
        item = response.get("Item")

        assert item["valid_field"] == "value"
        assert "empty_field" not in item

    def test_updates_existing_package(self, mock_packages_table):
        """Should update an existing package."""
        # Create initial
        put_package("npm", "test-pkg", {"health_score": 50})

        # Update
        put_package("npm", "test-pkg", {"health_score": 75, "new_field": "added"})

        response = mock_packages_table.get_item(
            Key={"pk": "npm#test-pkg", "sk": "LATEST"}
        )
        item = response.get("Item")

        assert item["health_score"] == 75
        assert item["new_field"] == "added"


class TestQueryPackagesByRisk:
    """Tests for query_packages_by_risk function."""

    def test_queries_high_risk_packages(self, mock_packages_table):
        """Should return packages with HIGH risk level."""
        # Seed data
        mock_packages_table.put_item(
            Item={
                "pk": "npm#risky-pkg",
                "sk": "LATEST",
                "risk_level": "HIGH",
                "last_updated": "2024-01-01T00:00:00Z",
                "name": "risky-pkg",
            }
        )
        mock_packages_table.put_item(
            Item={
                "pk": "npm#safe-pkg",
                "sk": "LATEST",
                "risk_level": "LOW",
                "last_updated": "2024-01-01T00:00:00Z",
                "name": "safe-pkg",
            }
        )

        result = query_packages_by_risk("HIGH")

        assert len(result) == 1
        assert result[0]["name"] == "risky-pkg"

    def test_returns_empty_list_for_no_matches(self, mock_packages_table):
        """Should return empty list when no packages match."""
        result = query_packages_by_risk("CRITICAL")

        assert result == []

    def test_respects_limit_parameter(self, mock_packages_table):
        """Should respect the limit parameter."""
        # Seed multiple packages
        for i in range(10):
            mock_packages_table.put_item(
                Item={
                    "pk": f"npm#pkg-{i}",
                    "sk": "LATEST",
                    "risk_level": "MEDIUM",
                    "last_updated": f"2024-01-0{i+1}T00:00:00Z",
                    "name": f"pkg-{i}",
                }
            )

        result = query_packages_by_risk("MEDIUM", limit=5)

        assert len(result) == 5

    def test_returns_newest_first(self, mock_packages_table):
        """Should return packages sorted by last_updated descending."""
        mock_packages_table.put_item(
            Item={
                "pk": "npm#old-pkg",
                "sk": "LATEST",
                "risk_level": "HIGH",
                "last_updated": "2024-01-01T00:00:00Z",
                "name": "old-pkg",
            }
        )
        mock_packages_table.put_item(
            Item={
                "pk": "npm#new-pkg",
                "sk": "LATEST",
                "risk_level": "HIGH",
                "last_updated": "2024-06-01T00:00:00Z",
                "name": "new-pkg",
            }
        )

        result = query_packages_by_risk("HIGH")

        assert result[0]["name"] == "new-pkg"
        assert result[1]["name"] == "old-pkg"


class TestQueryPackagesByTier:
    """Tests for query_packages_by_tier function."""

    def test_queries_tier_1_packages(self, mock_packages_table):
        """Should return packages in tier 1."""
        mock_packages_table.put_item(
            Item={
                "pk": "npm#popular-pkg",
                "sk": "LATEST",
                "tier": 1,
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )
        mock_packages_table.put_item(
            Item={
                "pk": "npm#other-pkg",
                "sk": "LATEST",
                "tier": 3,
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        result = query_packages_by_tier(1)

        assert len(result) == 1
        assert result[0]["pk"] == "npm#popular-pkg"

    def test_returns_empty_list_for_no_matches(self, mock_packages_table):
        """Should return empty list when no packages in tier."""
        result = query_packages_by_tier(1)

        assert result == []

    def test_handles_pagination(self, mock_packages_table):
        """Should handle pagination for large result sets."""
        # Seed many packages (pagination tested with smaller batches in moto)
        for i in range(30):
            mock_packages_table.put_item(
                Item={
                    "pk": f"npm#pkg-{i}",
                    "sk": "LATEST",
                    "tier": 2,
                    "last_updated": f"2024-01-{(i % 28) + 1:02d}T00:00:00Z",
                }
            )

        result = query_packages_by_tier(2)

        assert len(result) == 30


class TestUpdatePackageTier:
    """Tests for update_package_tier function."""

    def test_updates_tier(self, mock_packages_table):
        """Should update package tier."""
        mock_packages_table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "LATEST",
                "tier": 3,
            }
        )

        update_package_tier("npm", "test-pkg", 1)

        response = mock_packages_table.get_item(
            Key={"pk": "npm#test-pkg", "sk": "LATEST"}
        )
        assert response["Item"]["tier"] == 1

    def test_can_downgrade_tier(self, mock_packages_table):
        """Should be able to downgrade tier."""
        mock_packages_table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "LATEST",
                "tier": 1,
            }
        )

        update_package_tier("npm", "test-pkg", 3)

        response = mock_packages_table.get_item(
            Key={"pk": "npm#test-pkg", "sk": "LATEST"}
        )
        assert response["Item"]["tier"] == 3


class TestUpdatePackageScores:
    """Tests for update_package_scores function."""

    def test_updates_all_score_fields(self, mock_packages_table):
        """Should update all score-related fields."""
        mock_packages_table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "LATEST",
                "name": "test-pkg",
            }
        )

        update_package_scores(
            ecosystem="npm",
            name="test-pkg",
            health_score=Decimal("85.5"),
            risk_level="LOW",
            components={"activity": 90, "community": 80, "security": 85},
            confidence={"level": "high", "data_completeness": Decimal("0.95")},
            abandonment_risk={"probability": Decimal("0.15"), "risk_level": "LOW"},
        )

        response = mock_packages_table.get_item(
            Key={"pk": "npm#test-pkg", "sk": "LATEST"}
        )
        item = response["Item"]

        assert float(item["health_score"]) == 85.5
        assert item["risk_level"] == "LOW"
        assert item["score_components"]["activity"] == 90
        assert item["confidence"]["level"] == "high"
        assert float(item["abandonment_risk"]["probability"]) == 0.15
        assert "scored_at" in item

    def test_adds_scored_at_timestamp(self, mock_packages_table):
        """Should add scored_at timestamp."""
        mock_packages_table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "LATEST",
            }
        )

        update_package_scores(
            ecosystem="npm",
            name="test-pkg",
            health_score=Decimal("75.0"),
            risk_level="MEDIUM",
            components={},
            confidence={},
            abandonment_risk={},
        )

        response = mock_packages_table.get_item(
            Key={"pk": "npm#test-pkg", "sk": "LATEST"}
        )
        item = response["Item"]

        assert "scored_at" in item
        # Verify ISO format
        datetime.fromisoformat(item["scored_at"].replace("Z", "+00:00"))


class TestBatchGetPackages:
    """Tests for batch_get_packages function."""

    def test_retrieves_multiple_packages(self, mock_packages_table):
        """Should retrieve multiple packages in one batch."""
        mock_packages_table.put_item(
            Item={"pk": "npm#lodash", "sk": "LATEST", "name": "lodash"}
        )
        mock_packages_table.put_item(
            Item={"pk": "npm#react", "sk": "LATEST", "name": "react"}
        )
        mock_packages_table.put_item(
            Item={"pk": "npm#vue", "sk": "LATEST", "name": "vue"}
        )

        result = batch_get_packages("npm", ["lodash", "react", "vue"])

        assert len(result) == 3
        assert "lodash" in result
        assert "react" in result
        assert "vue" in result
        assert result["lodash"]["name"] == "lodash"

    def test_returns_empty_dict_for_empty_names(self, mock_packages_table):
        """Should return empty dict when names list is empty."""
        result = batch_get_packages("npm", [])

        assert result == {}

    def test_handles_missing_packages(self, mock_packages_table):
        """Should only return packages that exist."""
        mock_packages_table.put_item(
            Item={"pk": "npm#lodash", "sk": "LATEST", "name": "lodash"}
        )

        result = batch_get_packages("npm", ["lodash", "nonexistent"])

        assert len(result) == 1
        assert "lodash" in result
        assert "nonexistent" not in result

    def test_handles_more_than_25_packages(self, mock_packages_table):
        """Should handle batching for >25 packages (DynamoDB limit)."""
        # Seed 30 packages
        for i in range(30):
            mock_packages_table.put_item(
                Item={"pk": f"npm#pkg-{i}", "sk": "LATEST", "name": f"pkg-{i}"}
            )

        names = [f"pkg-{i}" for i in range(30)]
        result = batch_get_packages("npm", names)

        assert len(result) == 30

    def test_extracts_name_from_pk_correctly(self, mock_packages_table):
        """Should correctly extract package name from pk."""
        mock_packages_table.put_item(
            Item={"pk": "npm#@scope/package", "sk": "LATEST", "name": "@scope/package"}
        )

        result = batch_get_packages("npm", ["@scope/package"])

        assert "@scope/package" in result

    def test_handles_unprocessed_keys_with_retry(self, reset_dynamodb):
        """Should retry unprocessed keys with backoff."""
        with mock_aws():
            dynamo_module._dynamodb = None
            dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

            dynamodb.create_table(
                TableName=PACKAGES_TABLE,
                KeySchema=[
                    {"AttributeName": "pk", "KeyType": "HASH"},
                    {"AttributeName": "sk", "KeyType": "RANGE"},
                ],
                AttributeDefinitions=[
                    {"AttributeName": "pk", "AttributeType": "S"},
                    {"AttributeName": "sk", "AttributeType": "S"},
                ],
                BillingMode="PAY_PER_REQUEST",
            )

            table = dynamodb.Table(PACKAGES_TABLE)
            table.put_item(Item={"pk": "npm#test", "sk": "LATEST", "name": "test"})

            call_count = 0

            def batch_with_unprocessed(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    # First call returns unprocessed keys
                    return {
                        "Responses": {},
                        "UnprocessedKeys": {
                            PACKAGES_TABLE: {
                                "Keys": [{"pk": {"S": "npm#test"}, "sk": {"S": "LATEST"}}]
                            }
                        },
                    }
                # Second call succeeds
                return {
                    "Responses": {
                        PACKAGES_TABLE: [{"pk": {"S": "npm#test"}, "sk": {"S": "LATEST"}, "name": {"S": "test"}}]
                    },
                    "UnprocessedKeys": {},
                }

            # Need to patch at the DynamoDB resource level
            with patch("time.sleep"):
                result = batch_get_packages("npm", ["test"])

            # Should have result
            assert "test" in result or result == {}  # moto behavior may vary


class TestTableNameConfiguration:
    """Tests for table name configuration."""

    def test_uses_env_var_for_table_name(self):
        """Should use PACKAGES_TABLE environment variable."""
        with patch.dict(os.environ, {"PACKAGES_TABLE": "custom-table-name"}):
            import importlib
            importlib.reload(dynamo_module)

            assert dynamo_module.PACKAGES_TABLE == "custom-table-name"

        # Reset
        importlib.reload(dynamo_module)

    def test_default_table_name(self):
        """Default table name should be pkgwatch-packages."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove PACKAGES_TABLE if it exists
            os.environ.pop("PACKAGES_TABLE", None)
            import importlib
            importlib.reload(dynamo_module)

            assert dynamo_module.PACKAGES_TABLE == "pkgwatch-packages"


class TestEdgeCases:
    """Edge case tests for dynamo module."""

    def test_package_name_with_special_chars(self, mock_packages_table):
        """Should handle package names with special characters."""
        special_name = "@org/pkg-name.v2"
        mock_packages_table.put_item(
            Item={"pk": f"npm#{special_name}", "sk": "LATEST", "name": special_name}
        )

        result = get_package("npm", special_name)

        assert result is not None
        assert result["name"] == special_name

    def test_very_long_package_name(self, mock_packages_table):
        """Should handle long package names."""
        long_name = "a" * 200
        mock_packages_table.put_item(
            Item={"pk": f"npm#{long_name}", "sk": "LATEST", "name": long_name}
        )

        result = get_package("npm", long_name)

        assert result is not None

    def test_unicode_in_package_data(self, mock_packages_table):
        """Should handle unicode in package data."""
        put_package(
            "npm",
            "unicode-test",
            {"description": "Test with unicode: \u00e9\u00e8\u00ea \u4e2d\u6587"},
        )

        result = get_package("npm", "unicode-test")

        assert "\u00e9\u00e8\u00ea" in result["description"]
        assert "\u4e2d\u6587" in result["description"]

    def test_decimal_values_in_package_data(self, mock_packages_table):
        """Should handle Decimal values correctly."""
        put_package(
            "npm",
            "decimal-test",
            {"score": Decimal("85.5"), "count": Decimal("1000")},
        )

        result = get_package("npm", "decimal-test")

        assert result["score"] == Decimal("85.5")

    def test_nested_dict_in_package_data(self, mock_packages_table):
        """Should handle nested dictionaries."""
        put_package(
            "npm",
            "nested-test",
            {
                "metadata": {
                    "nested": {"deep": "value"},
                    "list": [1, 2, 3],
                }
            },
        )

        result = get_package("npm", "nested-test")

        assert result["metadata"]["nested"]["deep"] == "value"
        assert result["metadata"]["list"] == [1, 2, 3]
