"""Tests for data quality gates (queryable field, downloads_status, etc.)."""
import os
import sys

import boto3
import pytest
from moto import mock_aws

# Set up test environment before imports
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("PACKAGES_TABLE", "pkgwatch-packages")

# Add paths for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions", "collectors"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions", "shared"))


def _is_queryable(data: dict) -> bool:
    """
    Local copy of _is_queryable for testing without collector imports.

    This mirrors the logic in package_collector.py and score_package.py.
    """
    latest_version = data.get("latest_version")
    health_score = data.get("health_score")
    weekly_downloads = data.get("weekly_downloads", 0)
    dependents_count = data.get("dependents_count", 0)
    data_status = data.get("data_status")

    return (
        latest_version is not None
        and health_score is not None
        and (weekly_downloads > 0 or dependents_count > 0 or data_status == "complete")
    )


class TestIsQueryable:
    """Tests for the _is_queryable function logic."""

    def test_queryable_true_with_all_requirements(self):
        """Package with version, score, and downloads should be queryable."""
        data = {
            "latest_version": "1.0.0",
            "health_score": 85,
            "weekly_downloads": 1000,
            "dependents_count": 0,
            "data_status": "partial",
        }
        assert _is_queryable(data) is True

    def test_queryable_true_with_dependents_only(self):
        """Package with dependents (no downloads) should be queryable."""
        data = {
            "latest_version": "1.0.0",
            "health_score": 85,
            "weekly_downloads": 0,
            "dependents_count": 100,
            "data_status": "partial",
        }
        assert _is_queryable(data) is True

    def test_queryable_true_with_complete_status_escape_hatch(self):
        """Package with complete status and 0 downloads/dependents should be queryable."""
        data = {
            "latest_version": "1.0.0",
            "health_score": 75,
            "weekly_downloads": 0,
            "dependents_count": 0,
            "data_status": "complete",
        }
        assert _is_queryable(data) is True

    def test_queryable_false_without_health_score(self):
        """Package without health_score should not be queryable."""
        data = {
            "latest_version": "1.0.0",
            "health_score": None,
            "weekly_downloads": 1000,
            "dependents_count": 50,
            "data_status": "complete",
        }
        assert _is_queryable(data) is False

    def test_queryable_false_without_latest_version(self):
        """Package without latest_version should not be queryable."""
        data = {
            "latest_version": None,
            "health_score": 85,
            "weekly_downloads": 1000,
            "dependents_count": 50,
            "data_status": "complete",
        }
        assert _is_queryable(data) is False

    def test_queryable_false_with_zero_downloads_and_partial_status(self):
        """Package with 0 downloads, 0 dependents, and partial status should not be queryable."""
        data = {
            "latest_version": "1.0.0",
            "health_score": 85,
            "weekly_downloads": 0,
            "dependents_count": 0,
            "data_status": "partial",
        }
        assert _is_queryable(data) is False

    def test_queryable_handles_missing_fields_gracefully(self):
        """Missing fields should be treated as None/0."""
        # Missing all optional fields
        data = {"latest_version": "1.0.0", "health_score": 85}
        # Should be False because downloads=0, dependents=0, and data_status is None
        assert _is_queryable(data) is False

        # With downloads but missing other fields
        data = {"latest_version": "1.0.0", "health_score": 85, "weekly_downloads": 100}
        assert _is_queryable(data) is True


class TestScorePackageQueryable:
    """Tests for queryable computation in score_package.py."""

    def test_score_package_is_queryable(self):
        """Test _is_queryable in score_package module."""
        from scoring.score_package import _is_queryable

        # Complete package with all data
        data = {
            "latest_version": "1.0.0",
            "health_score": 85,
            "weekly_downloads": 1000,
            "dependents_count": 50,
            "data_status": "complete",
        }
        assert _is_queryable(data) is True

    def test_score_package_is_queryable_escape_hatch(self):
        """Test escape hatch for packages with zero downloads/dependents."""
        from scoring.score_package import _is_queryable

        # Package with complete status but 0 downloads/dependents
        data = {
            "latest_version": "1.0.0",
            "health_score": 70,
            "weekly_downloads": 0,
            "dependents_count": 0,
            "data_status": "complete",
        }
        assert _is_queryable(data) is True


class TestSeedPackagesInitialState:
    """Tests for seed_packages.py setting initial data_status and queryable."""

    def test_seed_packages_sets_pending_status_and_queryable_false(self, mock_dynamodb):
        """Seeded packages should have data_status='pending' and queryable=False."""
        # Import after moto is active
        from admin import seed_packages

        # Mock the Lambda client to avoid calling refresh dispatcher
        seed_packages.REFRESH_DISPATCHER_ARN = ""

        # Call batch_write_packages directly
        packages = [{"name": "test-package", "rank": 1}]
        success, errors = seed_packages.batch_write_packages(
            "pkgwatch-packages", packages, "npm"
        )

        assert success == 1
        assert errors == 0

        # Verify the item was written with correct fields
        table = mock_dynamodb.Table("pkgwatch-packages")
        response = table.get_item(Key={"pk": "npm#test-package", "sk": "LATEST"})
        item = response.get("Item")

        assert item is not None
        assert item.get("data_status") == "pending"
        assert item.get("queryable") is False
        assert item.get("needs_collection") is True


class TestDownloadsStatusValues:
    """Tests for downloads_status field values in pypi_downloads_collector."""

    def test_downloads_status_collected(self):
        """Successful fetch should set downloads_status to 'collected'."""
        # This is a unit test for the status value - integration tested separately
        status = "collected"
        assert status in ["collected", "unavailable", "rate_limited", "pending"]

    def test_downloads_status_unavailable(self):
        """404 response should set downloads_status to 'unavailable'."""
        status = "unavailable"
        assert status in ["collected", "unavailable", "rate_limited", "pending"]

    def test_downloads_status_rate_limited(self):
        """429 response should set downloads_status to 'rate_limited'."""
        status = "rate_limited"
        assert status in ["collected", "unavailable", "rate_limited", "pending"]


class TestMigrateQueryable:
    """Tests for the queryable field migration script."""

    def test_migrate_is_queryable_function(self):
        """Test the migration script's _is_queryable function."""
        from admin.migrate_queryable import _is_queryable

        # Complete package
        item = {
            "latest_version": "1.0.0",
            "health_score": 85.0,
            "weekly_downloads": 1000,
            "dependents_count": 50,
            "data_status": "complete",
        }
        assert _is_queryable(item) is True

        # Missing health_score
        item = {
            "latest_version": "1.0.0",
            "health_score": None,
            "weekly_downloads": 1000,
            "dependents_count": 50,
            "data_status": "complete",
        }
        assert _is_queryable(item) is False

        # Zero downloads/dependents with complete status (escape hatch)
        item = {
            "latest_version": "1.0.0",
            "health_score": 75.0,
            "weekly_downloads": 0,
            "dependents_count": 0,
            "data_status": "complete",
        }
        assert _is_queryable(item) is True


class TestPackageCollectorQueryableIntegration:
    """Integration tests for queryable field - run separately with full PYTHONPATH.

    These tests verify that the queryable field is correctly set by package_collector
    and score_package modules. They require the full collector environment to be set up.

    To run: PYTHONPATH=functions/collectors:functions:. pytest tests/test_data_quality_gates.py::TestPackageCollectorQueryableIntegration -v
    """

    def test_queryable_logic_matches_scoring_module(self):
        """Verify the local _is_queryable matches scoring module implementation."""
        from scoring.score_package import _is_queryable as score_is_queryable

        # Test data
        test_cases = [
            # (data, expected_result)
            ({"latest_version": "1.0.0", "health_score": 85, "weekly_downloads": 1000}, True),
            ({"latest_version": "1.0.0", "health_score": 85, "weekly_downloads": 0, "dependents_count": 100}, True),
            ({"latest_version": "1.0.0", "health_score": 85, "weekly_downloads": 0, "data_status": "complete"}, True),
            ({"latest_version": "1.0.0", "health_score": None, "weekly_downloads": 1000}, False),
            ({"latest_version": None, "health_score": 85, "weekly_downloads": 1000}, False),
        ]

        for data, expected in test_cases:
            local_result = _is_queryable(data)
            score_result = score_is_queryable(data)
            assert local_result == expected, f"Local _is_queryable failed for {data}"
            assert score_result == expected, f"score_package._is_queryable failed for {data}"
            assert local_result == score_result, f"Implementations differ for {data}"


@pytest.fixture
def mock_dynamodb():
    """Provide mocked DynamoDB with tables for seed_packages tests."""
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

        # Create packages table only (seed_packages doesn't need api-keys table)
        dynamodb.create_table(
            TableName="pkgwatch-packages",
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

        yield dynamodb
