"""
Tests for admin/migrate_queryable.py - Backfill migration for the queryable field.
"""

import json
import os

import boto3
import pytest
from moto import mock_aws
from unittest.mock import patch, MagicMock


class TestMigrateQueryableHandler:
    """Tests for the migrate_queryable Lambda handler."""

    @mock_aws
    def test_dry_run_reports_changes_without_applying(self, mock_dynamodb):
        """Dry run should report what would change but not modify DynamoDB."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Insert a package that should be queryable but has queryable=False
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "latest_version": "4.17.21",
                "health_score": 85,
                "weekly_downloads": 1000000,
                "data_status": "complete",
                "queryable": False,
            }
        )

        from admin.migrate_queryable import handler

        result = handler({"dry_run": True}, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["dry_run"] is True
        assert "Dry run complete" in body["message"]
        assert body["stats"]["set_to_true"] == 1
        assert body["stats"]["updated"] == 0  # No actual updates in dry run

        # Verify DynamoDB was NOT modified
        item = table.get_item(Key={"pk": "npm#lodash", "sk": "LATEST"})["Item"]
        assert item["queryable"] is False  # Should remain unchanged

    @mock_aws
    def test_updates_queryable_field_for_eligible_packages(self, mock_dynamodb):
        """Should set queryable=True for packages that meet criteria."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Package with complete data but queryable=False
        table.put_item(
            Item={
                "pk": "npm#express",
                "sk": "LATEST",
                "latest_version": "4.18.0",
                "health_score": 90,
                "weekly_downloads": 5000000,
                "dependents_count": 10000,
                "data_status": "complete",
                "queryable": False,
            }
        )

        from admin.migrate_queryable import handler

        result = handler({"dry_run": False}, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["stats"]["updated"] == 1
        assert body["stats"]["set_to_true"] == 1

        # Verify DynamoDB was updated
        item = table.get_item(Key={"pk": "npm#express", "sk": "LATEST"})["Item"]
        assert item["queryable"] is True
        assert "migrated_at" in item

    @mock_aws
    def test_sets_queryable_false_for_ineligible_packages(self, mock_dynamodb):
        """Should set queryable=False for packages that do not meet criteria."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Package with queryable=True but missing health_score
        table.put_item(
            Item={
                "pk": "npm#broken-pkg",
                "sk": "LATEST",
                "latest_version": "1.0.0",
                # No health_score
                "weekly_downloads": 100,
                "data_status": "pending",
                "queryable": True,
            }
        )

        from admin.migrate_queryable import handler

        result = handler({"dry_run": False}, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["stats"]["set_to_false"] == 1

        # Verify DynamoDB was updated
        item = table.get_item(Key={"pk": "npm#broken-pkg", "sk": "LATEST"})["Item"]
        assert item["queryable"] is False

    @mock_aws
    def test_skips_already_correct_packages(self, mock_dynamodb):
        """Should not update packages where queryable is already correct."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Package that is correctly queryable=True
        table.put_item(
            Item={
                "pk": "npm#correct-pkg",
                "sk": "LATEST",
                "latest_version": "2.0.0",
                "health_score": 75,
                "weekly_downloads": 500,
                "data_status": "complete",
                "queryable": True,
            }
        )

        from admin.migrate_queryable import handler

        result = handler({"dry_run": False}, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["stats"]["already_correct"] == 1
        assert body["stats"]["updated"] == 0

    @mock_aws
    def test_skips_non_latest_records(self, mock_dynamodb):
        """Should only process records with sk=LATEST."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # A LATEST record
        table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "LATEST",
                "latest_version": "1.0.0",
                "health_score": 80,
                "weekly_downloads": 1000,
                "data_status": "complete",
                "queryable": False,
            }
        )

        # A historical version record (should be skipped)
        table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "v1.0.0",
                "latest_version": "1.0.0",
                "health_score": 80,
                "weekly_downloads": 1000,
                "data_status": "complete",
                "queryable": False,
            }
        )

        from admin.migrate_queryable import handler

        result = handler({"dry_run": False}, {})

        body = json.loads(result["body"])
        # Only the LATEST record should trigger an update
        assert body["stats"]["set_to_true"] == 1
        assert body["stats"]["updated"] == 1

    @mock_aws
    def test_tracks_missing_data_status(self, mock_dynamodb):
        """Should track packages that have no data_status field."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Package without data_status
        table.put_item(
            Item={
                "pk": "npm#legacy-pkg",
                "sk": "LATEST",
                "latest_version": "1.0.0",
                "health_score": 60,
                "weekly_downloads": 0,
                "dependents_count": 0,
                # No data_status
            }
        )

        from admin.migrate_queryable import handler

        result = handler({"dry_run": True}, {})

        body = json.loads(result["body"])
        assert body["stats"]["missing_data_status"] == 1

    @mock_aws
    def test_max_items_limits_processing(self, mock_dynamodb):
        """Should stop processing after max_items is reached."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Insert 5 packages
        for i in range(5):
            table.put_item(
                Item={
                    "pk": f"npm#pkg-{i}",
                    "sk": "LATEST",
                    "latest_version": "1.0.0",
                    "health_score": 80,
                    "weekly_downloads": 1000,
                    "data_status": "complete",
                    "queryable": False,
                }
            )

        from admin.migrate_queryable import handler

        result = handler({"dry_run": True, "max_items": 3}, {})

        body = json.loads(result["body"])
        assert body["stats"]["scanned"] <= 3

    @mock_aws
    def test_batch_size_controls_write_batching(self, mock_dynamodb):
        """Should write updates in batches of the specified size."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Insert 5 packages that need updating
        for i in range(5):
            table.put_item(
                Item={
                    "pk": f"npm#pkg-{i}",
                    "sk": "LATEST",
                    "latest_version": "1.0.0",
                    "health_score": 80,
                    "weekly_downloads": 1000,
                    "data_status": "complete",
                    "queryable": False,
                }
            )

        from admin.migrate_queryable import handler

        result = handler({"dry_run": False, "batch_size": 2}, {})

        body = json.loads(result["body"])
        # All 5 should eventually get updated regardless of batch size
        assert body["stats"]["updated"] == 5

    @mock_aws
    def test_handles_dynamodb_client_error(self, mock_dynamodb):
        """Should handle DynamoDB errors gracefully and report in stats."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        from admin.migrate_queryable import handler

        # Use a non-existent table name to trigger a ClientError on scan
        os.environ["PACKAGES_TABLE"] = "nonexistent-table"

        import admin.migrate_queryable as migrate_module
        old_table = migrate_module.PACKAGES_TABLE
        migrate_module.PACKAGES_TABLE = "nonexistent-table"

        try:
            result = handler({"dry_run": False}, {})

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["stats"]["errors"] >= 1
        finally:
            migrate_module.PACKAGES_TABLE = old_table
            os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

    @mock_aws
    def test_default_event_parameters(self, mock_dynamodb):
        """Should use default values when event has no parameters."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        from admin.migrate_queryable import handler

        result = handler({}, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["dry_run"] is False
        assert body["message"] == "Migration complete"

    @mock_aws
    def test_empty_table_returns_zero_stats(self, mock_dynamodb):
        """Should handle an empty table and return all-zero stats."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        from admin.migrate_queryable import handler

        result = handler({"dry_run": False}, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["stats"]["scanned"] == 0
        assert body["stats"]["updated"] == 0
        assert body["stats"]["already_correct"] == 0
        assert body["stats"]["errors"] == 0

    @mock_aws
    def test_package_with_zero_downloads_but_complete_status_is_queryable(self, mock_dynamodb):
        """Package with 0 downloads but data_status=complete should be queryable."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "npm#zero-download-pkg",
                "sk": "LATEST",
                "latest_version": "1.0.0",
                "health_score": 50,
                "weekly_downloads": 0,
                "dependents_count": 0,
                "data_status": "complete",
                "queryable": False,
            }
        )

        from admin.migrate_queryable import handler

        result = handler({"dry_run": False}, {})

        body = json.loads(result["body"])
        assert body["stats"]["set_to_true"] == 1

        item = table.get_item(Key={"pk": "npm#zero-download-pkg", "sk": "LATEST"})["Item"]
        assert item["queryable"] is True

    @mock_aws
    def test_package_missing_latest_version_is_not_queryable(self, mock_dynamodb):
        """Package without latest_version should not be queryable."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "npm#no-version-pkg",
                "sk": "LATEST",
                # No latest_version
                "health_score": 70,
                "weekly_downloads": 1000,
                "data_status": "partial",
                "queryable": True,  # Incorrectly set to True
            }
        )

        from admin.migrate_queryable import handler

        result = handler({"dry_run": False}, {})

        body = json.loads(result["body"])
        assert body["stats"]["set_to_false"] == 1

        item = table.get_item(Key={"pk": "npm#no-version-pkg", "sk": "LATEST"})["Item"]
        assert item["queryable"] is False

    @mock_aws
    def test_package_missing_health_score_is_not_queryable(self, mock_dynamodb):
        """Package without health_score should not be queryable."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "npm#no-score-pkg",
                "sk": "LATEST",
                "latest_version": "1.0.0",
                # No health_score
                "weekly_downloads": 5000,
                "data_status": "partial",
                "queryable": True,  # Incorrectly set to True
            }
        )

        from admin.migrate_queryable import handler

        result = handler({"dry_run": False}, {})

        body = json.loads(result["body"])
        assert body["stats"]["set_to_false"] == 1


class TestWriteBatch:
    """Tests for the _write_batch helper function."""

    @mock_aws
    def test_writes_updates_to_dynamodb(self, mock_dynamodb):
        """Should update items in DynamoDB with queryable field and timestamp."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Pre-seed the item
        table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "LATEST",
                "latest_version": "1.0.0",
            }
        )

        from admin.migrate_queryable import _write_batch

        stats = {"updated": 0, "errors": 0}
        updates = [{"pk": "npm#test-pkg", "queryable": True}]

        _write_batch(table, updates, stats)

        assert stats["updated"] == 1
        assert stats["errors"] == 0

        item = table.get_item(Key={"pk": "npm#test-pkg", "sk": "LATEST"})["Item"]
        assert item["queryable"] is True
        assert "migrated_at" in item

    @mock_aws
    def test_handles_update_error_gracefully(self, mock_dynamodb):
        """Should increment error count when individual update fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        from admin.migrate_queryable import _write_batch

        stats = {"updated": 0, "errors": 0}

        # Mock table.update_item to raise an error
        with patch.object(table, "update_item", side_effect=Exception("DynamoDB error")):
            _write_batch(table, [{"pk": "npm#fail-pkg", "queryable": True}], stats)

        assert stats["errors"] == 1
        assert stats["updated"] == 0

    @mock_aws
    def test_writes_multiple_updates(self, mock_dynamodb):
        """Should write all updates in the batch."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Pre-seed items
        for i in range(3):
            table.put_item(
                Item={
                    "pk": f"npm#pkg-{i}",
                    "sk": "LATEST",
                    "latest_version": "1.0.0",
                }
            )

        from admin.migrate_queryable import _write_batch

        stats = {"updated": 0, "errors": 0}
        updates = [
            {"pk": "npm#pkg-0", "queryable": True},
            {"pk": "npm#pkg-1", "queryable": False},
            {"pk": "npm#pkg-2", "queryable": True},
        ]

        _write_batch(table, updates, stats)

        assert stats["updated"] == 3
        assert stats["errors"] == 0
