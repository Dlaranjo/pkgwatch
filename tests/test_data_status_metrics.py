"""
Tests for admin/data_status_metrics.py - CloudWatch metrics for data status distribution.
"""

import json
import os

import boto3
import pytest
from moto import mock_aws
from unittest.mock import patch, MagicMock


class TestCountByStatus:
    """Tests for the count_by_status function."""

    @mock_aws
    def test_counts_packages_with_given_status(self, mock_dynamodb):
        """Should return correct count for packages with a specific data_status."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Insert 3 complete packages
        for i in range(3):
            table.put_item(
                Item={
                    "pk": f"npm#pkg-{i}",
                    "sk": "LATEST",
                    "data_status": "complete",
                    "next_retry_at": "2024-01-01T00:00:00Z",
                }
            )

        # Insert 2 partial packages
        for i in range(2):
            table.put_item(
                Item={
                    "pk": f"npm#partial-{i}",
                    "sk": "LATEST",
                    "data_status": "partial",
                    "next_retry_at": "2024-01-01T00:00:00Z",
                }
            )

        from admin.data_status_metrics import count_by_status

        assert count_by_status(table, "complete") == 3
        assert count_by_status(table, "partial") == 2

    @mock_aws
    def test_returns_zero_for_nonexistent_status(self, mock_dynamodb):
        """Should return 0 when no packages have the given status."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        from admin.data_status_metrics import count_by_status

        assert count_by_status(table, "complete") == 0

    @mock_aws
    def test_returns_zero_for_empty_table(self, mock_dynamodb):
        """Should return 0 for an empty table."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        from admin.data_status_metrics import count_by_status

        assert count_by_status(table, "pending") == 0


class TestDataStatusMetricsHandler:
    """Tests for the data_status_metrics Lambda handler."""

    @mock_aws
    def test_returns_counts_for_all_statuses(self, mock_dynamodb):
        """Should return counts for all known data status values."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Seed packages with different statuses
        statuses = {
            "complete": 5,
            "partial": 3,
            "minimal": 2,
            "pending": 4,
            "abandoned_minimal": 1,
            "abandoned_partial": 1,
        }

        counter = 0
        for status, count in statuses.items():
            for i in range(count):
                table.put_item(
                    Item={
                        "pk": f"npm#pkg-{counter}",
                        "sk": "LATEST",
                        "data_status": status,
                        "next_retry_at": f"2024-01-01T{counter:02d}:00:00Z",
                    }
                )
                counter += 1

        from admin.data_status_metrics import handler

        # Reset the module-level dynamodb resource to use mock
        import admin.data_status_metrics as metrics_module
        metrics_module.dynamodb = mock_dynamodb

        result = handler({}, {})

        assert result["statusCode"] == 200
        counts = result["counts"]
        assert counts["complete"] == 5
        assert counts["partial"] == 3
        assert counts["minimal"] == 2
        assert counts["pending"] == 4
        assert counts["abandoned_minimal"] == 1
        assert counts["abandoned_partial"] == 1

    @mock_aws
    def test_returns_zeros_for_empty_table(self, mock_dynamodb):
        """Should return zero counts when table has no packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        from admin.data_status_metrics import handler

        import admin.data_status_metrics as metrics_module
        metrics_module.dynamodb = mock_dynamodb

        result = handler({}, {})

        assert result["statusCode"] == 200
        counts = result["counts"]
        for status in ["complete", "partial", "minimal", "pending", "abandoned_minimal", "abandoned_partial"]:
            assert counts[status] == 0

    @mock_aws
    def test_handles_query_error_gracefully(self, mock_dynamodb):
        """Should set count to 0 and log error when query fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        from admin.data_status_metrics import handler

        import admin.data_status_metrics as metrics_module
        metrics_module.dynamodb = mock_dynamodb

        # Patch count_by_status to raise an exception for a specific status
        original_count = metrics_module.count_by_status

        def failing_count(table, status):
            if status == "complete":
                raise Exception("Simulated DynamoDB error")
            return original_count(table, status)

        with patch.object(metrics_module, "count_by_status", side_effect=failing_count):
            result = handler({}, {})

        assert result["statusCode"] == 200
        # "complete" should be 0 due to the error
        assert result["counts"]["complete"] == 0
        # Other statuses should still work
        assert "partial" in result["counts"]

    @mock_aws
    def test_emits_cloudwatch_metrics(self, mock_dynamodb):
        """Should call emit_batch_metrics with the correct metric data."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#pkg-1",
                "sk": "LATEST",
                "data_status": "complete",
                "next_retry_at": "2024-01-01T00:00:00Z",
            }
        )

        import admin.data_status_metrics as metrics_module
        metrics_module.dynamodb = mock_dynamodb

        with patch("shared.metrics.emit_batch_metrics") as mock_emit:
            result = metrics_module.handler({}, {})

        assert result["statusCode"] == 200
        # Verify emit_batch_metrics was called
        mock_emit.assert_called_once()
        metrics_list = mock_emit.call_args[0][0]
        assert len(metrics_list) == 6

        # Check that CompletePackages metric has value 1
        complete_metric = next(m for m in metrics_list if m["metric_name"] == "CompletePackages")
        assert complete_metric["value"] == 1

    @mock_aws
    def test_handles_metrics_emit_failure(self, mock_dynamodb):
        """Should still return counts even if metric emission fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        import admin.data_status_metrics as metrics_module
        metrics_module.dynamodb = mock_dynamodb

        with patch("shared.metrics.emit_batch_metrics", side_effect=Exception("CloudWatch down")):
            result = metrics_module.handler({}, {})

        # Should still return 200 with counts despite metrics failure
        assert result["statusCode"] == 200
        assert "counts" in result

    @mock_aws
    def test_handler_with_realistic_event_and_context(self, mock_dynamodb):
        """Should handle a realistic EventBridge event and Lambda context."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        import admin.data_status_metrics as metrics_module
        metrics_module.dynamodb = mock_dynamodb

        # Simulate an EventBridge scheduled event
        event = {
            "version": "0",
            "id": "12345678-1234-1234-1234-123456789012",
            "detail-type": "Scheduled Event",
            "source": "aws.events",
            "time": "2024-01-15T12:00:00Z",
            "region": "us-east-1",
            "resources": ["arn:aws:events:us-east-1:123456789012:rule/daily-metrics"],
            "detail": {},
        }

        # Simulate a Lambda context object
        context = MagicMock()
        context.function_name = "pkgwatch-data-status-metrics"
        context.memory_limit_in_mb = 128
        context.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:pkgwatch-data-status-metrics"
        context.get_remaining_time_in_millis.return_value = 300000

        with patch("shared.metrics.emit_batch_metrics"):
            result = metrics_module.handler(event, context)

        assert result["statusCode"] == 200
