"""
Tests for admin/data_status_metrics.py - CloudWatch metrics for data status distribution.
"""

import os
from unittest.mock import MagicMock, patch

from moto import mock_aws


class TestCountByStatus:
    """Tests for the count_by_status function (deprecated GSI-based)."""

    @mock_aws
    def test_counts_packages_with_given_status(self, mock_dynamodb):
        """Should return correct count for packages with a specific data_status."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Insert 3 complete packages (with next_retry_at for GSI visibility)
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


class TestScanAllMetrics:
    """Tests for the scan_all_metrics function."""

    @mock_aws
    def test_counts_all_statuses_including_without_next_retry_at(self, mock_dynamodb):
        """Should count packages correctly even without next_retry_at (the GSI bug)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Complete packages WITHOUT next_retry_at (these were invisible to the GSI)
        for i in range(5):
            table.put_item(
                Item={
                    "pk": f"npm#complete-{i}",
                    "sk": "LATEST",
                    "ecosystem": "npm",
                    "data_status": "complete",
                    "weekly_downloads": 1000,
                }
            )

        # Partial packages WITH next_retry_at
        for i in range(3):
            table.put_item(
                Item={
                    "pk": f"pypi#partial-{i}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "data_status": "partial",
                    "next_retry_at": "2024-01-01T00:00:00Z",
                    "weekly_downloads": 500,
                }
            )

        from admin.data_status_metrics import scan_all_metrics

        result = scan_all_metrics(table)

        assert result["status_counts"]["complete"] == 5
        assert result["status_counts"]["partial"] == 3
        assert result["coverage"]["npm_total"] == 5
        assert result["coverage"]["npm_with_downloads"] == 5
        assert result["coverage"]["pypi_total"] == 3
        assert result["coverage"]["pypi_with_downloads"] == 3

    @mock_aws
    def test_counts_pypi_never_fetched(self, mock_dynamodb):
        """Should count PyPI packages with no downloads_status as never_fetched."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # PyPI package with no downloads_status
        table.put_item(
            Item={
                "pk": "pypi#pkg-a",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "data_status": "complete",
                "weekly_downloads": 0,
            }
        )
        # PyPI package with downloads_status = "collected"
        table.put_item(
            Item={
                "pk": "pypi#pkg-b",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "data_status": "complete",
                "weekly_downloads": 100,
                "downloads_status": "collected",
            }
        )

        from admin.data_status_metrics import scan_all_metrics

        result = scan_all_metrics(table)

        assert result["coverage"]["pypi_never_fetched"] == 1
        assert result["coverage"]["pypi_with_downloads"] == 1

    @mock_aws
    def test_returns_zeros_for_empty_table(self, mock_dynamodb):
        """Should return zero counts for empty table."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        from admin.data_status_metrics import scan_all_metrics

        result = scan_all_metrics(table)

        for status in ["complete", "partial", "minimal", "pending", "abandoned_minimal", "abandoned_partial"]:
            assert result["status_counts"][status] == 0
        assert result["coverage"]["npm_total"] == 0
        assert result["coverage"]["pypi_total"] == 0


class TestDataStatusMetricsHandler:
    """Tests for the data_status_metrics Lambda handler."""

    @mock_aws
    def test_returns_counts_for_all_statuses(self, mock_dynamodb):
        """Should return counts for all known data status values."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Seed packages with different statuses — NO next_retry_at on complete/abandoned
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
                item = {
                    "pk": f"npm#pkg-{counter}",
                    "sk": "LATEST",
                    "ecosystem": "npm",
                    "data_status": status,
                    "weekly_downloads": 100,
                }
                # Only partial/minimal/pending get next_retry_at (matching real behavior)
                if status in ("partial", "minimal", "pending"):
                    item["next_retry_at"] = f"2024-01-01T{counter:02d}:00:00Z"
                table.put_item(Item=item)
                counter += 1

        # Reset the module-level dynamodb resource to use mock
        import admin.data_status_metrics as metrics_module
        from admin.data_status_metrics import handler

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

        import admin.data_status_metrics as metrics_module
        from admin.data_status_metrics import handler

        metrics_module.dynamodb = mock_dynamodb

        result = handler({}, {})

        assert result["statusCode"] == 200
        counts = result["counts"]
        for status in ["complete", "partial", "minimal", "pending", "abandoned_minimal", "abandoned_partial"]:
            assert counts[status] == 0

    @mock_aws
    def test_handles_scan_error_gracefully(self, mock_dynamodb):
        """Should set counts to 0 and log error when scan fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        import admin.data_status_metrics as metrics_module
        from admin.data_status_metrics import handler

        metrics_module.dynamodb = mock_dynamodb

        with patch.object(metrics_module, "scan_all_metrics", side_effect=Exception("Simulated DynamoDB error")):
            result = handler({}, {})

        assert result["statusCode"] == 200
        assert result["counts"]["complete"] == 0

    @mock_aws
    def test_emits_cloudwatch_metrics(self, mock_dynamodb):
        """Should call emit_batch_metrics with the correct metric data."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        table = mock_dynamodb.Table("pkgwatch-packages")
        # Complete package WITHOUT next_retry_at — must still be counted
        table.put_item(
            Item={
                "pk": "npm#pkg-1",
                "sk": "LATEST",
                "ecosystem": "npm",
                "data_status": "complete",
                "weekly_downloads": 1000,
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
        assert len(metrics_list) == 9

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
