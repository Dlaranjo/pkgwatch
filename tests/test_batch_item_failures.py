"""
Tests for SQS partial batch failure handling in package_collector.
"""

import asyncio
import json
import os
from unittest.mock import MagicMock, patch

# Set up environment before importing
os.environ.setdefault("PACKAGES_TABLE", "pkgwatch-packages")
os.environ.setdefault("RAW_DATA_BUCKET", "pkgwatch-raw-data")
os.environ.setdefault("GITHUB_TOKEN_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123456789:secret:github-token")
os.environ.setdefault("API_KEYS_TABLE", "pkgwatch-api-keys")

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../functions/collectors"))


class TestProcessBatch:
    """Tests for process_batch with partial batch failure handling."""

    @patch("package_collector.process_single_package")
    @patch("package_collector.emit_metric")
    @patch("package_collector.emit_batch_metrics")
    def test_process_batch_returns_failed_message_ids(
        self, mock_batch_metrics, mock_metric, mock_process
    ):
        """Test that process_batch returns list of failed message IDs."""
        from package_collector import process_batch

        # Mock process_single_package to return success for first, failure for second
        mock_process.side_effect = [
            (True, "npm/lodash", None),
            (False, "npm/broken", "timeout"),
        ]

        records = [
            {"messageId": "msg-1", "body": json.dumps({"ecosystem": "npm", "name": "lodash"})},
            {"messageId": "msg-2", "body": json.dumps({"ecosystem": "npm", "name": "broken"})},
        ]

        loop = asyncio.new_event_loop()
        try:
            successes, failed_ids = loop.run_until_complete(process_batch(records))
        finally:
            loop.close()

        assert successes == 1
        assert failed_ids == ["msg-2"]

    @patch("package_collector.process_single_package")
    @patch("package_collector.emit_metric")
    @patch("package_collector.emit_batch_metrics")
    def test_process_batch_handles_json_parse_error(
        self, mock_batch_metrics, mock_metric, mock_process
    ):
        """Test that JSON parse errors result in message ID being recorded as failed."""
        from package_collector import process_batch

        records = [
            {"messageId": "msg-1", "body": "invalid json"},
            {"messageId": "msg-2", "body": json.dumps({"ecosystem": "npm", "name": "lodash"})},
        ]

        mock_process.return_value = (True, "npm/lodash", None)

        loop = asyncio.new_event_loop()
        try:
            successes, failed_ids = loop.run_until_complete(process_batch(records))
        finally:
            loop.close()

        assert "msg-1" in failed_ids
        mock_metric.assert_called()  # MessageParseError metric should be emitted

    @patch("package_collector.process_single_package")
    @patch("package_collector.emit_metric")
    @patch("package_collector.emit_batch_metrics")
    def test_process_batch_handles_exception(
        self, mock_batch_metrics, mock_metric, mock_process
    ):
        """Test that exceptions from process_single_package are handled."""
        from package_collector import process_batch

        mock_process.side_effect = Exception("Unexpected error")

        records = [
            {"messageId": "msg-1", "body": json.dumps({"ecosystem": "npm", "name": "lodash"})},
        ]

        loop = asyncio.new_event_loop()
        try:
            successes, failed_ids = loop.run_until_complete(process_batch(records))
        finally:
            loop.close()

        assert successes == 0
        assert "msg-1" in failed_ids

    @patch("package_collector.process_single_package")
    @patch("package_collector.emit_metric")
    @patch("package_collector.emit_batch_metrics")
    def test_process_batch_all_success(
        self, mock_batch_metrics, mock_metric, mock_process
    ):
        """Test that successful batch returns empty failed_ids list."""
        from package_collector import process_batch

        mock_process.return_value = (True, "npm/lodash", None)

        records = [
            {"messageId": "msg-1", "body": json.dumps({"ecosystem": "npm", "name": "lodash"})},
            {"messageId": "msg-2", "body": json.dumps({"ecosystem": "npm", "name": "react"})},
        ]

        loop = asyncio.new_event_loop()
        try:
            successes, failed_ids = loop.run_until_complete(process_batch(records))
        finally:
            loop.close()

        assert successes == 2
        assert failed_ids == []


class TestHandler:
    """Tests for the Lambda handler with batchItemFailures."""

    def test_handler_returns_batch_item_failures(self):
        """Test that handler returns batchItemFailures for failed messages."""
        from package_collector import handler

        # Need to patch asyncio loop behavior
        with patch("package_collector.asyncio.new_event_loop") as mock_loop:
            loop = MagicMock()
            mock_loop.return_value = loop
            loop.run_until_complete.return_value = (1, ["msg-2"])

            event = {
                "Records": [
                    {"messageId": "msg-1", "body": json.dumps({"ecosystem": "npm", "name": "lodash"})},
                    {"messageId": "msg-2", "body": json.dumps({"ecosystem": "npm", "name": "broken"})},
                ]
            }

            result = handler(event, None)

            assert result["statusCode"] == 200
            assert "batchItemFailures" in result
            assert result["batchItemFailures"] == [{"itemIdentifier": "msg-2"}]

    def test_handler_no_failures_no_batch_item_failures(self):
        """Test that handler omits batchItemFailures when all succeed."""
        from package_collector import handler

        with patch("package_collector.asyncio.new_event_loop") as mock_loop:
            loop = MagicMock()
            mock_loop.return_value = loop
            loop.run_until_complete.return_value = (2, [])  # No failures

            event = {
                "Records": [
                    {"messageId": "msg-1", "body": json.dumps({"ecosystem": "npm", "name": "lodash"})},
                    {"messageId": "msg-2", "body": json.dumps({"ecosystem": "npm", "name": "react"})},
                ]
            }

            result = handler(event, None)

            assert result["statusCode"] == 200
            # batchItemFailures should not be present when empty
            assert result.get("batchItemFailures") is None or result.get("batchItemFailures") == []

    def test_handler_empty_message_ids_filtered(self):
        """Test that empty message IDs are filtered from batchItemFailures."""
        from package_collector import handler

        with patch("package_collector.asyncio.new_event_loop") as mock_loop:
            loop = MagicMock()
            mock_loop.return_value = loop
            # Include empty string in failed IDs
            loop.run_until_complete.return_value = (0, ["msg-1", "", "msg-2"])

            event = {
                "Records": [
                    {"messageId": "msg-1", "body": json.dumps({"ecosystem": "npm", "name": "pkg1"})},
                    {"messageId": "msg-2", "body": json.dumps({"ecosystem": "npm", "name": "pkg2"})},
                ]
            }

            result = handler(event, None)

            # Empty strings should be filtered out
            batch_failures = result.get("batchItemFailures", [])
            item_ids = [f["itemIdentifier"] for f in batch_failures]
            assert "" not in item_ids


class TestErrorClassification:
    """Tests for error classification helper."""

    def test_classify_permanent_errors(self):
        """Test that permanent errors are classified correctly."""
        from package_collector import _classify_error

        permanent_errors = [
            "Package not found: 404",
            "Forbidden: access denied",
            "Unauthorized request",
            "Malformed package name",
            "Package name too long",
        ]

        for error in permanent_errors:
            assert _classify_error(error) == "permanent", f"Expected permanent for: {error}"

    def test_classify_transient_errors(self):
        """Test that transient errors are classified correctly."""
        from package_collector import _classify_error

        transient_errors = [
            "Request timeout",
            "Connection timed out",
            "503 Service Unavailable",
            "Rate limit exceeded",
            "Connection refused",
        ]

        for error in transient_errors:
            assert _classify_error(error) == "transient", f"Expected transient for: {error}"

    def test_classify_unknown_errors(self):
        """Test that unrecognized errors are classified as unknown."""
        from package_collector import _classify_error

        unknown_errors = [
            "Some random error",
            "Internal processing failed",
            "Unknown exception",
        ]

        for error in unknown_errors:
            assert _classify_error(error) == "unknown", f"Expected unknown for: {error}"


class TestStoreCollectionError:
    """Tests for storing collection errors in DynamoDB."""

    @patch("package_collector.get_dynamodb")
    def test_store_collection_error_success(self, mock_get_db):
        """Test successful storage of collection error."""
        from package_collector import _store_collection_error_sync

        mock_table = MagicMock()
        mock_db = MagicMock()
        mock_db.Table.return_value = mock_table
        mock_get_db.return_value = mock_db

        _store_collection_error_sync("npm", "lodash", "Connection timeout")

        mock_table.update_item.assert_called_once()
        call_args = mock_table.update_item.call_args
        assert call_args.kwargs["Key"] == {"pk": "npm#lodash", "sk": "LATEST"}
        assert ":error" in call_args.kwargs["ExpressionAttributeValues"]
        assert ":error_class" in call_args.kwargs["ExpressionAttributeValues"]

    @patch("package_collector.get_dynamodb")
    def test_store_collection_error_handles_failure(self, mock_get_db):
        """Test that storage failures don't raise exceptions."""
        from package_collector import _store_collection_error_sync

        mock_table = MagicMock()
        mock_table.update_item.side_effect = Exception("DynamoDB error")
        mock_db = MagicMock()
        mock_db.Table.return_value = mock_table
        mock_get_db.return_value = mock_db

        # Should not raise
        _store_collection_error_sync("npm", "lodash", "Some error")
