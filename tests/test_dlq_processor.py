"""
Comprehensive tests for DLQ (Dead Letter Queue) Processor.

Tests cover:
- Message reprocessing with retry tracking
- Exponential backoff delays
- Permanent failure storage after max retries
- Invalid message handling
- SQS interaction mocking

The DLQ processor is a critical component that handles failed package
collection messages, implementing retry logic to recover from transient failures.
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from moto import mock_aws

# Add functions directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions", "collectors"))


# =============================================================================
# TEST FIXTURES
# =============================================================================


@pytest.fixture
def dlq_environment(monkeypatch):
    """Set up environment variables for DLQ processor."""
    monkeypatch.setenv("DLQ_URL", "https://sqs.us-east-1.amazonaws.com/123456789012/test-dlq")
    monkeypatch.setenv("MAIN_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789012/test-main")
    monkeypatch.setenv("PACKAGES_TABLE", "pkgwatch-packages")
    monkeypatch.setenv("MAX_DLQ_RETRIES", "5")

    # Reload module to pick up new env vars
    import importlib

    import collectors.dlq_processor as dlq_module

    importlib.reload(dlq_module)

    yield dlq_module
    # monkeypatch automatically cleans up


@pytest.fixture
def sample_sqs_message():
    """Sample SQS message structure."""
    return {
        "MessageId": "msg-12345",
        "ReceiptHandle": "receipt-handle-abc123",
        "Body": json.dumps(
            {
                "ecosystem": "npm",
                "name": "test-package",
                "tier": 1,
            }
        ),
    }


@pytest.fixture
def sample_sqs_message_with_retry():
    """Sample SQS message with retry count."""
    return {
        "MessageId": "msg-retry-123",
        "ReceiptHandle": "receipt-handle-retry-abc",
        "Body": json.dumps(
            {
                "ecosystem": "npm",
                "name": "failing-package",
                "tier": 1,
                "_retry_count": 2,
                "_last_error": "Connection timeout",
            }
        ),
    }


# =============================================================================
# HANDLER TESTS
# =============================================================================


class TestDLQHandler:
    """Tests for the main DLQ handler Lambda function."""

    @mock_aws
    def test_handler_returns_error_without_dlq_url(self, mock_dynamodb):
        """Should return error when DLQ_URL is not configured."""
        os.environ["DLQ_URL"] = ""
        os.environ["MAIN_QUEUE_URL"] = "https://sqs.example.com/main"
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        from collectors.dlq_processor import handler

        result = handler({}, None)

        assert "error" in result
        assert "DLQ_URL not configured" in result["error"]

    @mock_aws
    def test_handler_returns_error_without_main_queue_url(self, mock_dynamodb, monkeypatch):
        """Should return error when MAIN_QUEUE_URL is not configured."""
        monkeypatch.setenv("DLQ_URL", "https://sqs.example.com/dlq")
        monkeypatch.setenv("MAIN_QUEUE_URL", "")
        monkeypatch.setenv("PACKAGES_TABLE", "pkgwatch-packages")

        # Reload module to pick up new env vars
        import importlib

        import collectors.dlq_processor as dlq_module

        importlib.reload(dlq_module)

        result = dlq_module.handler({}, None)

        assert "error" in result
        assert "MAIN_QUEUE_URL not configured" in result["error"]

    @mock_aws
    def test_handler_processes_messages(self, mock_dynamodb, dlq_environment, sample_sqs_message):
        """Should process messages from DLQ and requeue them."""
        # Mock SQS calls
        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            # First call returns messages, second returns empty
            mock_sqs.receive_message.side_effect = [
                {"Messages": [sample_sqs_message]},
                {"Messages": []},  # Empty queue
            ]

            result = dlq_environment.handler({}, None)

            assert result["processed"] == 1
            assert result["requeued"] == 1
            assert result["permanently_failed"] == 0

            # Verify requeue was called
            mock_sqs.send_message.assert_called_once()
            send_call = mock_sqs.send_message.call_args
            assert "MessageBody" in send_call.kwargs
            body = json.loads(send_call.kwargs["MessageBody"])
            assert body["_retry_count"] == 1

    @mock_aws
    def test_handler_processes_multiple_batches(self, mock_dynamodb, dlq_environment):
        """Should process multiple batches until queue is empty."""
        messages_batch_1 = [
            {
                "MessageId": f"msg-{i}",
                "ReceiptHandle": f"receipt-{i}",
                "Body": json.dumps({"ecosystem": "npm", "name": f"package-{i}"}),
            }
            for i in range(10)
        ]
        messages_batch_2 = [
            {
                "MessageId": f"msg-{i}",
                "ReceiptHandle": f"receipt-{i}",
                "Body": json.dumps({"ecosystem": "npm", "name": f"package-{i}"}),
            }
            for i in range(10, 15)
        ]

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            mock_sqs.receive_message.side_effect = [
                {"Messages": messages_batch_1},
                {"Messages": messages_batch_2},
                {"Messages": []},  # Empty
            ]

            result = dlq_environment.handler({}, None)

            assert result["processed"] == 15
            assert result["requeued"] == 15

    @mock_aws
    def test_handler_respects_max_iterations_limit(self, mock_dynamodb, dlq_environment):
        """Should stop after 10 batches even if messages remain."""
        # Create 12 batches worth of messages (handler has max_iterations=10)
        single_message = {
            "MessageId": "msg-123",
            "ReceiptHandle": "receipt-123",
            "Body": json.dumps({"ecosystem": "npm", "name": "test"}),
        }

        # Return 12 batches with messages
        batches = [{"Messages": [single_message]} for _ in range(12)]

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            mock_sqs.receive_message.side_effect = batches

            result = dlq_environment.handler({}, None)

            # Should only process 10 batches (max_iterations limit)
            assert result["processed"] == 10
            assert result["requeued"] == 10
            # Verify receive_message was called exactly 10 times
            assert mock_sqs.receive_message.call_count == 10

    @mock_aws
    def test_handler_tracks_mixed_results(self, mock_dynamodb, dlq_environment):
        """Should correctly track requeued, failed, and skipped messages."""
        messages = [
            # Message 1: Will be requeued (retry count < max)
            {
                "MessageId": "msg-requeue",
                "ReceiptHandle": "receipt-1",
                "Body": json.dumps(
                    {
                        "ecosystem": "npm",
                        "name": "test-requeue",
                        "_retry_count": 1,
                    }
                ),
            },
            # Message 2: Will be permanently failed (retry count >= max)
            {
                "MessageId": "msg-failed",
                "ReceiptHandle": "receipt-2",
                "Body": json.dumps(
                    {
                        "ecosystem": "npm",
                        "name": "test-failed",
                        "_retry_count": 5,  # At max
                        "_last_error": "Persistent error",
                    }
                ),
            },
            # Message 3: Invalid JSON, will be skipped
            {
                "MessageId": "msg-invalid",
                "ReceiptHandle": "receipt-3",
                "Body": "not valid json {{{",
            },
        ]

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            mock_sqs.receive_message.side_effect = [
                {"Messages": messages},
                {"Messages": []},
            ]

            result = dlq_environment.handler({}, None)

            assert result["processed"] == 3
            assert result["requeued"] == 1
            assert result["permanently_failed"] == 1
            # Skipped messages don't increment either counter

    @mock_aws
    def test_handler_continues_after_message_processing_error(self, mock_dynamodb, dlq_environment):
        """Should continue processing remaining messages after one fails."""
        messages = [
            {
                "MessageId": f"msg-{i}",
                "ReceiptHandle": f"receipt-{i}",
                "Body": json.dumps({"ecosystem": "npm", "name": f"package-{i}"}),
            }
            for i in range(3)
        ]

        with (
            patch("collectors.dlq_processor.sqs") as mock_sqs,
            patch("collectors.dlq_processor._process_dlq_message") as mock_process,
        ):
            mock_sqs.receive_message.side_effect = [
                {"Messages": messages},
                {"Messages": []},
            ]

            # First message raises exception, others succeed
            mock_process.side_effect = [
                Exception("Processing error"),
                "requeued",
                "requeued",
            ]

            result = dlq_environment.handler({}, None)

            # First message failed (exception), only last 2 counted as processed
            assert result["processed"] == 2
            assert result["requeued"] == 2
            # Verify all 3 were attempted
            assert mock_process.call_count == 3


# =============================================================================
# MESSAGE PROCESSING TESTS
# =============================================================================


class TestProcessDLQMessage:
    """Tests for _process_dlq_message function."""

    @mock_aws
    def test_requeues_message_with_incremented_retry_count(self, mock_dynamodb, dlq_environment, sample_sqs_message):
        """Should requeue message with retry count incremented."""
        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            from collectors.dlq_processor import _process_dlq_message

            result = _process_dlq_message(sample_sqs_message)

            assert result == "requeued"

            # Verify message was requeued with updated retry count
            mock_sqs.send_message.assert_called_once()
            send_call = mock_sqs.send_message.call_args
            body = json.loads(send_call.kwargs["MessageBody"])
            assert body["_retry_count"] == 1
            assert body["ecosystem"] == "npm"
            assert body["name"] == "test-package"

    @mock_aws
    def test_applies_exponential_backoff_delay(self, mock_dynamodb, dlq_environment, sample_sqs_message_with_retry):
        """Should apply exponential backoff delay based on retry count."""
        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            from collectors.dlq_processor import _process_dlq_message

            _process_dlq_message(sample_sqs_message_with_retry)

            send_call = mock_sqs.send_message.call_args
            # Retry count 2 -> delay should be 60 * 2^2 = 240 seconds
            assert send_call.kwargs["DelaySeconds"] == 240

    @mock_aws
    def test_caps_delay_at_15_minutes(self, mock_dynamodb, dlq_environment):
        """Should cap exponential backoff at 900 seconds (15 minutes)."""
        message = {
            "MessageId": "msg-high-retry",
            "ReceiptHandle": "receipt-high",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "test",
                    "_retry_count": 4,  # Retry count below max, will be requeued
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            from collectors.dlq_processor import _process_dlq_message

            _process_dlq_message(message)

            send_call = mock_sqs.send_message.call_args
            # 60 * 2^4 = 960, should be capped at 900 seconds
            assert send_call.kwargs["DelaySeconds"] == 900

    @mock_aws
    def test_stores_permanent_failure_after_max_retries(self, mock_dynamodb, dlq_environment):
        """Should store message as permanent failure after max retries."""
        message = {
            "MessageId": "msg-max-retry",
            "ReceiptHandle": "receipt-max",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "permanently-failing",
                    "_retry_count": 5,  # At max
                    "_last_error": "Persistent 404 error",
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            from collectors.dlq_processor import _process_dlq_message

            result = _process_dlq_message(message)

            assert result == "permanently_failed"

            # Verify message was NOT requeued
            mock_sqs.send_message.assert_not_called()

            # Verify message was deleted from DLQ
            mock_sqs.delete_message.assert_called_once()

            # Verify permanent failure was stored in DynamoDB
            table = mock_dynamodb.Table("pkgwatch-packages")
            response = table.scan()
            items = response["Items"]

            assert len(items) == 1
            failed_item = items[0]
            assert failed_item["pk"].startswith("FAILED#")
            assert failed_item["ecosystem"] == "npm"
            assert failed_item["name"] == "permanently-failing"
            assert failed_item["failure_reason"] == "Persistent 404 error"
            assert failed_item["retry_count"] == 5

    @mock_aws
    def test_deletes_message_after_successful_requeue(self, mock_dynamodb, dlq_environment, sample_sqs_message):
        """Should delete message from DLQ after successful requeue."""
        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            _process_dlq_message = dlq_environment._process_dlq_message

            _process_dlq_message(sample_sqs_message)

            # Verify delete was called with correct parameters
            mock_sqs.delete_message.assert_called_once()
            delete_call = mock_sqs.delete_message.call_args
            assert delete_call.kwargs["QueueUrl"] == "https://sqs.us-east-1.amazonaws.com/123456789012/test-dlq"
            assert delete_call.kwargs["ReceiptHandle"] == "receipt-handle-abc123"

    @mock_aws
    def test_handles_invalid_json_in_message_body(self, mock_dynamodb, dlq_environment):
        """Should handle messages with invalid JSON gracefully."""
        invalid_message = {
            "MessageId": "msg-invalid",
            "ReceiptHandle": "receipt-invalid",
            "Body": "not valid json {{{",
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            from collectors.dlq_processor import _process_dlq_message

            result = _process_dlq_message(invalid_message)

            assert result == "skipped"

            # Invalid message should be deleted
            mock_sqs.delete_message.assert_called_once()

    @mock_aws
    def test_does_not_delete_on_requeue_failure(self, mock_dynamodb, dlq_environment, sample_sqs_message):
        """Should not delete message from DLQ if requeue fails."""
        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            # Make send_message fail
            mock_sqs.send_message.side_effect = Exception("SQS unavailable")

            from collectors.dlq_processor import _process_dlq_message

            result = _process_dlq_message(sample_sqs_message)

            assert result == "skipped"

            # Should NOT delete message when requeue fails
            mock_sqs.delete_message.assert_not_called()


# =============================================================================
# EXPONENTIAL BACKOFF TESTS
# =============================================================================


class TestExponentialBackoff:
    """Tests for exponential backoff delay calculation."""

    def test_delay_calculation_for_first_retry(self, dlq_environment):
        """First retry should have 60 second delay."""
        from collectors.dlq_processor import _process_dlq_message

        message = {
            "MessageId": "msg-1",
            "ReceiptHandle": "receipt-1",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "test",
                    "_retry_count": 0,
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            _process_dlq_message(message)

            send_call = mock_sqs.send_message.call_args
            # 60 * 2^0 = 60
            assert send_call.kwargs["DelaySeconds"] == 60

    def test_delay_calculation_for_second_retry(self, dlq_environment):
        """Second retry should have 120 second delay."""
        message = {
            "MessageId": "msg-2",
            "ReceiptHandle": "receipt-2",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "test",
                    "_retry_count": 1,
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            from collectors.dlq_processor import _process_dlq_message

            _process_dlq_message(message)

            send_call = mock_sqs.send_message.call_args
            # 60 * 2^1 = 120
            assert send_call.kwargs["DelaySeconds"] == 120

    def test_delay_calculation_for_third_retry(self, dlq_environment):
        """Third retry should have 240 second delay."""
        message = {
            "MessageId": "msg-3",
            "ReceiptHandle": "receipt-3",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "test",
                    "_retry_count": 2,
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            from collectors.dlq_processor import _process_dlq_message

            _process_dlq_message(message)

            send_call = mock_sqs.send_message.call_args
            # 60 * 2^2 = 240
            assert send_call.kwargs["DelaySeconds"] == 240

    def test_delay_calculation_for_fourth_retry(self, dlq_environment):
        """Fourth retry should have 480 second delay."""
        message = {
            "MessageId": "msg-4",
            "ReceiptHandle": "receipt-4",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "test",
                    "_retry_count": 3,
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            from collectors.dlq_processor import _process_dlq_message

            _process_dlq_message(message)

            send_call = mock_sqs.send_message.call_args
            # 60 * 2^3 = 480
            assert send_call.kwargs["DelaySeconds"] == 480

    def test_delay_calculation_caps_at_900_seconds(self, dlq_environment):
        """Delay should be capped at 900 seconds (15 minutes)."""
        message = {
            "MessageId": "msg-5",
            "ReceiptHandle": "receipt-5",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "test",
                    "_retry_count": 4,
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            from collectors.dlq_processor import _process_dlq_message

            _process_dlq_message(message)

            send_call = mock_sqs.send_message.call_args
            # 60 * 2^4 = 960, but capped at 900
            assert send_call.kwargs["DelaySeconds"] == 900


# =============================================================================
# PERMANENT FAILURE STORAGE TESTS
# =============================================================================


class TestPermanentFailureStorage:
    """Tests for storing permanently failed messages."""

    @mock_aws
    def test_stores_failure_with_all_metadata(self, mock_dynamodb, dlq_environment):
        """Should store all relevant metadata for permanent failures."""
        from collectors.dlq_processor import _store_permanent_failure

        body = {
            "ecosystem": "npm",
            "name": "failed-package",
            "tier": 1,
            "_retry_count": 5,
        }

        _store_permanent_failure(body, "msg-123", "Persistent connection error")

        table = mock_dynamodb.Table("pkgwatch-packages")
        response = table.scan()
        items = response["Items"]

        assert len(items) == 1
        failed_item = items[0]
        assert failed_item["pk"] == "FAILED#msg-123"
        assert "sk" in failed_item  # Timestamp
        assert failed_item["ecosystem"] == "npm"
        assert failed_item["name"] == "failed-package"
        assert failed_item["body"] == body
        assert failed_item["failure_reason"] == "Persistent connection error"
        assert failed_item["retry_count"] == 5
        assert "failed_at" in failed_item

    @mock_aws
    def test_handles_missing_ecosystem_gracefully(self, mock_dynamodb, dlq_environment):
        """Should handle messages without ecosystem field."""
        from collectors.dlq_processor import _store_permanent_failure

        body = {
            "name": "package-without-ecosystem",
            "_retry_count": 5,
        }

        _store_permanent_failure(body, "msg-456", "Unknown error")

        table = mock_dynamodb.Table("pkgwatch-packages")
        response = table.scan()
        items = response["Items"]

        assert len(items) == 1
        assert items[0]["ecosystem"] == "unknown"

    @mock_aws
    def test_handles_missing_name_gracefully(self, mock_dynamodb, dlq_environment):
        """Should handle messages without name field."""
        from collectors.dlq_processor import _store_permanent_failure

        body = {
            "ecosystem": "npm",
            "_retry_count": 5,
        }

        _store_permanent_failure(body, "msg-789", "Unknown error")

        table = mock_dynamodb.Table("pkgwatch-packages")
        response = table.scan()
        items = response["Items"]

        assert len(items) == 1
        assert items[0]["name"] == "unknown"

    @mock_aws
    def test_handles_dynamodb_errors_gracefully(self, mock_dynamodb, dlq_environment):
        """Should not raise exception if DynamoDB storage fails."""
        with patch("collectors.dlq_processor.dynamodb") as mock_db:
            mock_table = MagicMock()
            mock_table.put_item.side_effect = Exception("DynamoDB unavailable")
            mock_db.Table.return_value = mock_table

            from collectors.dlq_processor import _store_permanent_failure

            # Should not raise exception
            _store_permanent_failure({"ecosystem": "npm", "name": "test"}, "msg-error", "Test error")


# =============================================================================
# EDGE CASES AND ERROR HANDLING
# =============================================================================


class TestEdgeCasesAndErrorHandling:
    """Tests for edge cases and error handling scenarios."""

    @mock_aws
    def test_handles_message_without_receipt_handle(self, mock_dynamodb, dlq_environment):
        """Should handle messages without ReceiptHandle field."""
        invalid_message = {
            "MessageId": "msg-no-handle",
            "Body": json.dumps({"ecosystem": "npm", "name": "test"}),
            # Missing ReceiptHandle
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            from collectors.dlq_processor import _process_dlq_message

            # Should not crash
            _result = _process_dlq_message(invalid_message)

            # Should still attempt to requeue
            assert mock_sqs.send_message.called

    @mock_aws
    def test_preserves_original_message_fields(self, mock_dynamodb, dlq_environment):
        """Should preserve all original message fields when requeuing."""
        message = {
            "MessageId": "msg-preserve",
            "ReceiptHandle": "receipt-preserve",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "test-package",
                    "tier": 2,
                    "custom_field": "custom_value",
                    "nested": {"key": "value"},
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            from collectors.dlq_processor import _process_dlq_message

            _process_dlq_message(message)

            send_call = mock_sqs.send_message.call_args
            body = json.loads(send_call.kwargs["MessageBody"])

            # All original fields should be preserved
            assert body["ecosystem"] == "npm"
            assert body["name"] == "test-package"
            assert body["tier"] == 2
            assert body["custom_field"] == "custom_value"
            assert body["nested"] == {"key": "value"}
            # Plus the retry count
            assert body["_retry_count"] == 1

    @mock_aws
    def test_handles_concurrent_processing_gracefully(self, mock_dynamodb, dlq_environment):
        """Should handle concurrent processing attempts."""
        message = {
            "MessageId": "msg-concurrent",
            "ReceiptHandle": "receipt-concurrent",
            "Body": json.dumps({"ecosystem": "npm", "name": "test"}),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            # Simulate message already deleted by another processor
            mock_sqs.delete_message.side_effect = Exception("Message not found")

            from collectors.dlq_processor import _process_dlq_message

            # Should not raise exception
            _process_dlq_message(message)

    @mock_aws
    def test_logs_useful_information_for_debugging(self, mock_dynamodb, dlq_environment, sample_sqs_message):
        """Should log useful information for debugging."""
        with patch("collectors.dlq_processor.sqs"), patch("collectors.dlq_processor.logger") as mock_logger:
            from collectors.dlq_processor import _process_dlq_message

            _process_dlq_message(sample_sqs_message)

            # Should log requeue information
            assert mock_logger.info.called
            log_message = mock_logger.info.call_args[0][0]
            assert "Requeued" in log_message
            assert "msg-12345" in log_message
