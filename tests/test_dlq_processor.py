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


# =============================================================================
# HANDLER TIMEOUT AND METRICS EDGE CASES
# =============================================================================


class TestHandlerTimeoutAndMetrics:
    """Tests for handler timeout guard and metrics emission failure."""

    @mock_aws
    def test_handler_stops_early_on_timeout(self, mock_dynamodb, dlq_environment):
        """Should stop processing when Lambda timeout approaches (lines 88-91)."""
        # Create a context mock that reports low remaining time
        mock_context = MagicMock()
        mock_context.aws_request_id = "test-req-id"
        mock_context.get_remaining_time_in_millis.return_value = 20000  # < 30000

        single_message = {
            "MessageId": "msg-timeout",
            "ReceiptHandle": "receipt-timeout",
            "Body": json.dumps({"ecosystem": "npm", "name": "test"}),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            # Return messages, but timeout should prevent processing
            mock_sqs.receive_message.return_value = {"Messages": [single_message]}

            result = dlq_environment.handler({}, mock_context)

            # Should stop before receiving any messages due to timeout
            assert result["processed"] == 0
            # receive_message should not have been called
            mock_sqs.receive_message.assert_not_called()

    @mock_aws
    def test_handler_stops_mid_batch_on_timeout(self, mock_dynamodb, dlq_environment):
        """Should stop between batches when timeout approaches."""
        mock_context = MagicMock()
        mock_context.aws_request_id = "test-req-id"
        # First check has enough time, second does not
        mock_context.get_remaining_time_in_millis.side_effect = [60000, 20000]

        messages = [
            {
                "MessageId": "msg-1",
                "ReceiptHandle": "receipt-1",
                "Body": json.dumps({"ecosystem": "npm", "name": "test-1"}),
            }
        ]

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            mock_sqs.receive_message.side_effect = [
                {"Messages": messages},
                {"Messages": messages},  # Won't be reached
            ]

            result = dlq_environment.handler({}, mock_context)

            # Should only process first batch
            assert result["processed"] == 1
            assert mock_sqs.receive_message.call_count == 1

    @mock_aws
    def test_handler_metrics_emission_failure_is_silent(self, mock_dynamodb, dlq_environment):
        """Metrics emission failure should not crash the handler (lines 135-136)."""
        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            mock_sqs.receive_message.return_value = {"Messages": []}

            with patch("collectors.dlq_processor.emit_batch_metrics", side_effect=Exception("CloudWatch down")):
                result = dlq_environment.handler({}, None)

            # Handler should complete successfully despite metrics failure
            assert "processed" in result
            assert result["processed"] == 0


# =============================================================================
# DLQ MESSAGE PROCESSING - ERROR INFO LOOKUP AND DELETE FAILURES
# =============================================================================


class TestDLQMessageErrorInfoLookup:
    """Tests for error info lookup from package records and delete failures."""

    @mock_aws
    def test_fetches_error_info_from_package_record(self, mock_dynamodb, dlq_environment):
        """Should fetch error info from DynamoDB when message has no _last_error (line 197-200)."""
        # Seed the packages table with error info
        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#pkg-with-error",
                "sk": "LATEST",
                "collection_error": "HTTP 503: Service Unavailable",
                "collection_error_class": "transient",
            }
        )

        message = {
            "MessageId": "msg-lookup-error",
            "ReceiptHandle": "receipt-lookup",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "pkg-with-error",
                    # No _last_error or _error_class
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            result = dlq_environment._process_dlq_message(message)

            # Should be requeued since the stored error is transient
            assert result == "requeued"
            mock_sqs.send_message.assert_called_once()

    @mock_aws
    def test_uses_stored_error_class_from_package_record(self, mock_dynamodb, dlq_environment):
        """Should use stored error_class from package record (line 199-200)."""
        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#permanent-fail-pkg",
                "sk": "LATEST",
                "collection_error": "HTTP 404: Not Found",
                "collection_error_class": "permanent",
            }
        )

        message = {
            "MessageId": "msg-stored-class",
            "ReceiptHandle": "receipt-stored",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "permanent-fail-pkg",
                    "_last_error": "unknown",  # Triggers lookup
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            result = dlq_environment._process_dlq_message(message)

            # Should be permanently failed because stored class is "permanent"
            assert result == "permanently_failed"
            mock_sqs.send_message.assert_not_called()

    @mock_aws
    def test_sets_last_error_to_unknown_when_empty_after_fetch(self, mock_dynamodb, dlq_environment):
        """Should set last_error to 'unknown' when fetch returns empty (line 205-206)."""
        # Package record exists but with no error info
        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#no-error-info",
                "sk": "LATEST",
                # No collection_error or collection_error_class
            }
        )

        message = {
            "MessageId": "msg-no-error",
            "ReceiptHandle": "receipt-no-error",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "no-error-info",
                    # No _last_error
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs"):
            result = dlq_environment._process_dlq_message(message)

            # Should still requeue (unknown errors are retried)
            assert result == "requeued"

    @mock_aws
    def test_delete_failure_after_permanent_fail_still_emits_metric(self, mock_dynamodb, dlq_environment):
        """Failed delete of permanently failed message should still emit metric (lines 225-226)."""
        message = {
            "MessageId": "msg-delete-fail",
            "ReceiptHandle": "receipt-delete-fail",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "perm-fail-pkg",
                    "_retry_count": 5,
                    "_last_error": "HTTP 404: Not Found",
                }
            ),
        }

        with (
            patch("collectors.dlq_processor.sqs") as mock_sqs,
            patch("collectors.dlq_processor.emit_dlq_metric") as mock_emit_dlq,
        ):
            # Make delete fail
            mock_sqs.delete_message.side_effect = Exception("SQS delete failed")

            result = dlq_environment._process_dlq_message(message)

            assert result == "permanently_failed"
            # Metric should still be emitted even when delete fails
            mock_emit_dlq.assert_called_with("permanent_failure", "perm-fail-pkg")

    @mock_aws
    def test_delete_invalid_message_failure(self, mock_dynamodb, dlq_environment):
        """Failed delete of invalid (unparseable) message should log warning (line 185)."""
        invalid_message = {
            "MessageId": "msg-invalid-delete-fail",
            "ReceiptHandle": "receipt-invalid-delete-fail",
            "Body": "not valid json {{",
        }

        with (
            patch("collectors.dlq_processor.sqs") as mock_sqs,
            patch("collectors.dlq_processor.logger") as mock_logger,
        ):
            mock_sqs.delete_message.side_effect = Exception("Delete failed")

            result = dlq_environment._process_dlq_message(invalid_message)

            assert result == "skipped"
            # Should log warning about failed delete of invalid message
            warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
            assert any("Failed to delete invalid message" in str(c) for c in warning_calls)


# =============================================================================
# SHOULD_RETRY FUNCTION TESTS
# =============================================================================


class TestShouldRetry:
    """Tests for the should_retry helper function."""

    def test_permanent_error_not_retried(self, dlq_environment):
        """Permanent errors should not be retried."""
        body = {
            "_retry_count": 0,
            "_last_error": "404 Not Found",
            "_error_class": "permanent",
        }
        assert dlq_environment.should_retry(body) is False

    def test_max_retries_not_retried(self, dlq_environment):
        """Messages at max retries should not be retried."""
        body = {
            "_retry_count": 5,
            "_last_error": "timeout",
            "_error_class": "transient",
        }
        assert dlq_environment.should_retry(body) is False

    def test_transient_error_below_max_retried(self, dlq_environment):
        """Transient errors below max retries should be retried."""
        body = {
            "_retry_count": 2,
            "_last_error": "timeout",
            "_error_class": "transient",
        }
        assert dlq_environment.should_retry(body) is True

    def test_unknown_error_below_max_retried(self, dlq_environment):
        """Unknown errors below max retries should be retried."""
        body = {
            "_retry_count": 3,
            "_last_error": "weird error",
            "_error_class": "unknown",
        }
        assert dlq_environment.should_retry(body) is True

    def test_missing_fields_defaults(self, dlq_environment):
        """Should handle missing fields with sensible defaults."""
        body = {}  # No retry_count, no error, no class
        assert dlq_environment.should_retry(body) is True

    def test_exactly_at_max_retries_not_retried(self, dlq_environment):
        """Exactly at MAX_DLQ_RETRIES should not be retried."""
        body = {"_retry_count": 5}  # MAX_DLQ_RETRIES = 5
        assert dlq_environment.should_retry(body) is False

    def test_one_below_max_retries_retried(self, dlq_environment):
        """One below MAX_DLQ_RETRIES should still be retried."""
        body = {"_retry_count": 4}
        assert dlq_environment.should_retry(body) is True


# =============================================================================
# DELETE DLQ MESSAGE WITH RETRIES
# =============================================================================


class TestDeleteDLQMessage:
    """Tests for _delete_dlq_message with internal retry logic."""

    @mock_aws
    def test_delete_succeeds_on_first_attempt(self, mock_dynamodb, dlq_environment):
        """Should return True when delete succeeds on first attempt."""
        message = {"ReceiptHandle": "test-receipt"}

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            result = dlq_environment._delete_dlq_message(message)
            assert result is True
            assert mock_sqs.delete_message.call_count == 1

    @mock_aws
    def test_delete_retries_on_failure(self, mock_dynamodb, dlq_environment):
        """Should retry delete on failure and succeed eventually."""
        message = {"ReceiptHandle": "test-receipt"}

        with patch("collectors.dlq_processor.sqs") as mock_sqs, patch("time.sleep"):
            # Fail first, succeed second
            mock_sqs.delete_message.side_effect = [
                Exception("Temporary SQS error"),
                None,  # Success
            ]

            result = dlq_environment._delete_dlq_message(message)
            assert result is True
            assert mock_sqs.delete_message.call_count == 2

    @mock_aws
    def test_delete_returns_false_after_all_retries_exhausted(self, mock_dynamodb, dlq_environment):
        """Should return False after all retry attempts fail (covers line 289 fallback)."""
        message = {"ReceiptHandle": "test-receipt"}

        with patch("collectors.dlq_processor.sqs") as mock_sqs, patch("time.sleep"):
            mock_sqs.delete_message.side_effect = Exception("Persistent SQS error")

            result = dlq_environment._delete_dlq_message(message, max_retries=3)
            assert result is False
            assert mock_sqs.delete_message.call_count == 3


# =============================================================================
# GET PACKAGE ERROR INFO TESTS
# =============================================================================


class TestGetPackageErrorInfo:
    """Tests for _get_package_error_info function."""

    @mock_aws
    def test_returns_error_info_from_package_record(self, mock_dynamodb, dlq_environment):
        """Should return error info from DynamoDB package record."""
        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "LATEST",
                "collection_error": "HTTP 503",
                "collection_error_class": "transient",
            }
        )

        error_msg, error_class = dlq_environment._get_package_error_info("npm", "test-pkg")
        assert error_msg == "HTTP 503"
        assert error_class == "transient"

    @mock_aws
    def test_returns_unknown_when_no_error_fields(self, mock_dynamodb, dlq_environment):
        """Should return 'unknown' when package has no error fields."""
        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#clean-pkg",
                "sk": "LATEST",
            }
        )

        error_msg, error_class = dlq_environment._get_package_error_info("npm", "clean-pkg")
        assert error_msg == "unknown"
        assert error_class == "unknown"

    @mock_aws
    def test_returns_unknown_when_package_not_found(self, mock_dynamodb, dlq_environment):
        """Should return 'unknown' when package doesn't exist."""
        error_msg, error_class = dlq_environment._get_package_error_info("npm", "nonexistent-pkg")
        assert error_msg == "unknown"
        assert error_class == "unknown"

    @mock_aws
    def test_handles_dynamodb_error_gracefully(self, mock_dynamodb, dlq_environment):
        """Should return 'unknown' when DynamoDB throws error."""
        with patch("collectors.dlq_processor.dynamodb") as mock_db:
            mock_table = MagicMock()
            mock_table.get_item.side_effect = Exception("DynamoDB unavailable")
            mock_db.Table.return_value = mock_table

            error_msg, error_class = dlq_environment._get_package_error_info("npm", "test")
            assert error_msg == "unknown"
            assert error_class == "unknown"


# =============================================================================
# MALFORMED AND HUGE PAYLOAD EDGE CASES
# =============================================================================


class TestMalformedAndHugePayloads:
    """Tests for malformed messages and unusually large payloads."""

    @mock_aws
    def test_message_with_empty_body_key(self, mock_dynamodb, dlq_environment):
        """Message with empty Body string should be skipped."""
        message = {
            "MessageId": "msg-empty-body",
            "ReceiptHandle": "receipt-empty",
            "Body": "",
        }

        with patch("collectors.dlq_processor.sqs"):
            result = dlq_environment._process_dlq_message(message)
            assert result == "skipped"

    @mock_aws
    def test_message_missing_body_key(self, mock_dynamodb, dlq_environment):
        """Message completely missing Body key should be skipped."""
        message = {
            "MessageId": "msg-no-body",
            "ReceiptHandle": "receipt-no-body",
            # No Body key at all
        }

        with patch("collectors.dlq_processor.sqs"):
            result = dlq_environment._process_dlq_message(message)
            assert result == "skipped"

    @mock_aws
    def test_huge_payload_still_processed(self, mock_dynamodb, dlq_environment):
        """Large message payloads should still be processed correctly."""
        large_body = {
            "ecosystem": "npm",
            "name": "big-pkg",
            "extra_data": "x" * 100000,  # 100KB of extra data
        }

        message = {
            "MessageId": "msg-huge",
            "ReceiptHandle": "receipt-huge",
            "Body": json.dumps(large_body),
        }

        with patch("collectors.dlq_processor.sqs"):
            result = dlq_environment._process_dlq_message(message)
            assert result == "requeued"

    @mock_aws
    def test_message_with_float_retry_count(self, mock_dynamodb, dlq_environment):
        """Retry count stored as float should be converted to int via int()."""
        message = {
            "MessageId": "msg-float-retry",
            "ReceiptHandle": "receipt-float",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "test",
                    "_retry_count": 3.7,  # Float instead of int
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            result = dlq_environment._process_dlq_message(message)
            assert result == "requeued"
            body = json.loads(mock_sqs.send_message.call_args.kwargs["MessageBody"])
            assert body["_retry_count"] == 4  # int(3.7) + 1 = 4

    @mock_aws
    def test_permanent_error_skips_retry_directly(self, mock_dynamodb, dlq_environment):
        """Message with permanent error class should skip retry immediately."""
        message = {
            "MessageId": "msg-perm",
            "ReceiptHandle": "receipt-perm",
            "Body": json.dumps(
                {
                    "ecosystem": "npm",
                    "name": "gone-pkg",
                    "_retry_count": 0,
                    "_last_error": "HTTP 404: Package not found",
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs") as mock_sqs:
            result = dlq_environment._process_dlq_message(message)

            # Permanent error should not be requeued even with 0 retries
            assert result == "permanently_failed"
            mock_sqs.send_message.assert_not_called()

    @mock_aws
    def test_message_without_ecosystem_or_name_still_requeues(self, mock_dynamodb, dlq_environment):
        """Message without ecosystem/name fields should still be requeued."""
        message = {
            "MessageId": "msg-no-pkg-info",
            "ReceiptHandle": "receipt-no-pkg",
            "Body": json.dumps(
                {
                    "some_other_field": "value",
                }
            ),
        }

        with patch("collectors.dlq_processor.sqs"):
            result = dlq_environment._process_dlq_message(message)
            # No ecosystem/name means no lookup, error is unknown, retries < max -> requeue
            assert result == "requeued"
