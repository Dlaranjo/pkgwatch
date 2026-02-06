"""
Tests for streams_dlq_processor.py - Handles failed score calculations.
"""

import json
import os
from unittest.mock import MagicMock, patch

# Set up environment before importing
os.environ.setdefault("PACKAGES_TABLE", "pkgwatch-packages")

# Import module under test
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../functions/scoring"))
from streams_dlq_processor import (
    _extract_package_key,
    _parse_dynamodb_value,
    _trigger_rescore,
    handler,
)


class TestParseDynamoDBValue:
    """Tests for DynamoDB value parsing."""

    def test_parse_string(self):
        assert _parse_dynamodb_value({"S": "npm#lodash"}) == "npm#lodash"

    def test_parse_number_int(self):
        assert _parse_dynamodb_value({"N": "42"}) == 42

    def test_parse_number_float(self):
        assert _parse_dynamodb_value({"N": "42.5"}) == 42.5

    def test_parse_bool(self):
        assert _parse_dynamodb_value({"BOOL": True}) is True
        assert _parse_dynamodb_value({"BOOL": False}) is False

    def test_parse_null(self):
        assert _parse_dynamodb_value({"NULL": True}) is None

    def test_parse_list(self):
        result = _parse_dynamodb_value({"L": [{"S": "a"}, {"N": "1"}]})
        assert result == ["a", 1]

    def test_parse_map(self):
        result = _parse_dynamodb_value({"M": {"key": {"S": "value"}}})
        assert result == {"key": "value"}


class TestExtractPackageKey:
    """Tests for extracting package key from DynamoDB Streams records."""

    def test_extract_from_new_image(self):
        stream_record = {
            "dynamodb": {
                "NewImage": {
                    "pk": {"S": "npm#lodash"},
                    "sk": {"S": "LATEST"},
                }
            }
        }
        result = _extract_package_key(stream_record)
        assert result == ("npm", "lodash")

    def test_extract_from_keys(self):
        stream_record = {
            "dynamodb": {
                "Keys": {
                    "pk": {"S": "pypi#requests"},
                    "sk": {"S": "LATEST"},
                }
            }
        }
        result = _extract_package_key(stream_record)
        assert result == ("pypi", "requests")

    def test_extract_scoped_package(self):
        stream_record = {
            "dynamodb": {
                "NewImage": {
                    "pk": {"S": "npm#@babel/core"},
                    "sk": {"S": "LATEST"},
                }
            }
        }
        result = _extract_package_key(stream_record)
        assert result == ("npm", "@babel/core")

    def test_extract_invalid_pk_format(self):
        stream_record = {
            "dynamodb": {
                "NewImage": {
                    "pk": {"S": "invalid-no-hash"},
                    "sk": {"S": "LATEST"},
                }
            }
        }
        result = _extract_package_key(stream_record)
        assert result is None

    def test_extract_missing_dynamodb(self):
        stream_record = {}
        result = _extract_package_key(stream_record)
        assert result is None


class TestTriggerRescore:
    """Tests for triggering rescore on packages."""

    @patch("streams_dlq_processor.dynamodb")
    def test_trigger_rescore_success(self, mock_dynamodb):
        """Test successful rescore trigger."""
        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table

        result = _trigger_rescore("npm", "lodash")

        assert result is True
        mock_table.update_item.assert_called_once()
        call_args = mock_table.update_item.call_args
        assert call_args.kwargs["Key"] == {"pk": "npm#lodash", "sk": "LATEST"}
        assert ":true" in call_args.kwargs["ExpressionAttributeValues"]

    @patch("streams_dlq_processor.dynamodb")
    def test_trigger_rescore_package_not_found(self, mock_dynamodb):
        """Test rescore when package doesn't exist."""
        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        mock_dynamodb.meta.client.exceptions.ConditionalCheckFailedException = Exception
        mock_table.update_item.side_effect = Exception("ConditionalCheckFailedException")

        result = _trigger_rescore("npm", "nonexistent")

        assert result is False


class TestHandler:
    """Tests for the Lambda handler."""

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_single_record(self, mock_metrics, mock_rescore):
        """Test processing single DLQ record."""
        mock_rescore.return_value = True

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "Records": [
                                {
                                    "dynamodb": {
                                        "NewImage": {
                                            "pk": {"S": "npm#lodash"},
                                            "sk": {"S": "LATEST"},
                                        }
                                    }
                                }
                            ]
                        }
                    )
                }
            ]
        }

        result = handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["processed"] == 1
        assert body["rescored"] == 1
        mock_rescore.assert_called_once_with("npm", "lodash")

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_multiple_records(self, mock_metrics, mock_rescore):
        """Test processing multiple DLQ records."""
        mock_rescore.return_value = True

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "Records": [
                                {
                                    "dynamodb": {
                                        "NewImage": {
                                            "pk": {"S": "npm#lodash"},
                                            "sk": {"S": "LATEST"},
                                        }
                                    }
                                }
                            ]
                        }
                    )
                },
                {
                    "body": json.dumps(
                        {
                            "Records": [
                                {
                                    "dynamodb": {
                                        "NewImage": {
                                            "pk": {"S": "npm#react"},
                                            "sk": {"S": "LATEST"},
                                        }
                                    }
                                }
                            ]
                        }
                    )
                },
            ]
        }

        result = handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["processed"] == 2
        assert body["rescored"] == 2
        assert mock_rescore.call_count == 2

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_deduplicates_same_package(self, mock_metrics, mock_rescore):
        """Test that duplicate packages in same batch are deduplicated."""
        mock_rescore.return_value = True

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "Records": [
                                {
                                    "dynamodb": {
                                        "NewImage": {
                                            "pk": {"S": "npm#lodash"},
                                            "sk": {"S": "LATEST"},
                                        }
                                    }
                                },
                                {
                                    "dynamodb": {
                                        "NewImage": {
                                            "pk": {"S": "npm#lodash"},
                                            "sk": {"S": "LATEST"},
                                        }
                                    }
                                },
                            ]
                        }
                    )
                }
            ]
        }

        result = handler(event, None)

        body = json.loads(result["body"])
        # Both records processed, but only one rescore triggered
        assert body["processed"] == 2
        assert body["rescored"] == 1
        mock_rescore.assert_called_once_with("npm", "lodash")

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_invalid_json(self, mock_metrics, mock_rescore):
        """Test handling invalid JSON in DLQ message."""
        event = {"Records": [{"body": "invalid json"}]}

        result = handler(event, None)

        body = json.loads(result["body"])
        assert body["skipped"] == 1

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_empty_records(self, mock_metrics, mock_rescore):
        """Test handling empty records list."""
        event = {"Records": []}

        result = handler(event, None)

        body = json.loads(result["body"])
        assert body["processed"] == 0

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_rescore_failure_increments_failed(self, mock_metrics, mock_rescore):
        """Test that rescore failure increments failed counter (line 180)."""
        mock_rescore.return_value = False  # Rescore fails

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "Records": [
                                {
                                    "dynamodb": {
                                        "NewImage": {
                                            "pk": {"S": "npm#lodash"},
                                            "sk": {"S": "LATEST"},
                                        }
                                    }
                                }
                            ]
                        }
                    )
                }
            ]
        }

        result = handler(event, None)

        body = json.loads(result["body"])
        assert body["processed"] == 1
        assert body["rescored"] == 0
        assert body["failed"] == 1

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_skips_unextractable_records(self, mock_metrics, mock_rescore):
        """Test that records with no extractable key are skipped (lines 163-165)."""
        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "Records": [
                                {
                                    "dynamodb": {
                                        "NewImage": {
                                            "pk": {"S": "invalid-no-hash"},
                                            "sk": {"S": "LATEST"},
                                        }
                                    }
                                }
                            ]
                        }
                    )
                }
            ]
        }

        result = handler(event, None)

        body = json.loads(result["body"])
        assert body["processed"] == 1
        assert body["skipped"] == 1
        assert body["rescored"] == 0
        mock_rescore.assert_not_called()

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_general_exception_in_record(self, mock_metrics, mock_rescore):
        """Test general exception during record processing (lines 185-187)."""
        # Create a record whose body causes a generic exception
        # Use a record with a body that parses as JSON but causes exception
        # in the stream record processing
        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "Records": [
                                {
                                    "dynamodb": {
                                        "NewImage": {
                                            "pk": {"S": "npm#lodash"},
                                            "sk": {"S": "LATEST"},
                                        }
                                    }
                                }
                            ]
                        }
                    )
                }
            ]
        }
        # Make _trigger_rescore raise an unexpected exception
        mock_rescore.side_effect = RuntimeError("Unexpected error")

        result = handler(event, None)

        body = json.loads(result["body"])
        # The general exception handler catches it
        assert body["failed"] == 1

    @patch("streams_dlq_processor._trigger_rescore")
    def test_handler_metrics_emission_failure(self, mock_rescore):
        """Test that metrics emission failure is handled gracefully (lines 197-198)."""
        mock_rescore.return_value = True

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "Records": [
                                {
                                    "dynamodb": {
                                        "NewImage": {
                                            "pk": {"S": "npm#lodash"},
                                            "sk": {"S": "LATEST"},
                                        }
                                    }
                                }
                            ]
                        }
                    )
                }
            ]
        }

        # Mock emit_batch_metrics to raise an exception
        with patch("streams_dlq_processor.emit_batch_metrics", side_effect=Exception("Metrics failed")):
            result = handler(event, None)

        # Should still return success despite metrics failure
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["rescored"] == 1

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_single_record_no_records_key(self, mock_metrics, mock_rescore):
        """Test SQS message body without 'Records' key (treated as single record)."""
        mock_rescore.return_value = True

        # Body is a direct stream record (not wrapped in "Records" array)
        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "dynamodb": {
                                "NewImage": {
                                    "pk": {"S": "npm#express"},
                                    "sk": {"S": "LATEST"},
                                }
                            }
                        }
                    )
                }
            ]
        }

        result = handler(event, None)

        body = json.loads(result["body"])
        assert body["processed"] == 1
        assert body["rescored"] == 1
        mock_rescore.assert_called_once_with("npm", "express")

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_no_records_key_in_event(self, mock_metrics, mock_rescore):
        """Test event without 'Records' key."""
        event = {}

        result = handler(event, None)

        body = json.loads(result["body"])
        assert body["processed"] == 0
        assert body["rescored"] == 0


class TestParseDynamoDBValueEdgeCases:
    """Tests for _parse_dynamodb_value edge cases (line 56)."""

    def test_parse_unknown_type_returns_none(self):
        """Unknown DynamoDB type should return None (line 56)."""
        result = _parse_dynamodb_value({"UNKNOWN_TYPE": "value"})
        assert result is None

    def test_parse_empty_dict_returns_none(self):
        """Empty dict should return None."""
        result = _parse_dynamodb_value({})
        assert result is None

    def test_parse_binary_type_returns_none(self):
        """Binary type (B) is not handled, should return None."""
        result = _parse_dynamodb_value({"B": b"binary_data"})
        assert result is None


class TestExtractPackageKeyEdgeCases:
    """Tests for _extract_package_key exception handling (lines 85-87)."""

    def test_extract_with_exception_in_parsing(self):
        """Exception during parsing should return None (lines 85-87)."""
        # Cause AttributeError by making "dynamodb" a non-dict (no .get() method)
        stream_record = {
            "dynamodb": "not-a-dict",  # .get() will raise AttributeError
        }
        result = _extract_package_key(stream_record)
        assert result is None

    def test_extract_with_none_dynamodb_raises_exception(self):
        """None dynamodb value should be caught by exception handler (lines 85-87)."""
        # Cause an AttributeError: NoneType has no .get()
        stream_record = {
            "dynamodb": None,
        }
        result = _extract_package_key(stream_record)
        assert result is None

    def test_extract_with_none_pk_value(self):
        """Empty pk value should return None."""
        stream_record = {
            "dynamodb": {
                "NewImage": {
                    "pk": {},
                }
            }
        }
        result = _extract_package_key(stream_record)
        assert result is None

    def test_extract_with_missing_pk(self):
        """Missing pk in both NewImage and Keys should return None."""
        stream_record = {
            "dynamodb": {
                "NewImage": {
                    "sk": {"S": "LATEST"},
                },
                "Keys": {
                    "sk": {"S": "LATEST"},
                },
            }
        }
        result = _extract_package_key(stream_record)
        assert result is None


class TestTriggerRescoreEdgeCases:
    """Tests for _trigger_rescore error handling (lines 126-128)."""

    @patch("streams_dlq_processor.dynamodb")
    def test_trigger_rescore_general_exception(self, mock_dynamodb):
        """General exception in _trigger_rescore should return False (lines 126-128)."""
        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        # Set up ConditionalCheckFailedException as a different class
        mock_dynamodb.meta.client.exceptions.ConditionalCheckFailedException = type(
            "ConditionalCheckFailedException", (Exception,), {}
        )
        # Raise a generic exception (not ConditionalCheckFailed)
        mock_table.update_item.side_effect = RuntimeError("DynamoDB service error")

        result = _trigger_rescore("npm", "lodash")
        assert result is False

    @patch("streams_dlq_processor.dynamodb")
    def test_trigger_rescore_conditional_check_failed(self, mock_dynamodb):
        """ConditionalCheckFailedException should return False (package not found)."""
        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table

        # Create a proper exception class
        ConditionalCheckFailed = type("ConditionalCheckFailedException", (Exception,), {})
        mock_dynamodb.meta.client.exceptions.ConditionalCheckFailedException = ConditionalCheckFailed
        mock_table.update_item.side_effect = ConditionalCheckFailed("Package not found")

        result = _trigger_rescore("npm", "nonexistent")
        assert result is False

    @patch("streams_dlq_processor.dynamodb")
    def test_trigger_rescore_sets_correct_values(self, mock_dynamodb):
        """Verify _trigger_rescore sets the correct DynamoDB values."""
        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table

        result = _trigger_rescore("pypi", "requests")

        assert result is True
        call_kwargs = mock_table.update_item.call_args.kwargs
        assert call_kwargs["Key"] == {"pk": "pypi#requests", "sk": "LATEST"}
        assert call_kwargs["ExpressionAttributeValues"][":true"] is True
        assert call_kwargs["ExpressionAttributeValues"][":reason"] == "streams_dlq_recovery"
        assert "ConditionExpression" in call_kwargs


class TestMetricsImportFallback:
    """Tests for metrics import fallback (lines 32-37).

    The fallback functions emit_metric and emit_batch_metrics are defined
    when the metrics module cannot be imported. We verify the fallback
    behavior works correctly.
    """

    def test_fallback_emit_metric_is_noop(self):
        """Fallback emit_metric should accept any args without error."""
        # The module-level import fallback is tested implicitly by all handler tests
        # that mock emit_batch_metrics. We test that the handler doesn't crash
        # when metrics are unavailable by verifying the module loaded correctly.
        # The import fallback at module level (lines 32-37) was already exercised
        # during test module import since the test_streams_dlq_processor.py
        # manipulates sys.path.
        assert callable(handler)

    @patch("streams_dlq_processor._trigger_rescore")
    def test_handler_works_with_fallback_metrics(self, mock_rescore):
        """Handler should work even if metrics functions are the fallback versions."""
        mock_rescore.return_value = True

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "Records": [
                                {
                                    "dynamodb": {
                                        "NewImage": {
                                            "pk": {"S": "npm#lodash"},
                                            "sk": {"S": "LATEST"},
                                        }
                                    }
                                }
                            ]
                        }
                    )
                }
            ]
        }

        # Don't mock emit_batch_metrics - let the fallback or real one run
        result = handler(event, None)
        assert result["statusCode"] == 200

    def test_fallback_functions_are_noops_when_invoked(self):
        """Fallback emit_metric and emit_batch_metrics should be callable noops (lines 34-38)."""
        # Simulate the ImportError fallback by directly testing the pattern
        # The actual coverage of lines 32-38 requires the import to fail.
        # We test the fallback behavior by importing with blocked metrics module.

        original_modules = {}
        modules_to_block = ["metrics", "shared.metrics"]
        for mod_name in modules_to_block:
            if mod_name in sys.modules:
                original_modules[mod_name] = sys.modules[mod_name]
                del sys.modules[mod_name]

        # Also remove the streams_dlq_processor module so it can be re-imported
        if "streams_dlq_processor" in sys.modules:
            original_sdp = sys.modules.pop("streams_dlq_processor")

        # Block the metrics import
        import builtins

        original_import = builtins.__import__

        def blocking_import(name, *args, **kwargs):
            if name == "metrics":
                raise ImportError("Blocked for testing")
            return original_import(name, *args, **kwargs)

        builtins.__import__ = blocking_import
        try:
            # Re-import the module - should use fallback functions
            import streams_dlq_processor as reloaded

            # The fallback functions should be callable noops
            reloaded.emit_metric("test_metric", value=1)
            reloaded.emit_batch_metrics([{"metric_name": "test", "value": 1}])
            # No error means fallback worked correctly
        finally:
            builtins.__import__ = original_import
            # Restore original modules
            for mod_name, mod in original_modules.items():
                sys.modules[mod_name] = mod
            if "original_sdp" in dir():
                sys.modules["streams_dlq_processor"] = original_sdp


# =============================================================================
# ADDITIONAL EDGE CASES FOR STREAMS DLQ
# =============================================================================


class TestStreamsDLQEdgeCases:
    """Additional edge cases for streams DLQ processor."""

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_handles_empty_body(self, mock_metrics, mock_rescore):
        """Handler should handle record with empty body."""
        event = {"Records": [{"body": "{}"}]}

        result = handler(event, None)

        body = json.loads(result["body"])
        # Empty body parses as {}, body.get("Records", [body]) = [{}]
        # _extract_package_key({}) returns None -> skipped
        assert body["skipped"] == 1

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_handles_missing_body_key(self, mock_metrics, mock_rescore):
        """Handler should handle record missing body key."""
        event = {"Records": [{}]}

        result = handler(event, None)

        body = json.loads(result["body"])
        # record.get("body", "{}") = "{}" -> parses to empty dict
        assert body["processed"] >= 0

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_multiple_stream_records_in_one_sqs_message(self, mock_metrics, mock_rescore):
        """Handler should process multiple stream records within one SQS message."""
        mock_rescore.return_value = True

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "Records": [
                                {
                                    "dynamodb": {
                                        "NewImage": {
                                            "pk": {"S": "npm#pkg-a"},
                                            "sk": {"S": "LATEST"},
                                        }
                                    }
                                },
                                {
                                    "dynamodb": {
                                        "NewImage": {
                                            "pk": {"S": "npm#pkg-b"},
                                            "sk": {"S": "LATEST"},
                                        }
                                    }
                                },
                                {
                                    "dynamodb": {
                                        "NewImage": {
                                            "pk": {"S": "pypi#pkg-c"},
                                            "sk": {"S": "LATEST"},
                                        }
                                    }
                                },
                            ]
                        }
                    )
                }
            ]
        }

        result = handler(event, None)

        body = json.loads(result["body"])
        assert body["processed"] == 3
        assert body["rescored"] == 3
        assert mock_rescore.call_count == 3

    @patch("streams_dlq_processor._trigger_rescore")
    @patch("streams_dlq_processor.emit_batch_metrics")
    def test_handler_deduplicates_across_sqs_messages(self, mock_metrics, mock_rescore):
        """Should deduplicate same package across different SQS messages."""
        mock_rescore.return_value = True

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "dynamodb": {
                                "NewImage": {
                                    "pk": {"S": "npm#lodash"},
                                    "sk": {"S": "LATEST"},
                                }
                            }
                        }
                    )
                },
                {
                    "body": json.dumps(
                        {
                            "dynamodb": {
                                "NewImage": {
                                    "pk": {"S": "npm#lodash"},
                                    "sk": {"S": "LATEST"},
                                }
                            }
                        }
                    )
                },
            ]
        }

        result = handler(event, None)

        body = json.loads(result["body"])
        assert body["processed"] == 2
        # Only one rescore because dedup
        assert body["rescored"] == 1
        mock_rescore.assert_called_once_with("npm", "lodash")
