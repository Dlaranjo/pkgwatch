"""
Tests for streams_dlq_processor.py - Handles failed score calculations.
"""

import json
import os
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

# Set up environment before importing
os.environ.setdefault("PACKAGES_TABLE", "pkgwatch-packages")

# Import module under test
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../functions/scoring"))
from streams_dlq_processor import (
    handler,
    _extract_package_key,
    _trigger_rescore,
    _parse_dynamodb_value,
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
                    "body": json.dumps({
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
                    })
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
                    "body": json.dumps({
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
                    })
                },
                {
                    "body": json.dumps({
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
                    })
                }
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
                    "body": json.dumps({
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
                            }
                        ]
                    })
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
        event = {
            "Records": [
                {"body": "invalid json"}
            ]
        }

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
