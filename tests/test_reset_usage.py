"""
Tests for monthly usage reset Lambda.
"""

import hashlib
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from moto import mock_aws


class TestResetUsageHandler:
    """Tests for the reset_usage Lambda handler."""

    @mock_aws
    def test_resets_all_user_counters(self, mock_dynamodb):
        """Should reset requests_this_month for all users."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

        # Create users with usage
        for i in range(3):
            key_hash = hashlib.sha256(f"dh_user{i}".encode()).hexdigest()
            table.put_item(
                Item={
                    "pk": f"user_{i}",
                    "sk": key_hash,
                    "key_hash": key_hash,
                    "email": f"user{i}@example.com",
                    "tier": "free",
                    "requests_this_month": 1000 + i * 100,
                    "email_verified": True,
                }
            )

        from api.reset_usage import handler

        # Mock context
        context = MagicMock()
        context.get_remaining_time_in_millis.return_value = 300000  # 5 minutes
        context.function_name = "test-reset-function"

        result = handler({}, context)

        assert result["statusCode"] == 200
        assert result["items_processed"] == 3
        assert result["completed"] is True

        # Verify all users were reset
        for i in range(3):
            key_hash = hashlib.sha256(f"dh_user{i}".encode()).hexdigest()
            response = table.get_item(Key={"pk": f"user_{i}", "sk": key_hash})
            item = response.get("Item")
            assert item["requests_this_month"] == 0

    @mock_aws
    def test_skips_pending_records(self, mock_dynamodb):
        """Should not reset PENDING signup records."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

        # Create PENDING record
        table.put_item(
            Item={
                "pk": "user_pending",
                "sk": "PENDING",
                "email": "pending@example.com",
                "verification_token": "token123",
            }
        )

        # Create verified user
        key_hash = hashlib.sha256(b"dh_verified").hexdigest()
        table.put_item(
            Item={
                "pk": "user_verified",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "verified@example.com",
                "tier": "free",
                "requests_this_month": 500,
                "email_verified": True,
            }
        )

        from api.reset_usage import handler

        context = MagicMock()
        context.get_remaining_time_in_millis.return_value = 300000
        context.function_name = "test-reset-function"

        result = handler({}, context)

        assert result["items_processed"] == 1  # Only verified user

        # PENDING should not have last_reset
        pending = table.get_item(Key={"pk": "user_pending", "sk": "PENDING"})
        assert "last_reset" not in pending.get("Item", {})

    @mock_aws
    def test_skips_demo_rate_limit_records(self, mock_dynamodb):
        """Should not reset demo rate limit records."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

        # Create demo rate limit record
        table.put_item(
            Item={
                "pk": "demo#192.168.1.1",
                "sk": "hour#2024-01-01-12",
                "requests": 15,
            }
        )

        # Create verified user
        key_hash = hashlib.sha256(b"dh_user").hexdigest()
        table.put_item(
            Item={
                "pk": "user_real",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "real@example.com",
                "tier": "free",
                "requests_this_month": 100,
                "email_verified": True,
            }
        )

        from api.reset_usage import handler

        context = MagicMock()
        context.get_remaining_time_in_millis.return_value = 300000
        context.function_name = "test-reset-function"

        result = handler({}, context)

        assert result["items_processed"] == 1  # Only real user

    @mock_aws
    def test_skips_system_records(self, mock_dynamodb):
        """Should not reset SYSTEM# records."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

        # Create system state record
        table.put_item(
            Item={
                "pk": "SYSTEM#RESET_STATE",
                "sk": "monthly_reset",
                "reset_month": "2024-01",
            }
        )

        # Create verified user
        key_hash = hashlib.sha256(b"dh_user").hexdigest()
        table.put_item(
            Item={
                "pk": "user_real",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "real@example.com",
                "tier": "free",
                "requests_this_month": 100,
                "email_verified": True,
            }
        )

        from api.reset_usage import handler

        context = MagicMock()
        context.get_remaining_time_in_millis.return_value = 300000
        context.function_name = "test-reset-function"

        result = handler({}, context)

        assert result["items_processed"] == 1

    @mock_aws
    def test_resumes_from_stored_state(self, mock_dynamodb):
        """Should resume from stored state on re-invocation."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        from datetime import datetime, timezone

        table = mock_dynamodb.Table("dephealth-api-keys")

        # Create reset state
        current_month = datetime.now(timezone.utc).strftime("%Y-%m")
        table.put_item(
            Item={
                "pk": "SYSTEM#RESET_STATE",
                "sk": "monthly_reset",
                "reset_month": current_month,
                "last_key": {"pk": {"S": "user_1"}, "sk": {"S": "somehash"}},
                "items_processed": 10,
            }
        )

        from api.reset_usage import _get_reset_state

        state = _get_reset_state(table, current_month)
        assert state is not None
        assert state["items_processed"] == 10

    @mock_aws
    def test_clears_state_on_completion(self, mock_dynamodb):
        """Should clear stored state when reset completes."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

        # Create one user to reset
        key_hash = hashlib.sha256(b"dh_single").hexdigest()
        table.put_item(
            Item={
                "pk": "user_single",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "single@example.com",
                "tier": "free",
                "requests_this_month": 100,
                "email_verified": True,
            }
        )

        from api.reset_usage import handler, RESET_STATE_PK, RESET_STATE_SK

        context = MagicMock()
        context.get_remaining_time_in_millis.return_value = 300000
        context.function_name = "test-reset-function"

        result = handler({}, context)

        assert result["completed"] is True

        # State should be cleared
        state = table.get_item(Key={"pk": RESET_STATE_PK, "sk": RESET_STATE_SK})
        assert "Item" not in state

    @mock_aws
    @patch("api.reset_usage.lambda_client")
    def test_self_invokes_on_timeout(self, mock_lambda, mock_dynamodb):
        """Should invoke self when running low on time."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

        # Create a user
        key_hash = hashlib.sha256(b"dh_timeout").hexdigest()
        table.put_item(
            Item={
                "pk": "user_timeout",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "timeout@example.com",
                "tier": "free",
                "requests_this_month": 100,
                "email_verified": True,
            }
        )

        # Mock Lambda invoke
        mock_lambda.invoke.return_value = {"StatusCode": 202}

        from api.reset_usage import _invoke_self_async

        # Test the self-invoke function directly
        _invoke_self_async("test-function", {"pk": {"S": "user_1"}, "sk": {"S": "somehash"}})

        # Should have invoked Lambda
        mock_lambda.invoke.assert_called_once()
        call_args = mock_lambda.invoke.call_args
        assert call_args[1]["FunctionName"] == "test-function"
        assert call_args[1]["InvocationType"] == "Event"

    @mock_aws
    @patch("api.reset_usage.lambda_client")
    def test_raises_on_self_invoke_failure(self, mock_lambda, mock_dynamodb):
        """Should raise exception if self-invocation fails."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        # Mock Lambda invoke to fail
        mock_lambda.invoke.side_effect = Exception("Lambda invocation failed")

        from api.reset_usage import _invoke_self_async

        with pytest.raises(RuntimeError, match="Failed to schedule reset continuation"):
            _invoke_self_async("test-function", {"pk": {"S": "user_1"}})

    @mock_aws
    def test_resets_payment_failures(self, mock_dynamodb):
        """Should reset payment_failures to 0."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

        key_hash = hashlib.sha256(b"dh_failures").hexdigest()
        table.put_item(
            Item={
                "pk": "user_failures",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "failures@example.com",
                "tier": "free",
                "requests_this_month": 100,
                "payment_failures": 2,
                "email_verified": True,
            }
        )

        from api.reset_usage import handler

        context = MagicMock()
        context.get_remaining_time_in_millis.return_value = 300000
        context.function_name = "test-reset-function"

        handler({}, context)

        response = table.get_item(Key={"pk": "user_failures", "sk": key_hash})
        item = response.get("Item")
        assert item["payment_failures"] == 0
        assert item["requests_this_month"] == 0
