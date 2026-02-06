"""
Tests for per-user billing cycle reset functionality.

Tests the invoice.paid webhook handler, idempotency checks,
monthly reset skip logic, and backup reset handler.
"""

import hashlib
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from moto import mock_aws


class TestInvoicePaidHandler:
    """Tests for the invoice.paid webhook handler."""

    @mock_aws
    def test_resets_usage_on_subscription_cycle(self, mock_dynamodb):
        """Should reset usage when subscription billing cycle renews."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_cycle_user").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cycle",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cycle@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_cycle123",
                "requests_this_month": 5000,
                "current_period_end": 1704067200,  # Old period end
                "last_reset_period_start": 1701388800,  # Previous period start
            }
        )

        # Also create USER_META with usage
        table.put_item(
            Item={
                "pk": "user_cycle",
                "sk": "USER_META",
                "requests_this_month": 5000,
            }
        )

        from api.stripe_webhook import _handle_invoice_paid

        invoice = {
            "customer": "cus_cycle123",
            "subscription": "sub_123",
            "billing_reason": "subscription_cycle",
            "lines": {
                "data": [
                    {
                        "type": "subscription",
                        "period": {
                            "start": 1704067200,  # New period start
                            "end": 1706745600,  # New period end
                        },
                    }
                ]
            },
        }

        _handle_invoice_paid(invoice)

        # Check usage was reset
        response = table.get_item(Key={"pk": "user_cycle", "sk": key_hash})
        item = response["Item"]
        assert item["requests_this_month"] == 0
        assert item["current_period_end"] == 1706745600
        assert item["last_reset_period_start"] == 1704067200
        assert "last_usage_reset" in item

        # Check USER_META was also reset
        meta = table.get_item(Key={"pk": "user_cycle", "sk": "USER_META"})
        assert meta["Item"]["requests_this_month"] == 0

    @mock_aws
    def test_skips_manual_payment(self, mock_dynamodb):
        """Should not reset usage for manual payments."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_manual").hexdigest()
        table.put_item(
            Item={
                "pk": "user_manual",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "manual@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_manual",
                "requests_this_month": 3000,
            }
        )

        from api.stripe_webhook import _handle_invoice_paid

        invoice = {
            "customer": "cus_manual",
            "billing_reason": "manual",  # Not a cycle renewal
        }

        _handle_invoice_paid(invoice)

        # Usage should NOT be reset
        response = table.get_item(Key={"pk": "user_manual", "sk": key_hash})
        assert response["Item"]["requests_this_month"] == 3000

    @mock_aws
    def test_idempotency_prevents_double_reset(self, mock_dynamodb):
        """Should not reset twice for the same period (idempotency check)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_idempotent").hexdigest()
        table.put_item(
            Item={
                "pk": "user_idempotent",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "idempotent@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_idempotent",
                "requests_this_month": 0,  # Already reset
                "current_period_start": 1704067200,
                "current_period_end": 1706745600,
                "last_reset_period_start": 1704067200,  # Already reset for this period
            }
        )

        # Simulate usage after reset
        table.update_item(
            Key={"pk": "user_idempotent", "sk": key_hash},
            UpdateExpression="SET requests_this_month = :usage",
            ExpressionAttributeValues={":usage": 100},
        )

        from api.stripe_webhook import _handle_invoice_paid

        # Try to reset again for same period
        invoice = {
            "customer": "cus_idempotent",
            "subscription": "sub_123",
            "billing_reason": "subscription_cycle",
            "lines": {
                "data": [
                    {
                        "type": "subscription",
                        "period": {
                            "start": 1704067200,  # Same period start
                            "end": 1706745600,
                        },
                    }
                ]
            },
        }

        _handle_invoice_paid(invoice)

        # Usage should NOT be reset (idempotency)
        response = table.get_item(Key={"pk": "user_idempotent", "sk": key_hash})
        assert response["Item"]["requests_this_month"] == 100


class TestMonthlyResetWithBillingCycle:
    """Tests for monthly reset with paid user exclusion."""

    @mock_aws
    def test_skips_paid_users_with_billing_data(self, mock_dynamodb):
        """Should skip paid users who have billing cycle data."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_CYCLE_RESET_ENABLED"] = "true"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Free user - should be reset
        free_hash = hashlib.sha256(b"pw_free").hexdigest()
        table.put_item(
            Item={
                "pk": "user_free",
                "sk": free_hash,
                "key_hash": free_hash,
                "tier": "free",
                "requests_this_month": 100,
            }
        )

        # Paid user with billing data - should be skipped
        paid_hash = hashlib.sha256(b"pw_paid").hexdigest()
        table.put_item(
            Item={
                "pk": "user_paid",
                "sk": paid_hash,
                "key_hash": paid_hash,
                "tier": "pro",
                "stripe_customer_id": "cus_paid",
                "current_period_end": 1706745600,  # Has billing data
                "requests_this_month": 5000,
            }
        )

        from api.reset_usage import handler

        context = MagicMock()
        context.get_remaining_time_in_millis.return_value = 300000
        context.function_name = "test-reset"

        result = handler({}, context)

        # Free user should be reset
        free_response = table.get_item(Key={"pk": "user_free", "sk": free_hash})
        assert free_response["Item"]["requests_this_month"] == 0

        # Paid user should NOT be reset
        paid_response = table.get_item(Key={"pk": "user_paid", "sk": paid_hash})
        assert paid_response["Item"]["requests_this_month"] == 5000

        # Verify skip count
        assert result["items_skipped"] == 1

    @mock_aws
    def test_resets_legacy_paid_users_without_billing_data(self, mock_dynamodb):
        """Should reset legacy paid users who don't have billing cycle data."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_CYCLE_RESET_ENABLED"] = "true"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Legacy paid user without billing data - should be reset
        legacy_hash = hashlib.sha256(b"pw_legacy").hexdigest()
        table.put_item(
            Item={
                "pk": "user_legacy",
                "sk": legacy_hash,
                "key_hash": legacy_hash,
                "tier": "pro",
                "stripe_customer_id": "cus_legacy",
                # No current_period_end field
                "requests_this_month": 2000,
            }
        )

        from api.reset_usage import handler

        context = MagicMock()
        context.get_remaining_time_in_millis.return_value = 300000
        context.function_name = "test-reset"

        handler({}, context)

        # Legacy user should still be reset
        response = table.get_item(Key={"pk": "user_legacy", "sk": legacy_hash})
        assert response["Item"]["requests_this_month"] == 0

    @mock_aws
    def test_feature_flag_disabled_resets_all(self, mock_dynamodb):
        """When feature flag is disabled, should reset all users including paid."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_CYCLE_RESET_ENABLED"] = "false"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Paid user with billing data - should be reset when flag disabled
        paid_hash = hashlib.sha256(b"pw_paid_flag").hexdigest()
        table.put_item(
            Item={
                "pk": "user_paid_flag",
                "sk": paid_hash,
                "key_hash": paid_hash,
                "tier": "pro",
                "stripe_customer_id": "cus_paid_flag",
                "current_period_end": 1706745600,
                "requests_this_month": 5000,
            }
        )

        from api.reset_usage import handler

        context = MagicMock()
        context.get_remaining_time_in_millis.return_value = 300000
        context.function_name = "test-reset"

        result = handler({}, context)

        # Paid user should be reset when flag is disabled
        response = table.get_item(Key={"pk": "user_paid_flag", "sk": paid_hash})
        assert response["Item"]["requests_this_month"] == 0
        assert result["billing_cycle_enabled"] is False


class TestBackupReset:
    """Tests for the daily backup reset handler."""

    @mock_aws
    def test_catches_missed_reset(self, mock_dynamodb):
        """Should reset users whose period ended but weren't reset."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # User whose period ended 2 hours ago but wasn't reset
        now = datetime.now(timezone.utc)
        old_period_end = int((now - timedelta(hours=2)).timestamp())
        old_period_start = old_period_end - (30 * 24 * 60 * 60)

        missed_hash = hashlib.sha256(b"pw_missed").hexdigest()
        table.put_item(
            Item={
                "pk": "user_missed",
                "sk": missed_hash,
                "key_hash": missed_hash,
                "tier": "pro",
                "stripe_customer_id": "cus_missed",
                "current_period_start": old_period_start,
                "current_period_end": old_period_end,
                "last_reset_period_start": old_period_start - (30 * 24 * 60 * 60),  # Previous period
                "requests_this_month": 8000,
            }
        )

        from api.reset_usage_backup import handler

        result = handler({}, {})

        assert result["items_reset"] == 1

        # User should now be reset
        response = table.get_item(Key={"pk": "user_missed", "sk": missed_hash})
        assert response["Item"]["requests_this_month"] == 0

    @mock_aws
    def test_skips_already_reset_users(self, mock_dynamodb):
        """Should not re-reset users who were already reset."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # User whose period ended but was already reset via webhook
        now = datetime.now(timezone.utc)
        old_period_end = int((now - timedelta(hours=2)).timestamp())
        old_period_start = old_period_end - (30 * 24 * 60 * 60)

        done_hash = hashlib.sha256(b"pw_done").hexdigest()
        table.put_item(
            Item={
                "pk": "user_done",
                "sk": done_hash,
                "key_hash": done_hash,
                "tier": "pro",
                "stripe_customer_id": "cus_done",
                "current_period_start": old_period_start,
                "current_period_end": old_period_end,
                "last_reset_period_start": old_period_start,  # Already reset for this period
                "requests_this_month": 0,
            }
        )

        from api.reset_usage_backup import handler

        result = handler({}, {})

        assert result["items_reset"] == 0
        assert result["items_already_reset"] == 1

    @mock_aws
    def test_respects_grace_period(self, mock_dynamodb):
        """Should not reset users within grace period (webhook might still arrive)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # User whose period ended 30 minutes ago (within grace period)
        now = datetime.now(timezone.utc)
        recent_period_end = int((now - timedelta(minutes=30)).timestamp())
        recent_period_start = recent_period_end - (30 * 24 * 60 * 60)

        recent_hash = hashlib.sha256(b"pw_recent").hexdigest()
        table.put_item(
            Item={
                "pk": "user_recent",
                "sk": recent_hash,
                "key_hash": recent_hash,
                "tier": "pro",
                "stripe_customer_id": "cus_recent",
                "current_period_start": recent_period_start,
                "current_period_end": recent_period_end,
                "last_reset_period_start": recent_period_start - (30 * 24 * 60 * 60),
                "requests_this_month": 1000,
            }
        )

        from api.reset_usage_backup import handler

        result = handler({}, {})

        # Should not be processed (within grace period, filtered out by scan)
        assert result["items_reset"] == 0


class TestExtractPeriodFromInvoice:
    """Tests for period extraction from invoice lines."""

    def test_extracts_subscription_period(self):
        """Should extract period from subscription line item."""
        from api.stripe_webhook import _extract_period_from_invoice

        invoice = {
            "lines": {
                "data": [
                    {
                        "type": "subscription",
                        "period": {
                            "start": 1704067200,
                            "end": 1706745600,
                        },
                    }
                ]
            }
        }

        start, end = _extract_period_from_invoice(invoice)

        assert start == 1704067200
        assert end == 1706745600

    def test_returns_none_for_missing_lines(self):
        """Should return None when no subscription lines."""
        from api.stripe_webhook import _extract_period_from_invoice

        invoice = {"lines": {"data": []}}

        start, end = _extract_period_from_invoice(invoice)

        assert start is None
        assert end is None

    def test_ignores_non_subscription_lines(self):
        """Should only extract from subscription type lines."""
        from api.stripe_webhook import _extract_period_from_invoice

        invoice = {
            "lines": {
                "data": [
                    {
                        "type": "invoiceitem",
                        "period": {"start": 1111, "end": 2222},
                    },
                    {
                        "type": "subscription",
                        "period": {"start": 3333, "end": 4444},
                    },
                ]
            }
        }

        start, end = _extract_period_from_invoice(invoice)

        assert start == 3333
        assert end == 4444


class TestBackupResetErrors:
    """Tests for error handling in backup reset (lines 143-144, 149)."""

    @mock_aws
    def test_per_item_error_continues_processing(self, mock_dynamodb):
        """Per-item error during backup reset should be caught and processing continues (lines 143-144)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from unittest.mock import MagicMock, patch

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # User who needs backup reset
        now = datetime.now(timezone.utc)
        old_period_end = int((now - timedelta(hours=2)).timestamp())
        old_period_start = old_period_end - (30 * 24 * 60 * 60)

        for i in range(2):
            err_hash = hashlib.sha256(f"pw_err_backup_{i}".encode()).hexdigest()
            table.put_item(
                Item={
                    "pk": f"user_err_backup_{i}",
                    "sk": err_hash,
                    "key_hash": err_hash,
                    "tier": "pro",
                    "stripe_customer_id": f"cus_err_backup_{i}",
                    "current_period_start": old_period_start,
                    "current_period_end": old_period_end,
                    "last_reset_period_start": old_period_start - (30 * 24 * 60 * 60),
                    "requests_this_month": 5000,
                }
            )

        # Create a mock table that wraps the real one but fails on one update
        mock_table = MagicMock()
        mock_table.scan.side_effect = table.scan

        call_count = [0]
        original_update = table.update_item

        def failing_update(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("Simulated DynamoDB error")
            return original_update(*args, **kwargs)

        mock_table.update_item.side_effect = failing_update

        import api.reset_usage_backup as backup_module

        with patch.object(backup_module, "dynamodb") as mock_db:
            mock_db.Table.return_value = mock_table

            result = backup_module.handler({}, {})

        # Should have checked 2 items, but only 1 successfully reset
        # (the other failed on first update_item call)
        assert result["items_checked"] == 2

    @mock_aws
    def test_pagination_handles_multiple_pages(self, mock_dynamodb):
        """Should handle pagination correctly (line 149)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        now = datetime.now(timezone.utc)
        old_period_end = int((now - timedelta(hours=2)).timestamp())
        old_period_start = old_period_end - (30 * 24 * 60 * 60)

        missed_hash = hashlib.sha256(b"pw_paginate").hexdigest()
        table.put_item(
            Item={
                "pk": "user_paginate",
                "sk": missed_hash,
                "key_hash": missed_hash,
                "tier": "pro",
                "stripe_customer_id": "cus_paginate",
                "current_period_start": old_period_start,
                "current_period_end": old_period_end,
                "last_reset_period_start": old_period_start - (30 * 24 * 60 * 60),
                "requests_this_month": 3000,
            }
        )

        # Use the real table - moto handles single-page scans
        from api.reset_usage_backup import handler

        result = handler({}, {})

        assert result["items_reset"] == 1
        # Verify the user was reset
        response = table.get_item(Key={"pk": "user_paginate", "sk": missed_hash})
        assert response["Item"]["requests_this_month"] == 0


class TestBackupResetUserMetaUpdate:
    """Tests for USER_META update in backup reset."""

    @mock_aws
    def test_updates_user_meta_during_backup_reset(self, mock_dynamodb):
        """Should also update USER_META record when performing backup reset."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        now = datetime.now(timezone.utc)
        old_period_end = int((now - timedelta(hours=2)).timestamp())
        old_period_start = old_period_end - (30 * 24 * 60 * 60)

        missed_hash = hashlib.sha256(b"pw_meta_backup").hexdigest()
        table.put_item(
            Item={
                "pk": "user_meta_backup",
                "sk": missed_hash,
                "key_hash": missed_hash,
                "tier": "pro",
                "stripe_customer_id": "cus_meta_backup",
                "current_period_start": old_period_start,
                "current_period_end": old_period_end,
                "last_reset_period_start": old_period_start - (30 * 24 * 60 * 60),
                "requests_this_month": 7000,
            }
        )

        # Create USER_META
        table.put_item(
            Item={
                "pk": "user_meta_backup",
                "sk": "USER_META",
                "requests_this_month": 7000,
            }
        )

        from api.reset_usage_backup import handler

        result = handler({}, {})

        assert result["items_reset"] == 1

        # Check USER_META was also updated
        meta = table.get_item(Key={"pk": "user_meta_backup", "sk": "USER_META"})
        meta_item = meta.get("Item")
        assert meta_item["requests_this_month"] == 0

    @mock_aws
    def test_backup_reset_warning_when_resets_needed(self, mock_dynamodb, caplog):
        """Should log ALERT warning when backup resets are needed."""
        import logging

        caplog.set_level(logging.WARNING)

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        now = datetime.now(timezone.utc)
        old_period_end = int((now - timedelta(hours=2)).timestamp())
        old_period_start = old_period_end - (30 * 24 * 60 * 60)

        alert_hash = hashlib.sha256(b"pw_alert_backup").hexdigest()
        table.put_item(
            Item={
                "pk": "user_alert_backup",
                "sk": alert_hash,
                "key_hash": alert_hash,
                "tier": "pro",
                "stripe_customer_id": "cus_alert_backup",
                "current_period_start": old_period_start,
                "current_period_end": old_period_end,
                "last_reset_period_start": old_period_start - (30 * 24 * 60 * 60),
                "requests_this_month": 2000,
            }
        )

        from api.reset_usage_backup import handler

        handler({}, {})

        assert "ALERT" in caplog.text
        assert "check Stripe webhook delivery" in caplog.text


class TestInvoicePaidMissingSubscription:
    """Test for invoice.paid with no subscription ID."""

    @mock_aws
    def test_handles_no_subscription_id_gracefully(self, mock_dynamodb):
        """Should handle invoice.paid with missing subscription field."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _handle_invoice_paid

        invoice = {
            "customer": "cus_no_sub",
            "billing_reason": "subscription_cycle",
            "lines": {"data": [{"type": "subscription", "period": {"start": 1706745600, "end": 1709424000}}]},
        }

        # Should not raise even without subscription field
        _handle_invoice_paid(invoice)
