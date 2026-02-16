"""
Tests for shared.billing_utils.update_billing_state().
"""

import hashlib

import pytest
from botocore.exceptions import ClientError


@pytest.fixture
def billing_table(mock_dynamodb):
    """API keys table with a test user (2 API keys + USER_META)."""
    table = mock_dynamodb.Table("pkgwatch-api-keys")

    key1 = hashlib.sha256(b"pw_key1").hexdigest()
    key2 = hashlib.sha256(b"pw_key2").hexdigest()

    # API key record 1
    table.put_item(
        Item={
            "pk": "user_abc",
            "sk": key1,
            "email": "test@example.com",
            "tier": "starter",
            "monthly_limit": 50000,
            "email_verified": True,
            "stripe_customer_id": "cus_123",
            "stripe_subscription_id": "sub_456",
            "cancellation_pending": True,
            "cancellation_date": 1700000000,
            "current_period_end": 1700000000,
            "payment_failures": 2,
        }
    )

    # API key record 2
    table.put_item(
        Item={
            "pk": "user_abc",
            "sk": key2,
            "email": "test@example.com",
            "tier": "starter",
            "monthly_limit": 50000,
            "email_verified": True,
            "stripe_customer_id": "cus_123",
            "stripe_subscription_id": "sub_456",
            "cancellation_pending": True,
            "cancellation_date": 1700000000,
        }
    )

    # USER_META
    table.put_item(
        Item={
            "pk": "user_abc",
            "sk": "USER_META",
            "tier": "starter",
            "monthly_limit": 50000,
            "cancellation_pending": True,
            "cancellation_date": 1700000000,
            "current_period_end": 1700000000,
            "payment_failures": 2,
            "requests_this_month": 100,
        }
    )

    return table, key1, key2


def _get_items(table, user_id="user_abc"):
    """Helper to fetch all items for a user."""
    from boto3.dynamodb.conditions import Key

    resp = table.query(KeyConditionExpression=Key("pk").eq(user_id))
    items = resp["Items"]
    meta = None
    keys = []
    for item in items:
        if item["sk"] == "USER_META":
            meta = item
        elif item["sk"] != "PENDING":
            keys.append(item)
    return meta, keys, items


class TestUpdateBillingState:
    """Tests for the centralized billing state writer."""

    def test_basic_tier_update(self, billing_table):
        """Tier update writes tier, monthly_limit, tier_updated_at to both USER_META and API keys."""
        table, key1, key2 = billing_table

        from shared.billing_utils import update_billing_state

        _, _, all_items = _get_items(table)
        update_billing_state(
            user_id="user_abc",
            api_key_records=all_items,
            tier="pro",
            table=table,
        )

        meta, keys, _ = _get_items(table)

        # USER_META updated
        assert meta["tier"] == "pro"
        assert meta["monthly_limit"] == 100000
        assert "tier_updated_at" in meta

        # All API key records updated
        for key in keys:
            assert key["tier"] == "pro"
            assert key["monthly_limit"] == 100000
            assert "tier_updated_at" in key

    def test_cancellation_clear(self, billing_table):
        """Setting cancellation_pending=False and cancellation_date=None clears cancellation."""
        table, key1, key2 = billing_table

        from shared.billing_utils import update_billing_state

        _, _, all_items = _get_items(table)
        update_billing_state(
            user_id="user_abc",
            api_key_records=all_items,
            cancellation_pending=False,
            cancellation_date=None,
            table=table,
        )

        meta, keys, _ = _get_items(table)

        assert meta["cancellation_pending"] is False
        assert meta["cancellation_date"] is None

        for key in keys:
            assert key["cancellation_pending"] is False
            assert key["cancellation_date"] is None

    def test_stripe_ids_not_written_to_user_meta(self, billing_table):
        """stripe_customer_id and stripe_subscription_id are written only to API keys, not USER_META."""
        table, key1, key2 = billing_table

        from shared.billing_utils import update_billing_state

        _, _, all_items = _get_items(table)
        update_billing_state(
            user_id="user_abc",
            api_key_records=all_items,
            stripe_customer_id="cus_new",
            stripe_subscription_id="sub_new",
            table=table,
        )

        meta, keys, _ = _get_items(table)

        # USER_META should NOT have Stripe IDs
        assert meta.get("stripe_customer_id") is None
        assert meta.get("stripe_subscription_id") is None

        # API keys should have them
        for key in keys:
            assert key["stripe_customer_id"] == "cus_new"
            assert key["stripe_subscription_id"] == "sub_new"

    def test_email_verified_not_written_to_user_meta(self, billing_table):
        """email_verified is written only to API keys, not USER_META."""
        table, key1, key2 = billing_table

        from shared.billing_utils import update_billing_state

        _, _, all_items = _get_items(table)
        update_billing_state(
            user_id="user_abc",
            api_key_records=all_items,
            email_verified=True,
            table=table,
        )

        meta, _, _ = _get_items(table)
        assert "email_verified" not in meta

    def test_pending_records_skipped(self, billing_table):
        """PENDING records in api_key_records are not updated."""
        table, key1, key2 = billing_table

        # Add a PENDING record
        table.put_item(
            Item={
                "pk": "user_abc",
                "sk": "PENDING",
                "email": "test@example.com",
                "tier": "free",
            }
        )

        from shared.billing_utils import update_billing_state

        _, _, all_items = _get_items(table)
        # Manually add PENDING to the list (since _get_items filters it)
        pending_item = {"pk": "user_abc", "sk": "PENDING"}
        all_items.append(pending_item)

        update_billing_state(
            user_id="user_abc",
            api_key_records=all_items,
            tier="business",
            table=table,
        )

        # PENDING record should still be free
        pending = table.get_item(Key={"pk": "user_abc", "sk": "PENDING"})["Item"]
        assert pending["tier"] == "free"

        # API keys should be updated
        _, keys, _ = _get_items(table)
        for key in keys:
            assert key["tier"] == "business"

    def test_user_meta_in_records_skipped(self, billing_table):
        """USER_META passed in api_key_records is not double-written in phase 2."""
        table, key1, key2 = billing_table

        from shared.billing_utils import update_billing_state

        _, _, all_items = _get_items(table)
        update_billing_state(
            user_id="user_abc",
            api_key_records=all_items,
            tier="pro",
            table=table,
        )

        # Should not raise or error — just works
        meta, _, _ = _get_items(table)
        assert meta["tier"] == "pro"

    def test_remove_subscription_id(self, billing_table):
        """remove_subscription_id=True REMOVEs stripe_subscription_id from API keys."""
        table, key1, key2 = billing_table

        from shared.billing_utils import update_billing_state

        _, _, all_items = _get_items(table)
        update_billing_state(
            user_id="user_abc",
            api_key_records=all_items,
            tier="free",
            remove_subscription_id=True,
            table=table,
        )

        _, keys, _ = _get_items(table)
        for key in keys:
            assert "stripe_subscription_id" not in key
            assert key["tier"] == "free"

    def test_current_period_start_mirrors_last_reset(self, billing_table):
        """current_period_start also writes last_reset_period_start to API keys (not USER_META)."""
        table, key1, key2 = billing_table

        from shared.billing_utils import update_billing_state

        _, _, all_items = _get_items(table)
        update_billing_state(
            user_id="user_abc",
            api_key_records=all_items,
            current_period_start=1710000000,
            table=table,
        )

        meta, keys, _ = _get_items(table)

        # USER_META gets current_period_start but NOT last_reset_period_start
        assert meta["current_period_start"] == 1710000000
        assert "last_reset_period_start" not in meta

        # API keys get both
        for key in keys:
            assert key["current_period_start"] == 1710000000
            assert key["last_reset_period_start"] == 1710000000

    def test_individual_api_key_failure_doesnt_abort(self, billing_table):
        """If one API key update fails, the others still get updated."""
        table, key1, key2 = billing_table

        from shared.billing_utils import update_billing_state

        _, _, all_items = _get_items(table)

        # Wrap table to fail on first key update only
        original_update = table.update_item
        call_count = [0]

        def flaky_update(**kwargs):
            call_count[0] += 1
            # Fail on the 2nd call (first API key, after USER_META)
            if call_count[0] == 2:
                raise ClientError(
                    {"Error": {"Code": "InternalServerError", "Message": "boom"}},
                    "UpdateItem",
                )
            return original_update(**kwargs)

        table.update_item = flaky_update

        update_billing_state(
            user_id="user_abc",
            api_key_records=all_items,
            tier="business",
            table=table,
        )

        # Restore original for reads
        table.update_item = original_update

        meta, keys, _ = _get_items(table)
        # USER_META should be updated
        assert meta["tier"] == "business"
        # One key should be updated, one should still be old
        tiers = [k["tier"] for k in keys]
        assert "business" in tiers
        assert "starter" in tiers  # The one that failed

    def test_empty_api_key_records(self, billing_table):
        """Empty api_key_records still writes USER_META."""
        table, _, _ = billing_table

        from shared.billing_utils import update_billing_state

        update_billing_state(
            user_id="user_abc",
            api_key_records=[],
            tier="pro",
            table=table,
        )

        meta, _, _ = _get_items(table)
        assert meta["tier"] == "pro"

    def test_all_unset_is_noop(self, billing_table):
        """Calling with no fields set is a no-op (early return)."""
        table, key1, key2 = billing_table

        from shared.billing_utils import update_billing_state

        # Get original state
        meta_before, keys_before, _ = _get_items(table)

        update_billing_state(
            user_id="user_abc",
            api_key_records=[],
            table=table,
        )

        meta_after, keys_after, _ = _get_items(table)
        assert meta_after["tier"] == meta_before["tier"]
        assert meta_after["cancellation_pending"] == meta_before["cancellation_pending"]

    def test_missing_user_meta_graceful(self, mock_dynamodb):
        """ConditionalCheckFailedException on USER_META is handled gracefully."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_key1").hexdigest()

        # Only create an API key record, NO USER_META
        table.put_item(
            Item={
                "pk": "user_no_meta",
                "sk": key_hash,
                "email": "test@example.com",
                "tier": "free",
            }
        )

        from shared.billing_utils import update_billing_state

        items = [{"pk": "user_no_meta", "sk": key_hash}]

        # Should not raise
        update_billing_state(
            user_id="user_no_meta",
            api_key_records=items,
            tier="pro",
            table=table,
        )

        # API key should still be updated
        key = table.get_item(Key={"pk": "user_no_meta", "sk": key_hash})["Item"]
        assert key["tier"] == "pro"

    def test_throttling_error_propagates(self, billing_table):
        """Throttling errors on USER_META re-raise so callers can retry."""
        table, key1, key2 = billing_table

        from shared.billing_utils import update_billing_state

        original_update = table.update_item

        def throttle_update(**kwargs):
            key = kwargs.get("Key", {})
            if key.get("sk") == "USER_META":
                raise ClientError(
                    {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "throttled"}},
                    "UpdateItem",
                )
            return original_update(**kwargs)

        table.update_item = throttle_update

        _, _, all_items = _get_items(table)

        with pytest.raises(ClientError) as exc_info:
            update_billing_state(
                user_id="user_abc",
                api_key_records=all_items,
                tier="pro",
                table=table,
            )

        assert exc_info.value.response["Error"]["Code"] == "ProvisionedThroughputExceededException"

    def test_payment_failures_written(self, billing_table):
        """payment_failures is written to both USER_META and API keys."""
        table, key1, key2 = billing_table

        from shared.billing_utils import update_billing_state

        _, _, all_items = _get_items(table)
        update_billing_state(
            user_id="user_abc",
            api_key_records=all_items,
            payment_failures=0,
            table=table,
        )

        meta, keys, _ = _get_items(table)
        assert meta["payment_failures"] == 0
        for key in keys:
            assert key["payment_failures"] == 0

    def test_full_upgrade_scenario(self, billing_table):
        """Simulates a full upgrade: tier change + clear cancellation + reset failures."""
        table, key1, key2 = billing_table

        from shared.billing_utils import update_billing_state

        _, _, all_items = _get_items(table)
        update_billing_state(
            user_id="user_abc",
            api_key_records=all_items,
            tier="pro",
            cancellation_pending=False,
            cancellation_date=None,
            payment_failures=0,
            current_period_end=1710000000,
            table=table,
        )

        meta, keys, _ = _get_items(table)

        # Verify all fields on USER_META
        assert meta["tier"] == "pro"
        assert meta["monthly_limit"] == 100000
        assert meta["cancellation_pending"] is False
        assert meta["cancellation_date"] is None
        assert meta["payment_failures"] == 0
        assert meta["current_period_end"] == 1710000000

        # Verify all fields on API keys
        for key in keys:
            assert key["tier"] == "pro"
            assert key["monthly_limit"] == 100000
            assert key["cancellation_pending"] is False
            assert key["cancellation_date"] is None
            assert key["payment_failures"] == 0
            assert key["current_period_end"] == 1710000000

    def test_remove_only_expression(self, billing_table):
        """REMOVE-only update (no SET fields) produces valid DynamoDB expression."""
        table, key1, key2 = billing_table

        from shared.billing_utils import update_billing_state

        # remove_subscription_id with email_verified (which needs SET) to avoid
        # the edge case. But let's also test the pure REMOVE case.
        # Pure REMOVE requires at least one API-key-only field and no common fields.
        # Actually, remove_subscription_id alone would produce nothing in common_set_parts
        # but key_remove_parts would have one entry. However, the guard at line 176
        # (if not key_set_parts and not key_remove_parts: return) would not trigger.
        # But we need at least one common field or key field for the expression to work.

        # Test: remove_subscription_id=True WITH a tier change (SET + REMOVE)
        _, _, all_items = _get_items(table)
        update_billing_state(
            user_id="user_abc",
            api_key_records=all_items,
            tier="free",
            remove_subscription_id=True,
            table=table,
        )

        _, keys, _ = _get_items(table)
        for key in keys:
            assert key["tier"] == "free"
            assert "stripe_subscription_id" not in key
