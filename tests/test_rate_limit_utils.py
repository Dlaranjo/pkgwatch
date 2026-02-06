"""
Tests for rate limiting utilities.
"""

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from moto import mock_aws


class TestGetResetTimestamp:
    """Tests for get_reset_timestamp function."""

    def test_returns_first_of_next_month(self):
        """Should return timestamp for first day of next month."""
        from shared.rate_limit_utils import get_reset_timestamp

        timestamp = get_reset_timestamp()
        reset_date = datetime.fromtimestamp(timestamp, tz=timezone.utc)

        # Should be first of month
        assert reset_date.day == 1
        assert reset_date.hour == 0
        assert reset_date.minute == 0
        assert reset_date.second == 0

    def test_returns_integer_timestamp(self):
        """Should return integer Unix timestamp."""
        from shared.rate_limit_utils import get_reset_timestamp

        timestamp = get_reset_timestamp()
        assert isinstance(timestamp, int)

    def test_reset_is_in_future(self):
        """Should return a future timestamp."""
        from shared.rate_limit_utils import get_reset_timestamp

        timestamp = get_reset_timestamp()
        now = int(datetime.now(timezone.utc).timestamp())

        assert timestamp > now

    def test_december_wraps_to_january(self):
        """Should correctly handle December -> January transition."""
        from unittest.mock import patch

        from shared.rate_limit_utils import get_reset_timestamp

        # Mock December 15th
        mock_date = datetime(2025, 12, 15, 10, 30, 0, tzinfo=timezone.utc)
        with patch("shared.rate_limit_utils.datetime") as mock_datetime:
            mock_datetime.now.return_value = mock_date
            mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

            timestamp = get_reset_timestamp()
            reset_date = datetime.fromtimestamp(timestamp, tz=timezone.utc)

            # Should be January 1st of next year
            assert reset_date.year == 2026
            assert reset_date.month == 1
            assert reset_date.day == 1


class TestCheckUsageAlerts:
    """Tests for check_usage_alerts function."""

    def test_no_alert_under_80_percent(self):
        """Should return None when usage is under 80%."""
        from shared.rate_limit_utils import check_usage_alerts

        user = {"monthly_limit": 5000}
        result = check_usage_alerts(user, 3000)  # 60%

        assert result is None

    def test_warning_at_80_percent(self):
        """Should return warning alert at 80% usage."""
        from shared.rate_limit_utils import check_usage_alerts

        user = {"monthly_limit": 5000}
        result = check_usage_alerts(user, 4000)  # 80%

        assert result is not None
        assert result["level"] == "warning"
        assert result["percent"] == 80.0

    def test_critical_at_95_percent(self):
        """Should return critical alert at 95% usage."""
        from shared.rate_limit_utils import check_usage_alerts

        user = {"monthly_limit": 5000}
        result = check_usage_alerts(user, 4800)  # 96%

        assert result is not None
        assert result["level"] == "critical"
        assert "remaining" in result["message"]

    def test_exceeded_at_100_percent(self):
        """Should return exceeded alert at 100% usage."""
        from shared.rate_limit_utils import check_usage_alerts

        user = {"monthly_limit": 5000}
        result = check_usage_alerts(user, 5000)  # 100%

        assert result is not None
        assert result["level"] == "exceeded"
        assert result["percent"] == 100

    def test_exceeded_over_100_percent(self):
        """Should return exceeded alert when over limit."""
        from shared.rate_limit_utils import check_usage_alerts

        user = {"monthly_limit": 5000}
        result = check_usage_alerts(user, 5500)  # 110%

        assert result is not None
        assert result["level"] == "exceeded"

    def test_uses_default_limit_if_missing(self):
        """Should use default 5000 limit if not specified."""
        from shared.rate_limit_utils import check_usage_alerts

        user = {}  # No monthly_limit
        result = check_usage_alerts(user, 4500)  # 90% of 5000

        assert result is not None
        assert result["level"] == "warning"

    def test_handles_zero_limit(self):
        """Should return exceeded for zero limit."""
        from shared.rate_limit_utils import check_usage_alerts

        user = {"monthly_limit": 0}
        result = check_usage_alerts(user, 1)

        assert result is not None
        assert result["level"] == "exceeded"


class TestExternalRateLimiting:
    """Tests for external service rate limiting with sharded counters."""

    @mock_aws
    def test_get_dynamodb_lazy_initialization(self, mock_dynamodb):
        """Should lazily initialize DynamoDB resource on first use."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import shared.aws_clients as aws_clients_module

        aws_clients_module._dynamodb = None

        # First call should create DynamoDB resource
        db1 = aws_clients_module.get_dynamodb()
        assert db1 is not None

        # Second call should return same instance
        db2 = aws_clients_module.get_dynamodb()
        assert db1 is db2

    @mock_aws
    def test_first_request_allowed_creates_counter(self, mock_dynamodb):
        """Should allow first request and create counter in DynamoDB."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import shared.rate_limit_utils as module

        module._dynamodb = None  # Reset for test isolation

        result = module.check_and_increment_external_rate_limit(
            service="npm", hourly_limit=100, table_name="pkgwatch-api-keys"
        )

        assert result is True

        # Verify counter was created in DynamoDB
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        response = table.scan()
        rate_limit_items = [item for item in response["Items"] if item.get("pk", "").startswith("npm_rate_limit#")]
        assert len(rate_limit_items) == 1
        assert rate_limit_items[0]["calls"] == 1

    @mock_aws
    def test_subsequent_requests_increment_counter(self, mock_dynamodb):
        """Should increment counter for subsequent requests."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import shared.rate_limit_utils as module

        module._dynamodb = None

        # Make multiple requests - use fixed shard to ensure same counter
        with patch("shared.rate_limit_utils.random.randint", return_value=0):
            for _ in range(5):
                result = module.check_and_increment_external_rate_limit(
                    service="npm", hourly_limit=100, table_name="pkgwatch-api-keys"
                )
                assert result is True

        # Verify counter was incremented
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        response = table.scan()
        rate_limit_items = [item for item in response["Items"] if item.get("pk", "").startswith("npm_rate_limit#0")]
        assert len(rate_limit_items) == 1
        assert rate_limit_items[0]["calls"] == 5

    @mock_aws
    def test_shard_limit_reached_falls_back_to_other_shards(self, mock_dynamodb):
        """Should try other shards when random shard is at limit."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import shared.rate_limit_utils as module

        module._dynamodb = None

        # Pre-fill shard 0 to its limit (hourly_limit=20, 10 shards => shard_limit=3)
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        now = datetime.now(timezone.utc)
        window_key = now.strftime("%Y-%m-%d-%H")

        table.put_item(
            Item={
                "pk": "npm_rate_limit#0",
                "sk": window_key,
                "calls": 3,  # At shard limit
                "ttl": int(now.timestamp()) + 7200,
            }
        )

        # Mock random to always return shard 0 first
        with patch("shared.rate_limit_utils.random.randint", return_value=0):
            # Should still succeed by falling back to another shard
            result = module.check_and_increment_external_rate_limit(
                service="npm", hourly_limit=20, table_name="pkgwatch-api-keys"
            )

            assert result is True

    @mock_aws
    def test_all_shards_at_limit_returns_false(self, mock_dynamodb):
        """Should return False when all shards are at their limit."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import shared.rate_limit_utils as module

        module._dynamodb = None

        # Pre-fill ALL shards to their limits
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        now = datetime.now(timezone.utc)
        window_key = now.strftime("%Y-%m-%d-%H")

        # hourly_limit=20, 10 shards => shard_limit=3
        for shard_id in range(10):
            table.put_item(
                Item={
                    "pk": f"npm_rate_limit#{shard_id}",
                    "sk": window_key,
                    "calls": 3,
                    "ttl": int(now.timestamp()) + 7200,
                }
            )

        result = module.check_and_increment_external_rate_limit(
            service="npm", hourly_limit=20, table_name="pkgwatch-api-keys"
        )

        assert result is False

    @mock_aws
    def test_non_conditional_check_errors_propagate(self, mock_dynamodb):
        """Should propagate non-ConditionalCheckFailedException errors."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import shared.aws_clients as aws_clients_module
        import shared.rate_limit_utils as module

        aws_clients_module._dynamodb = None

        with patch("shared.rate_limit_utils.get_dynamodb") as mock_get_db:
            mock_table = MagicMock()
            mock_table.update_item.side_effect = ClientError(
                {"Error": {"Code": "ProvisionedThroughputExceededException"}},
                "UpdateItem",
            )
            mock_get_db.return_value.Table.return_value = mock_table

            with pytest.raises(ClientError) as exc_info:
                module.check_and_increment_external_rate_limit(
                    service="npm", hourly_limit=100, table_name="pkgwatch-api-keys"
                )

            assert exc_info.value.response["Error"]["Code"] == "ProvisionedThroughputExceededException"
