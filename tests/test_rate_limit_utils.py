"""
Tests for rate limiting utilities.
"""

from datetime import datetime, timezone


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
        with patch('shared.rate_limit_utils.datetime') as mock_datetime:
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
