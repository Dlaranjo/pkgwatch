"""
Tests for referral program functionality.

Tests cover:
- Email canonicalization (Gmail dots/plus-aliases)
- Disposable email detection
- Referral code generation and validation
- Self-referral prevention
- Bonus credit management with lifetime cap
- Activity gate threshold trigger
- Late entry within 14-day window
"""

import os
import pytest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import patch, MagicMock

# Set environment variables before importing modules
os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

from shared.referral_utils import (
    canonicalize_email,
    is_disposable_email,
    generate_referral_code,
    is_valid_referral_code,
    is_self_referral,
    mask_email,
    REFERRAL_REWARDS,
    REFERRED_USER_BONUS,
    ACTIVITY_THRESHOLD,
    BONUS_CAP,
    LATE_ENTRY_DAYS,
    PENDING_TIMEOUT_DAYS,
)


class TestEmailCanonicalization:
    """Test email canonicalization for self-referral prevention."""

    def test_gmail_dots_stripped(self):
        """Gmail dots should be stripped."""
        assert canonicalize_email("john.doe@gmail.com") == "johndoe@gmail.com"
        assert canonicalize_email("j.o.h.n@gmail.com") == "john@gmail.com"

    def test_gmail_plus_alias_stripped(self):
        """Gmail plus-aliases should be stripped."""
        assert canonicalize_email("john+work@gmail.com") == "john@gmail.com"
        assert canonicalize_email("john+referral@gmail.com") == "john@gmail.com"

    def test_gmail_dots_and_plus_combined(self):
        """Gmail dots and plus should both be stripped."""
        assert canonicalize_email("j.o.h.n+work@gmail.com") == "john@gmail.com"

    def test_googlemail_normalized(self):
        """googlemail.com should be normalized to gmail.com."""
        assert canonicalize_email("john@googlemail.com") == "john@gmail.com"

    def test_non_gmail_preserved(self):
        """Non-Gmail domains should preserve dots and plus."""
        assert canonicalize_email("john.doe@example.com") == "john.doe@example.com"
        assert canonicalize_email("john+work@example.com") == "john+work@example.com"

    def test_case_insensitive(self):
        """Email should be case-insensitive."""
        assert canonicalize_email("JOHN@GMAIL.COM") == "john@gmail.com"
        assert canonicalize_email("John.Doe@Example.Com") == "john.doe@example.com"

    def test_empty_and_invalid(self):
        """Empty and invalid emails handled gracefully."""
        assert canonicalize_email("") == ""
        assert canonicalize_email("invalid") == "invalid"


class TestDisposableEmailDetection:
    """Test disposable email domain blocking."""

    def test_known_disposable_domains_blocked(self):
        """Known disposable email domains should be detected."""
        assert is_disposable_email("test@mailinator.com") is True
        assert is_disposable_email("test@10minutemail.com") is True
        assert is_disposable_email("test@guerrillamail.com") is True
        assert is_disposable_email("test@tempmail.com") is True

    def test_legitimate_domains_allowed(self):
        """Legitimate email domains should be allowed."""
        assert is_disposable_email("test@gmail.com") is False
        assert is_disposable_email("test@example.com") is False
        assert is_disposable_email("test@company.io") is False

    def test_case_insensitive(self):
        """Domain check should be case-insensitive."""
        assert is_disposable_email("test@MAILINATOR.COM") is True

    def test_empty_and_invalid(self):
        """Empty and invalid emails handled gracefully."""
        assert is_disposable_email("") is False
        assert is_disposable_email("invalid") is False


class TestReferralCodeGeneration:
    """Test referral code generation and validation."""

    def test_code_format(self):
        """Generated codes should be 8 characters alphanumeric only."""
        code = generate_referral_code()
        assert len(code) == 8
        assert code.isalnum()  # New codes are always alphanumeric (no _ or -)

    def test_codes_unique(self):
        """Generated codes should be unique."""
        codes = {generate_referral_code() for _ in range(100)}
        assert len(codes) == 100

    def test_valid_code_format(self):
        """Valid codes should pass validation."""
        assert is_valid_referral_code("abc12345") is True
        assert is_valid_referral_code("ABCDEF12") is True
        assert is_valid_referral_code("a1b2c3") is True  # 6 chars min

    def test_invalid_code_format(self):
        """Invalid codes should fail validation."""
        assert is_valid_referral_code("") is False
        assert is_valid_referral_code("abc") is False  # Too short
        assert is_valid_referral_code("abc!@#$%") is False  # Special chars
        assert is_valid_referral_code("a" * 20) is False  # Too long


class TestSelfReferralPrevention:
    """Test self-referral detection."""

    def test_same_email_detected(self):
        """Same email should be detected as self-referral."""
        assert is_self_referral("john@example.com", "john@example.com") is True

    def test_gmail_alias_detected(self):
        """Gmail aliases should be detected as self-referral."""
        assert is_self_referral("john@gmail.com", "j.o.h.n@gmail.com") is True
        assert is_self_referral("john@gmail.com", "john+referral@gmail.com") is True
        assert is_self_referral("john@gmail.com", "j.o.h.n+work@gmail.com") is True

    def test_different_users_allowed(self):
        """Different users should not be flagged."""
        assert is_self_referral("john@gmail.com", "jane@gmail.com") is False
        assert is_self_referral("john@example.com", "john@different.com") is False


class TestMaskEmail:
    """Test email masking for privacy."""

    def test_normal_email_masked(self):
        """Normal emails should be masked correctly."""
        assert mask_email("john@example.com") == "jo**@example.com"
        assert mask_email("jane.doe@company.io") == "ja**@company.io"

    def test_short_local_part(self):
        """Short local parts handled correctly."""
        assert mask_email("j@example.com") == "j*@example.com"
        assert mask_email("jo@example.com") == "j*@example.com"  # 2 chars -> first char + *

    def test_invalid_email(self):
        """Invalid emails handled gracefully."""
        assert mask_email("") == "**@**.***"
        assert mask_email("invalid") == "**@**.***"


class TestConstants:
    """Test referral constants are correctly defined."""

    def test_reward_amounts(self):
        """Reward amounts should match spec."""
        assert REFERRAL_REWARDS["signup"] == 5000
        assert REFERRAL_REWARDS["paid"] == 25000
        assert REFERRAL_REWARDS["retained"] == 25000
        assert REFERRED_USER_BONUS == 10000

    def test_thresholds(self):
        """Thresholds should match spec."""
        assert ACTIVITY_THRESHOLD == 100
        assert BONUS_CAP == 500000
        assert LATE_ENTRY_DAYS == 14
        assert PENDING_TIMEOUT_DAYS == 90


class TestReferralCodeValidation:
    """Test backwards-compatible referral code validation."""

    def test_valid_code_with_underscore(self):
        """Codes with underscores should be valid (backwards compat)."""
        assert is_valid_referral_code("abc_1234") is True

    def test_valid_code_with_hyphen(self):
        """Codes with hyphens should be valid (backwards compat)."""
        assert is_valid_referral_code("abc-1234") is True

    def test_none_code_is_invalid(self):
        """None should be treated as invalid."""
        assert is_valid_referral_code(None) is False

    def test_min_length_boundary(self):
        """Exactly 6 characters should pass."""
        assert is_valid_referral_code("abcdef") is True

    def test_max_length_boundary(self):
        """Exactly 12 characters should pass."""
        assert is_valid_referral_code("abcdefghijkl") is True

    def test_13_chars_is_too_long(self):
        """13 characters should fail."""
        assert is_valid_referral_code("abcdefghijklm") is False


class TestBonusCredits:
    """Test bonus credit management with mocked DynamoDB."""

    @pytest.fixture
    def mock_table(self, mock_dynamodb):
        """Get the API keys table."""
        return mock_dynamodb.Table("pkgwatch-api-keys")

    def test_add_bonus_creates_record(self, mock_table):
        """Adding bonus to new user creates USER_META."""
        from shared.referral_utils import add_bonus_with_cap

        # Create minimal user
        mock_table.put_item(Item={"pk": "user_test1", "sk": "USER_META"})

        amount = add_bonus_with_cap("user_test1", 5000)

        assert amount == 5000

        # Verify the record
        response = mock_table.get_item(Key={"pk": "user_test1", "sk": "USER_META"})
        item = response["Item"]
        assert item["bonus_requests"] == 5000
        assert item["bonus_requests_lifetime"] == 5000

    def test_add_bonus_respects_cap(self, mock_table):
        """Adding bonus should respect lifetime cap."""
        from shared.referral_utils import add_bonus_with_cap

        # Create user at 490K lifetime
        mock_table.put_item(
            Item={
                "pk": "user_test2",
                "sk": "USER_META",
                "bonus_requests": 10000,
                "bonus_requests_lifetime": 490000,
            }
        )

        # Try to add 25K (should only add 10K)
        amount = add_bonus_with_cap("user_test2", 25000)

        assert amount == 10000  # Partial credit

        response = mock_table.get_item(Key={"pk": "user_test2", "sk": "USER_META"})
        item = response["Item"]
        assert item["bonus_requests_lifetime"] == 500000  # At cap

    def test_add_bonus_at_cap_returns_zero(self, mock_table):
        """Adding bonus at cap should return zero."""
        from shared.referral_utils import add_bonus_with_cap

        # Create user at cap
        mock_table.put_item(
            Item={
                "pk": "user_test3",
                "sk": "USER_META",
                "bonus_requests": 0,
                "bonus_requests_lifetime": 500000,
            }
        )

        amount = add_bonus_with_cap("user_test3", 5000)

        assert amount == 0


class TestGenerateUniqueReferralCode:
    """Test unique referral code generation."""

    def test_generates_unique_code(self, mock_dynamodb):
        """Should generate a unique code that doesn't exist."""
        from shared.referral_utils import generate_unique_referral_code

        code = generate_unique_referral_code()

        assert code is not None
        assert len(code) >= 6

    def test_multiple_codes_are_unique(self, mock_dynamodb):
        """Multiple generated codes should be unique."""
        from shared.referral_utils import generate_unique_referral_code

        codes = [generate_unique_referral_code() for _ in range(10)]
        unique_codes = set(codes)

        assert len(unique_codes) == 10


class TestUpdateReferralEventToCredited:
    """Test updating referral event status."""

    @pytest.fixture
    def pending_event(self, mock_dynamodb):
        """Create a pending referral event."""
        table = mock_dynamodb.Table("pkgwatch-referral-events")
        referrer_id = "user_referrer_credited"
        referred_id = "user_referred_credited"

        table.put_item(
            Item={
                "pk": referrer_id,
                "sk": f"{referred_id}#pending",
                "referrer_id": referrer_id,
                "referred_id": referred_id,
                "event_type": "pending",
                "reward_amount": 0,
            }
        )
        return table, referrer_id, referred_id

    def test_updates_event_to_credited(self, pending_event):
        """Should update pending event to credited with reward amount."""
        from shared.referral_utils import update_referral_event_to_credited

        table, referrer_id, referred_id = pending_event

        result = update_referral_event_to_credited(
            referrer_id=referrer_id,
            referred_id=referred_id,
            reward_amount=5000,
        )

        assert result is True

        # Verify event was updated
        response = table.get_item(
            Key={"pk": referrer_id, "sk": f"{referred_id}#signup"}
        )
        assert "Item" in response
        assert response["Item"]["event_type"] == "signup"
        assert response["Item"]["reward_amount"] == 5000


class TestMarkRetentionChecked:
    """Test marking retention as checked."""

    @pytest.fixture
    def paid_event_with_retention(self, mock_dynamodb):
        """Create a paid event needing retention check."""
        table = mock_dynamodb.Table("pkgwatch-referral-events")
        referrer_id = "user_referrer_retention"
        referred_id = "user_referred_retention"

        table.put_item(
            Item={
                "pk": referrer_id,
                "sk": f"{referred_id}#paid",
                "referrer_id": referrer_id,
                "referred_id": referred_id,
                "event_type": "paid",
                "needs_retention_check": "true",
                "retention_check_date": "2024-03-15T00:00:00Z",
            }
        )
        return table, referrer_id, referred_id

    def test_clears_retention_check_flag(self, paid_event_with_retention):
        """Should clear the needs_retention_check flag."""
        from shared.referral_utils import mark_retention_checked

        table, referrer_id, referred_id = paid_event_with_retention

        result = mark_retention_checked(referrer_id, referred_id)

        assert result is True

        # Verify flag was cleared
        response = table.get_item(
            Key={"pk": referrer_id, "sk": f"{referred_id}#paid"}
        )
        item = response.get("Item", {})
        assert item.get("needs_retention_check") is None


class TestGetBonusBalance:
    """Test getting bonus balance."""

    @pytest.fixture
    def user_with_bonus(self, mock_dynamodb):
        """Create a user with bonus balance."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_bonus_test",
                "sk": "USER_META",
                "bonus_requests": 15000,
                "bonus_requests_lifetime": 30000,
            }
        )
        return table

    def test_returns_bonus_balance(self, user_with_bonus):
        """Should return current bonus balance."""
        from shared.referral_utils import get_bonus_balance

        result = get_bonus_balance("user_bonus_test")

        assert result["bonus_requests"] == 15000
        assert result["bonus_requests_lifetime"] == 30000
        assert result["at_cap"] is False

    def test_returns_zero_for_no_bonus(self, mock_dynamodb):
        """Should return zero for user without bonus."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(Item={"pk": "user_no_bonus", "sk": "USER_META"})

        from shared.referral_utils import get_bonus_balance

        result = get_bonus_balance("user_no_bonus")

        assert result["bonus_requests"] == 0
        assert result["bonus_requests_lifetime"] == 0


class TestReferralCodeLookup:
    """Test referral code lookup via GSI."""

    @pytest.fixture
    def referrer_user(self, mock_dynamodb):
        """Create a referrer user with a referral code."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_referrer",
                "sk": "USER_META",
                "email": "referrer@example.com",
                "referral_code": "testcode",
            }
        )
        return table

    def test_lookup_existing_code(self, referrer_user):
        """Looking up existing code returns referrer info."""
        from shared.referral_utils import lookup_referrer_by_code

        result = lookup_referrer_by_code("testcode")

        assert result is not None
        assert result["user_id"] == "user_referrer"
        assert result["email"] == "referrer@example.com"

    def test_lookup_nonexistent_code(self, mock_dynamodb):
        """Looking up nonexistent code returns None."""
        from shared.referral_utils import lookup_referrer_by_code

        result = lookup_referrer_by_code("notacode")

        assert result is None

    def test_lookup_invalid_format(self, mock_dynamodb):
        """Looking up invalid format returns None."""
        from shared.referral_utils import lookup_referrer_by_code

        result = lookup_referrer_by_code("bad")  # Too short

        assert result is None


class TestReferralEvents:
    """Test referral event recording."""

    @pytest.fixture
    def events_table(self, mock_dynamodb):
        """Get the referral events table."""
        return mock_dynamodb.Table("pkgwatch-referral-events")

    def test_record_pending_event(self, events_table):
        """Recording a pending event creates record with TTL."""
        from shared.referral_utils import record_referral_event

        result = record_referral_event(
            referrer_id="user_ref",
            referred_id="user_new",
            event_type="pending",
            referred_email="new@example.com",
            reward_amount=0,
            ttl_days=90,
        )

        assert result is True

        response = events_table.get_item(
            Key={"pk": "user_ref", "sk": "user_new#pending"}
        )
        item = response["Item"]
        assert item["event_type"] == "pending"
        assert item["referred_email_masked"] == "ne**@example.com"
        assert "ttl" in item

    def test_record_paid_event_with_retention_check(self, events_table):
        """Recording a paid event sets retention check fields."""
        from shared.referral_utils import record_referral_event

        retention_date = (datetime.now(timezone.utc) + timedelta(days=60)).isoformat()

        result = record_referral_event(
            referrer_id="user_ref",
            referred_id="user_paid",
            event_type="paid",
            referred_email="paid@example.com",
            reward_amount=25000,
            retention_check_date=retention_date,
        )

        assert result is True

        response = events_table.get_item(
            Key={"pk": "user_ref", "sk": "user_paid#paid"}
        )
        item = response["Item"]
        assert item["needs_retention_check"] == "true"
        assert item["retention_check_date"] == retention_date


class TestReferrerStats:
    """Test referrer statistics management."""

    @pytest.fixture
    def user_with_meta(self, mock_dynamodb):
        """Create a user with USER_META."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_stats",
                "sk": "USER_META",
                "referral_total": 5,
                "referral_pending_count": 2,
                "referral_paid": 2,
                "referral_retained": 1,
                "referral_rewards_earned": 55000,
            }
        )
        return table

    def test_update_stats_increments(self, user_with_meta):
        """Stats should be incremented atomically."""
        from shared.referral_utils import update_referrer_stats

        result = update_referrer_stats(
            "user_stats",
            total_delta=1,
            pending_delta=1,
        )

        assert result is True

        response = user_with_meta.get_item(Key={"pk": "user_stats", "sk": "USER_META"})
        item = response["Item"]
        assert item["referral_total"] == 6
        assert item["referral_pending_count"] == 3

    def test_get_stats(self, user_with_meta):
        """Getting stats returns correct values."""
        from shared.referral_utils import get_referrer_stats

        stats = get_referrer_stats("user_stats")

        assert stats["total_referrals"] == 5
        assert stats["pending_referrals"] == 2
        assert stats["paid_conversions"] == 2
        assert stats["retained_conversions"] == 1
        assert stats["total_rewards_earned"] == 55000


class TestGetReferralEvents:
    """Test getting referral events for a user."""

    @pytest.fixture
    def referrer_with_events(self, mock_dynamodb):
        """Create a referrer with multiple referral events."""
        table = mock_dynamodb.Table("pkgwatch-referral-events")
        referrer_id = "user_referrer_events"

        # Add multiple events
        events = [
            {"pk": referrer_id, "sk": "user1#pending", "event_type": "pending", "referred_id": "user1", "created_at": "2024-01-15T10:00:00Z"},
            {"pk": referrer_id, "sk": "user2#signup", "event_type": "signup", "referred_id": "user2", "created_at": "2024-01-14T10:00:00Z"},
            {"pk": referrer_id, "sk": "user3#paid", "event_type": "paid", "referred_id": "user3", "created_at": "2024-01-13T10:00:00Z"},
        ]
        for event in events:
            table.put_item(Item=event)

        return table, referrer_id

    def test_returns_events_for_referrer(self, referrer_with_events):
        """Should return all referral events for a referrer."""
        from shared.referral_utils import get_referral_events

        table, referrer_id = referrer_with_events

        events = get_referral_events(referrer_id)

        assert len(events) == 3

    def test_returns_empty_for_no_events(self, mock_dynamodb):
        """Should return empty list when no events exist."""
        from shared.referral_utils import get_referral_events

        events = get_referral_events("user_no_events")

        assert events == []

    def test_respects_limit(self, referrer_with_events):
        """Should respect limit parameter."""
        from shared.referral_utils import get_referral_events

        table, referrer_id = referrer_with_events

        events = get_referral_events(referrer_id, limit=2)

        assert len(events) == 2


class TestCodeExists:
    """Test checking if referral code exists."""

    @pytest.fixture
    def existing_code(self, mock_dynamodb):
        """Create a user with a referral code."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_code_exists",
                "sk": "USER_META",
                "referral_code": "existcode",
                "email": "exists@example.com",
            }
        )
        return table

    def test_returns_true_for_existing_code(self, existing_code):
        """Should return True if code exists."""
        from shared.referral_utils import code_exists

        assert code_exists("existcode") is True

    def test_returns_false_for_nonexistent_code(self, mock_dynamodb):
        """Should return False if code doesn't exist."""
        from shared.referral_utils import code_exists

        assert code_exists("notacode1") is False


class TestLateEntry:
    """Test late entry eligibility checking."""

    @pytest.fixture
    def recent_user(self, mock_dynamodb):
        """Create a user created recently (within 14 days)."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        created = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        table.put_item(
            Item={
                "pk": "user_recent",
                "sk": "USER_META",
                "created_at": created,
            }
        )
        return table

    @pytest.fixture
    def old_user(self, mock_dynamodb):
        """Create a user created more than 14 days ago."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        created = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()
        table.put_item(
            Item={
                "pk": "user_old",
                "sk": "USER_META",
                "created_at": created,
            }
        )
        return table

    def test_recent_user_can_add(self, recent_user):
        """User within 14 days can add referral code."""
        from shared.referral_utils import can_add_late_referral

        can_add, deadline = can_add_late_referral("user_recent")

        assert can_add is True
        assert deadline is not None

    def test_old_user_cannot_add(self, old_user):
        """User after 14 days cannot add referral code."""
        from shared.referral_utils import can_add_late_referral

        can_add, deadline = can_add_late_referral("user_old")

        assert can_add is False
        assert deadline is None

    def test_referred_user_cannot_add(self, mock_dynamodb):
        """User who was already referred cannot add code."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        created = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        table.put_item(
            Item={
                "pk": "user_referred",
                "sk": "USER_META",
                "created_at": created,
                "referred_by": "user_someone",
            }
        )

        from shared.referral_utils import can_add_late_referral

        can_add, deadline = can_add_late_referral("user_referred")

        assert can_add is False


# ==========================================================================
# Tests for uncovered lines in referral_utils.py
# ==========================================================================


class TestLookupReferrerByCodeClientError:
    """Test lookup_referrer_by_code ClientError handling (lines 214-216)."""

    @patch("shared.referral_utils._get_dynamodb")
    def test_returns_none_on_client_error(self, mock_get_dynamodb):
        """Should return None when DynamoDB query raises ClientError."""
        from botocore.exceptions import ClientError
        from shared.referral_utils import lookup_referrer_by_code

        mock_table = MagicMock()
        mock_table.query.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "Service unavailable"}},
            "Query",
        )
        mock_dynamodb_resource = MagicMock()
        mock_dynamodb_resource.Table.return_value = mock_table
        mock_get_dynamodb.return_value = mock_dynamodb_resource

        result = lookup_referrer_by_code("validcde")

        assert result is None


class TestGenerateUniqueReferralCodeExhaustion:
    """Test generate_unique_referral_code RuntimeError (line 251)."""

    @patch("shared.referral_utils.code_exists")
    def test_raises_runtime_error_after_max_attempts(self, mock_code_exists):
        """Should raise RuntimeError when all attempts produce existing codes."""
        from shared.referral_utils import generate_unique_referral_code

        # Every generated code already exists
        mock_code_exists.return_value = True

        with pytest.raises(RuntimeError, match="Failed to generate unique referral code"):
            generate_unique_referral_code(max_attempts=5)

        # Verify it tried exactly 5 times
        assert mock_code_exists.call_count == 5


class TestAddBonusWithCapEdgeCases:
    """Test add_bonus_with_cap edge cases (lines 273, 300-301, 324, 347-352)."""

    def test_zero_amount_returns_zero(self, mock_dynamodb):
        """Adding 0 bonus should return 0 immediately (line 273)."""
        from shared.referral_utils import add_bonus_with_cap

        result = add_bonus_with_cap("user_test", 0)
        assert result == 0

    def test_negative_amount_returns_zero(self, mock_dynamodb):
        """Adding negative bonus should return 0 immediately (line 273)."""
        from shared.referral_utils import add_bonus_with_cap

        result = add_bonus_with_cap("user_test", -100)
        assert result == 0

    @patch("shared.referral_utils._get_dynamodb")
    def test_non_conditional_client_error_is_reraised(self, mock_get_dynamodb):
        """Non-ConditionalCheckFailedException should be re-raised (lines 300-301)."""
        from botocore.exceptions import ClientError
        from shared.referral_utils import add_bonus_with_cap

        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "Service unavailable"}},
            "UpdateItem",
        )
        mock_dynamodb_resource = MagicMock()
        mock_dynamodb_resource.Table.return_value = mock_table
        mock_get_dynamodb.return_value = mock_dynamodb_resource

        with pytest.raises(ClientError) as exc_info:
            add_bonus_with_cap("user_test", 5000)

        assert exc_info.value.response["Error"]["Code"] == "InternalServerError"

    @patch("shared.referral_utils._get_dynamodb")
    def test_concurrent_cap_fill_returns_zero(self, mock_get_dynamodb):
        """Should return 0 when a concurrent request fills the cap (lines 347-352)."""
        from botocore.exceptions import ClientError
        from shared.referral_utils import add_bonus_with_cap

        mock_table = MagicMock()

        # First update_item: ConditionalCheckFailedException (near cap)
        # get_item: user has 490K lifetime
        # Second update_item: ConditionalCheckFailedException (concurrent fill)
        conditional_error = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Condition not met"}},
            "UpdateItem",
        )
        mock_table.update_item.side_effect = [conditional_error, conditional_error]
        mock_table.get_item.return_value = {
            "Item": {"bonus_requests_lifetime": 490000}
        }

        mock_dynamodb_resource = MagicMock()
        mock_dynamodb_resource.Table.return_value = mock_table
        mock_get_dynamodb.return_value = mock_dynamodb_resource

        result = add_bonus_with_cap("user_test", 25000)
        assert result == 0

    @patch("shared.referral_utils._get_dynamodb")
    def test_partial_amount_zero_returns_zero(self, mock_get_dynamodb):
        """Should return 0 when remaining cap is exactly zero (line 324)."""
        from botocore.exceptions import ClientError
        from shared.referral_utils import add_bonus_with_cap, BONUS_CAP

        mock_table = MagicMock()

        # First update: ConditionalCheckFailedException
        conditional_error = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Condition not met"}},
            "UpdateItem",
        )
        mock_table.update_item.side_effect = conditional_error
        # get_item: user is exactly at cap
        mock_table.get_item.return_value = {
            "Item": {"bonus_requests_lifetime": BONUS_CAP}
        }

        mock_dynamodb_resource = MagicMock()
        mock_dynamodb_resource.Table.return_value = mock_table
        mock_get_dynamodb.return_value = mock_dynamodb_resource

        result = add_bonus_with_cap("user_test", 5000)
        assert result == 0

    @patch("shared.referral_utils._get_dynamodb")
    def test_retry_non_conditional_error_is_reraised(self, mock_get_dynamodb):
        """Non-ConditionalCheckFailed on retry should be re-raised (line 352)."""
        from botocore.exceptions import ClientError
        from shared.referral_utils import add_bonus_with_cap

        mock_table = MagicMock()

        conditional_error = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Condition not met"}},
            "UpdateItem",
        )
        internal_error = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "Service error"}},
            "UpdateItem",
        )
        # First update: conditional fail; retry update: internal error
        mock_table.update_item.side_effect = [conditional_error, internal_error]
        mock_table.get_item.return_value = {
            "Item": {"bonus_requests_lifetime": 490000}
        }

        mock_dynamodb_resource = MagicMock()
        mock_dynamodb_resource.Table.return_value = mock_table
        mock_get_dynamodb.return_value = mock_dynamodb_resource

        with pytest.raises(ClientError) as exc_info:
            add_bonus_with_cap("user_test", 25000)

        assert exc_info.value.response["Error"]["Code"] == "InternalServerError"


class TestConsumeBonusCredits:
    """Test consume_bonus_credits function (lines 369-385)."""

    @pytest.fixture
    def user_with_bonus(self, mock_dynamodb):
        """Create a user with bonus credits."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_consume",
                "sk": "USER_META",
                "bonus_requests": 10000,
                "bonus_requests_lifetime": 20000,
            }
        )
        return table

    def test_zero_amount_returns_true(self, mock_dynamodb):
        """Consuming 0 credits should return True (line 369-370)."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        from shared.referral_utils import consume_bonus_credits

        result = consume_bonus_credits("user_any", 0)
        assert result is True

    def test_negative_amount_returns_true(self, mock_dynamodb):
        """Consuming negative credits should return True (line 369-370)."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        from shared.referral_utils import consume_bonus_credits

        result = consume_bonus_credits("user_any", -5)
        assert result is True

    def test_successful_consumption(self, user_with_bonus):
        """Should consume credits and return True (lines 374-381)."""
        from shared.referral_utils import consume_bonus_credits

        result = consume_bonus_credits("user_consume", 5000)
        assert result is True

        # Verify balance was reduced
        response = user_with_bonus.get_item(Key={"pk": "user_consume", "sk": "USER_META"})
        item = response["Item"]
        assert item["bonus_requests"] == 5000

    def test_insufficient_credits_returns_false(self, user_with_bonus):
        """Should return False when insufficient credits (lines 382-384)."""
        from shared.referral_utils import consume_bonus_credits

        # Try to consume more than available
        result = consume_bonus_credits("user_consume", 50000)
        assert result is False

        # Verify balance unchanged
        response = user_with_bonus.get_item(Key={"pk": "user_consume", "sk": "USER_META"})
        item = response["Item"]
        assert item["bonus_requests"] == 10000

    def test_no_bonus_attribute_returns_false(self, mock_dynamodb):
        """Should return False when user has no bonus_requests attribute."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        from shared.referral_utils import consume_bonus_credits

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(Item={"pk": "user_no_bonus", "sk": "USER_META"})

        result = consume_bonus_credits("user_no_bonus", 1000)
        assert result is False

    @patch("shared.referral_utils._get_dynamodb")
    def test_non_conditional_error_is_reraised(self, mock_get_dynamodb):
        """Non-ConditionalCheckFailed errors should be re-raised (line 385)."""
        from botocore.exceptions import ClientError
        from shared.referral_utils import consume_bonus_credits

        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "Service unavailable"}},
            "UpdateItem",
        )
        mock_dynamodb_resource = MagicMock()
        mock_dynamodb_resource.Table.return_value = mock_table
        mock_get_dynamodb.return_value = mock_dynamodb_resource

        with pytest.raises(ClientError) as exc_info:
            consume_bonus_credits("user_test", 1000)

        assert exc_info.value.response["Error"]["Code"] == "InternalServerError"


class TestRecordReferralEventClientError:
    """Test record_referral_event ClientError handling (lines 476-478)."""

    @patch("shared.referral_utils._get_dynamodb")
    def test_returns_false_on_client_error(self, mock_get_dynamodb):
        """Should return False when DynamoDB put_item raises ClientError."""
        from botocore.exceptions import ClientError
        from shared.referral_utils import record_referral_event

        mock_table = MagicMock()
        mock_table.put_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "Service unavailable"}},
            "PutItem",
        )
        mock_dynamodb_resource = MagicMock()
        mock_dynamodb_resource.Table.return_value = mock_table
        mock_get_dynamodb.return_value = mock_dynamodb_resource

        result = record_referral_event(
            referrer_id="user_ref",
            referred_id="user_new",
            event_type="pending",
        )

        assert result is False


class TestUpdateReferralEventToCreditedClientError:
    """Test update_referral_event_to_credited ClientError handling (lines 521-523)."""

    @patch("shared.referral_utils._get_dynamodb")
    def test_returns_false_on_client_error(self, mock_get_dynamodb):
        """Should return False when DynamoDB operations raise ClientError."""
        from botocore.exceptions import ClientError
        from shared.referral_utils import update_referral_event_to_credited

        mock_table = MagicMock()
        mock_table.delete_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "Service unavailable"}},
            "DeleteItem",
        )
        mock_dynamodb_resource = MagicMock()
        mock_dynamodb_resource.Table.return_value = mock_table
        mock_get_dynamodb.return_value = mock_dynamodb_resource

        result = update_referral_event_to_credited(
            referrer_id="user_ref",
            referred_id="user_new",
            reward_amount=5000,
        )

        assert result is False


class TestMarkRetentionCheckedClientError:
    """Test mark_retention_checked ClientError handling (lines 545-547)."""

    @patch("shared.referral_utils._get_dynamodb")
    def test_returns_false_on_client_error(self, mock_get_dynamodb):
        """Should return False when DynamoDB update_item raises ClientError."""
        from botocore.exceptions import ClientError
        from shared.referral_utils import mark_retention_checked

        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "Service unavailable"}},
            "UpdateItem",
        )
        mock_dynamodb_resource = MagicMock()
        mock_dynamodb_resource.Table.return_value = mock_table
        mock_get_dynamodb.return_value = mock_dynamodb_resource

        result = mark_retention_checked("user_ref", "user_referred")

        assert result is False


class TestUpdateReferrerStatsEdgeCases:
    """Test update_referrer_stats edge cases (lines 592-593, 604, 615-617)."""

    def test_no_deltas_returns_true(self, mock_dynamodb):
        """Calling with no deltas should return True early (line 604)."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        from shared.referral_utils import update_referrer_stats

        # All deltas default to 0, so no update should happen
        result = update_referrer_stats("user_test")
        assert result is True

    def test_paid_delta_increments(self, mock_dynamodb):
        """Should update paid count when paid_delta is non-zero (lines 591-593)."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        from shared.referral_utils import update_referrer_stats

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_paid_stat",
                "sk": "USER_META",
                "referral_paid": 1,
            }
        )

        result = update_referrer_stats("user_paid_stat", paid_delta=1)
        assert result is True

        response = table.get_item(Key={"pk": "user_paid_stat", "sk": "USER_META"})
        item = response["Item"]
        assert item["referral_paid"] == 2

    def test_retained_delta_increments(self, mock_dynamodb):
        """Should update retained count when retained_delta is non-zero (lines 595-596)."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        from shared.referral_utils import update_referrer_stats

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_retained_stat",
                "sk": "USER_META",
                "referral_retained": 0,
            }
        )

        result = update_referrer_stats("user_retained_stat", retained_delta=1)
        assert result is True

        response = table.get_item(Key={"pk": "user_retained_stat", "sk": "USER_META"})
        item = response["Item"]
        assert item["referral_retained"] == 1

    def test_rewards_delta_increments(self, mock_dynamodb):
        """Should update rewards earned when rewards_delta is non-zero (lines 599-601)."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        from shared.referral_utils import update_referrer_stats

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_rewards_stat",
                "sk": "USER_META",
                "referral_rewards_earned": 5000,
            }
        )

        result = update_referrer_stats("user_rewards_stat", rewards_delta=25000)
        assert result is True

        response = table.get_item(Key={"pk": "user_rewards_stat", "sk": "USER_META"})
        item = response["Item"]
        assert item["referral_rewards_earned"] == 30000

    @patch("shared.referral_utils._get_dynamodb")
    def test_returns_false_on_client_error(self, mock_get_dynamodb):
        """Should return False when DynamoDB update_item raises ClientError (lines 615-617)."""
        from botocore.exceptions import ClientError
        from shared.referral_utils import update_referrer_stats

        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "Service unavailable"}},
            "UpdateItem",
        )
        mock_dynamodb_resource = MagicMock()
        mock_dynamodb_resource.Table.return_value = mock_table
        mock_get_dynamodb.return_value = mock_dynamodb_resource

        result = update_referrer_stats("user_test", total_delta=1)
        assert result is False


class TestCanAddLateReferralEdgeCases:
    """Test can_add_late_referral edge cases (lines 729, 741-742)."""

    def test_missing_created_at_returns_false(self, mock_dynamodb):
        """Should return (False, None) when created_at is missing (line 729)."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        from shared.referral_utils import can_add_late_referral

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_no_created_at",
                "sk": "USER_META",
                # No created_at field
            }
        )

        can_add, deadline = can_add_late_referral("user_no_created_at")
        assert can_add is False
        assert deadline is None

    def test_invalid_date_format_returns_false(self, mock_dynamodb):
        """Should return (False, None) when created_at has invalid format (lines 741-742)."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        from shared.referral_utils import can_add_late_referral

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_bad_date",
                "sk": "USER_META",
                "created_at": "not-a-valid-date-format",
            }
        )

        can_add, deadline = can_add_late_referral("user_bad_date")
        assert can_add is False
        assert deadline is None

    def test_nonexistent_user_returns_false(self, mock_dynamodb):
        """Should return (False, None) for user that doesn't exist."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        from shared.referral_utils import can_add_late_referral

        can_add, deadline = can_add_late_referral("user_nonexistent")
        assert can_add is False
        assert deadline is None


class TestGetReferralEventsClientError:
    """Test get_referral_events ClientError handling (lines 767-769)."""

    @patch("shared.referral_utils._get_dynamodb")
    def test_returns_empty_list_on_client_error(self, mock_get_dynamodb):
        """Should return empty list when DynamoDB query raises ClientError."""
        from botocore.exceptions import ClientError
        from shared.referral_utils import get_referral_events

        mock_table = MagicMock()
        mock_table.query.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "Service unavailable"}},
            "Query",
        )
        mock_dynamodb_resource = MagicMock()
        mock_dynamodb_resource.Table.return_value = mock_table
        mock_get_dynamodb.return_value = mock_dynamodb_resource

        result = get_referral_events("user_ref")

        assert result == []
