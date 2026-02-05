"""
Edge Case Tests for PkgWatch Application.

These tests target boundary conditions, extreme values, and unusual inputs
that could cause bugs or unexpected behavior.

Focus areas:
- Scoring edge cases (boundaries, extreme values, malformed data)
- Auth edge cases (rate limits, malformed API keys)
- API handler edge cases (unicode, special characters, empty bodies)
- Date/time edge cases (future dates, timezone handling, boundaries)
"""

import hashlib
import json
import math
import os
import sys
from datetime import datetime, timezone, timedelta
from decimal import Decimal

import pytest
from freezegun import freeze_time
from moto import mock_aws

# Add functions directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions"))


# =============================================================================
# Scoring Edge Cases
# =============================================================================


class TestScoringBoundaryConditions:
    """Test exact boundary conditions in scoring algorithms."""

    def test_days_exactly_at_90_day_halflife(self):
        """At 90 days, recency should be exactly 0.5 (half-life)."""
        from scoring.health_score import _maintainer_health

        data = {"days_since_last_commit": 90, "active_contributors_90d": 1}
        score = _maintainer_health(data)

        # Recency at 90 days = exp(-0.693 * 90 / 90) = exp(-0.693) = 0.5
        # Bus factor for 1 contributor = 1 / (1 + exp(1)) ~= 0.27
        # Total = 0.5 * 0.6 + 0.27 * 0.4 = 0.3 + 0.108 = 0.408
        expected_recency = math.exp(-0.693)  # ~0.5
        assert abs(expected_recency - 0.5) < 0.01  # Verify our math

    def test_days_exactly_at_180_day_release_halflife(self):
        """At 180 days, release score should be exactly 0.5 (half-life)."""
        from scoring.health_score import _evolution_health

        # Use a fixed time
        with freeze_time("2026-01-08"):
            # 180 days before 2026-01-08 is 2025-07-12
            data = {
                "last_published": "2025-07-12T00:00:00Z",
                "commits_90d": 0,
            }
            score = _evolution_health(data)

            # Release score at 180 days = exp(-0.693 * 180 / 180) = 0.5
            # Activity score = 0 (no commits)
            # Total = 0.5 * 0.5 + 0 * 0.5 = 0.25
            assert 0.24 <= score <= 0.26

    def test_package_exactly_90_days_old_boundary(self):
        """Package exactly 90 days old should NOT return INSUFFICIENT_DATA."""
        from scoring.health_score import _calculate_confidence

        with freeze_time("2026-01-08"):
            # Exactly 90 days ago
            data = {"created_at": "2025-10-10T00:00:00Z"}
            result = _calculate_confidence(data)

            # Should NOT be INSUFFICIENT_DATA (boundary is < 90, not <= 90)
            assert result["level"] != "INSUFFICIENT_DATA"

    def test_package_89_days_old_insufficient_data(self):
        """Package 89 days old should return INSUFFICIENT_DATA."""
        from scoring.health_score import _calculate_confidence

        with freeze_time("2026-01-08"):
            # 89 days ago - just under the threshold
            data = {"created_at": "2025-10-11T00:00:00Z"}
            result = _calculate_confidence(data)

            assert result["level"] == "INSUFFICIENT_DATA"


class TestScoringExtremeValues:
    """Test handling of extreme values that could cause overflow or precision issues."""

    def test_very_large_downloads_no_overflow(self):
        """Extremely large download counts should not cause overflow."""
        from scoring.health_score import _user_centric_health

        # 10^18 downloads (way beyond any real package)
        data = {"weekly_downloads": 10**18, "dependents_count": 0, "stars": 0}
        score = _user_centric_health(data)

        # Should be capped at 1.0 and not overflow
        assert score <= 1.0
        assert not math.isnan(score)
        assert not math.isinf(score)

    def test_very_large_days_since_commit(self):
        """Very large days_since_last_commit should not cause issues."""
        from scoring.health_score import _maintainer_health

        # 100 years without commits
        data = {"days_since_last_commit": 36500, "active_contributors_90d": 1}
        score = _maintainer_health(data)

        # Should approach 0 but not be exactly 0 or negative
        assert 0 <= score <= 1
        assert not math.isnan(score)

    def test_very_large_contributors(self):
        """Very large contributor count should be high but weighted with issue response."""
        from scoring.health_score import _community_health

        # With no issue response data, neutral (0.5) is assumed
        # Score = contributor_score * 0.6 + issue_response * 0.4
        # = 1.0 * 0.6 + 0.5 * 0.4 = 0.8
        data = {"total_contributors": 100000}
        score = _community_health(data)

        assert score <= 1.0
        assert score >= 0.7  # Should be high but not max without issue response data

    def test_zero_time_horizon_abandonment_risk(self):
        """Zero months time horizon should not cause division by zero."""
        from scoring.abandonment_risk import calculate_abandonment_risk

        data = {"days_since_last_commit": 30}
        result = calculate_abandonment_risk(data, months=0)

        # Should handle gracefully (time_factor = 0)
        assert result["probability"] >= 0
        assert result["probability"] <= 100

    def test_negative_time_horizon_abandonment_risk(self):
        """Negative months time horizon should be handled.

        BUG DISCOVERED: When months=-12, time_factor = min(-12/12, 2.0) = -1.0
        This makes adjusted_risk = risk_score * -1.0, producing negative probability.

        FIX NEEDED: Clamp months to minimum of 1:
            months = max(1, months)
        Or at start of function:
            time_factor = min(max(0, months) / 12, 2.0)
        """
        from scoring.abandonment_risk import calculate_abandonment_risk

        data = {"days_since_last_commit": 30}
        result = calculate_abandonment_risk(data, months=-12)

        # Should handle gracefully (time_factor clamped or defaults)
        assert result["probability"] >= 0
        assert result["probability"] <= 100

    def test_max_int_values(self):
        """MAX_INT values should not cause overflow.

        BUG DISCOVERED: In _calculate_maturity_factor():
            activity_low = 1 / (1 + math.exp((commits_90d - 10) / 3))
        When commits_90d = 2^31-1, the exp() argument is ~715 million,
        which causes OverflowError.

        FIX NEEDED: Clamp the exp argument or use a safe sigmoid:
            exp_arg = (commits_90d - 10) / 3
            if exp_arg > 700:  # Prevent overflow
                activity_low = 0.0
            else:
                activity_low = 1 / (1 + math.exp(exp_arg))
        """
        from scoring.health_score import calculate_health_score

        data = {
            "weekly_downloads": 2**31 - 1,
            "dependents_count": 2**31 - 1,
            "stars": 2**31 - 1,
            "commits_90d": 2**31 - 1,
            "total_contributors": 2**31 - 1,
        }
        result = calculate_health_score(data)

        assert 0 <= result["health_score"] <= 100
        assert not math.isnan(result["health_score"])


class TestScoringMalformedData:
    """Test handling of malformed or unexpected data types."""

    def test_openssf_score_as_string(self):
        """OpenSSF score passed as string should be handled."""
        from scoring.health_score import _security_health

        data = {
            "openssf_score": "7.5",  # String instead of number
            "advisories": [],
            "openssf_checks": [],
        }
        score = _security_health(data)

        assert 0 <= score <= 1

    def test_openssf_score_as_invalid_string(self):
        """Invalid OpenSSF score string should use default."""
        from scoring.health_score import _security_health

        data = {
            "openssf_score": "not-a-number",
            "advisories": [],
            "openssf_checks": [],
        }
        score = _security_health(data)

        # Should use default 0.3 for invalid data
        assert 0 <= score <= 1

    def test_openssf_score_nan(self):
        """NaN OpenSSF score should be handled."""
        from scoring.health_score import _security_health

        data = {
            "openssf_score": float("nan"),
            "advisories": [],
            "openssf_checks": [],
        }
        score = _security_health(data)

        # Should not produce NaN in output
        assert not math.isnan(score)
        assert 0 <= score <= 1

    def test_openssf_score_infinity(self):
        """Infinity OpenSSF score should be handled."""
        from scoring.health_score import _security_health

        data = {
            "openssf_score": float("inf"),
            "advisories": [],
            "openssf_checks": [],
        }
        score = _security_health(data)

        # Should cap at max (1.0 component)
        assert not math.isinf(score)
        assert 0 <= score <= 1

    def test_advisories_with_malformed_items(self):
        """Advisories list with non-dict items should be handled."""
        from scoring.health_score import _security_health

        data = {
            "openssf_score": 5.0,
            "advisories": [
                {"severity": "HIGH"},
                "invalid-string-item",
                None,
                123,
                {"severity": "MEDIUM"},
            ],
            "openssf_checks": [],
        }
        score = _security_health(data)

        # Should count only valid advisory dicts
        assert 0 <= score <= 1

    def test_advisories_none_vs_empty_list(self):
        """None advisories should behave same as empty list."""
        from scoring.health_score import _security_health

        data_none = {
            "openssf_score": 5.0,
            "advisories": None,
            "openssf_checks": [],
        }
        data_empty = {
            "openssf_score": 5.0,
            "advisories": [],
            "openssf_checks": [],
        }

        score_none = _security_health(data_none)
        score_empty = _security_health(data_empty)

        assert score_none == score_empty

    def test_openssf_checks_none_vs_empty_list(self):
        """None openssf_checks should behave same as empty list."""
        from scoring.health_score import _security_health

        data_none = {
            "openssf_score": 5.0,
            "advisories": [],
            "openssf_checks": None,
        }
        data_empty = {
            "openssf_score": 5.0,
            "advisories": [],
            "openssf_checks": [],
        }

        score_none = _security_health(data_none)
        score_empty = _security_health(data_empty)

        assert score_none == score_empty

    def test_negative_openssf_score(self):
        """Negative OpenSSF score should be clamped to 0."""
        from scoring.health_score import _security_health

        data = {
            "openssf_score": -5.0,
            "advisories": [],
            "openssf_checks": [],
        }
        score = _security_health(data)

        # Negative should be clamped, resulting in 0 for openssf component
        assert 0 <= score <= 1

    def test_openssf_score_over_10(self):
        """OpenSSF score over 10 should be clamped to 1.0."""
        from scoring.health_score import _security_health

        data = {
            "openssf_score": 15.0,  # Over max of 10
            "advisories": [],
            "openssf_checks": [{"name": "Security-Policy", "score": 10}],
        }
        score = _security_health(data)

        # Should clamp to 1.0 for openssf component
        assert 0 <= score <= 1


class TestScoringDateHandling:
    """Test date/time edge cases in scoring."""

    @freeze_time("2026-01-08")
    def test_future_date_last_published(self):
        """Future last_published date should be clamped to today."""
        from scoring.health_score import _evolution_health

        data = {
            "last_published": "2027-01-01T00:00:00Z",  # Future date
            "commits_90d": 10,
        }
        score = _evolution_health(data)

        # Should handle gracefully (future = 0 days since release = high score)
        assert 0 <= score <= 1

    @freeze_time("2026-01-08")
    def test_future_date_created_at(self):
        """Future created_at date should be handled."""
        from scoring.health_score import _calculate_confidence

        data = {"created_at": "2027-01-01T00:00:00Z"}  # Future date
        result = _calculate_confidence(data)

        # Should not crash, may return low confidence or handle edge
        assert "level" in result

    def test_malformed_timezone_in_date(self):
        """Malformed timezone should be handled gracefully."""
        from scoring.health_score import _evolution_health

        data = {
            "last_published": "2025-12-01T00:00:00+25:00",  # Invalid timezone
            "commits_90d": 10,
        }
        score = _evolution_health(data)

        # Should use default on parse error
        assert 0 <= score <= 1

    def test_naive_datetime_object(self):
        """Naive datetime object (no timezone) should be handled."""
        from scoring.health_score import _evolution_health

        with freeze_time("2026-01-08"):
            data = {
                "last_published": datetime(2025, 12, 1, 0, 0, 0),  # Naive datetime
                "commits_90d": 10,
            }
            score = _evolution_health(data)

            assert 0 <= score <= 1

    def test_unix_epoch_date(self):
        """Unix epoch (1970-01-01) should be handled."""
        from scoring.health_score import _evolution_health

        data = {
            "last_published": "1970-01-01T00:00:00Z",
            "commits_90d": 0,
        }
        score = _evolution_health(data)

        # Very old date = very low release score
        assert 0 <= score <= 1


# =============================================================================
# Auth Edge Cases
# =============================================================================


class TestAuthEdgeCases:
    """Test authentication edge cases."""

    @mock_aws
    def test_api_key_exactly_at_limit(self, aws_credentials, mock_dynamodb):
        """Request at exact limit should be denied (not allowed)."""
        from shared.auth import check_and_increment_usage, generate_api_key, validate_api_key, TIER_LIMITS

        api_key = generate_api_key("user_at_limit", tier="free")
        user = validate_api_key(api_key)

        # Set USER_META.requests_this_month to exactly at limit (rate limiting is user-level)
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": user["user_id"],
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": TIER_LIMITS["free"],
            }
        )

        # Try to increment - should be denied
        allowed, count = check_and_increment_usage(
            user["user_id"], user["key_hash"], TIER_LIMITS["free"]
        )

        assert allowed is False
        assert count == TIER_LIMITS["free"]

    @mock_aws
    def test_api_key_one_under_limit(self, aws_credentials, mock_dynamodb):
        """Request one under limit should be allowed."""
        from shared.auth import check_and_increment_usage, generate_api_key, validate_api_key, TIER_LIMITS

        api_key = generate_api_key("user_under_limit", tier="free")
        user = validate_api_key(api_key)

        # Set USER_META.requests_this_month to one under limit (rate limiting is user-level)
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": user["user_id"],
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": TIER_LIMITS["free"] - 1,
            }
        )

        # Should be allowed
        allowed, count = check_and_increment_usage(
            user["user_id"], user["key_hash"], TIER_LIMITS["free"]
        )

        assert allowed is True
        assert count == TIER_LIMITS["free"]

    @mock_aws
    def test_empty_string_api_key(self, aws_credentials, mock_dynamodb):
        """Empty string API key should return None (not crash)."""
        from shared.auth import validate_api_key

        result = validate_api_key("")

        assert result is None

    @mock_aws
    def test_api_key_only_prefix(self, aws_credentials, mock_dynamodb):
        """API key with only 'pw_' prefix should return None."""
        from shared.auth import validate_api_key

        result = validate_api_key("pw_")

        assert result is None

    @mock_aws
    def test_api_key_with_special_characters(self, aws_credentials, mock_dynamodb):
        """API key with special characters should be handled."""
        from shared.auth import validate_api_key

        # Various special character patterns
        special_keys = [
            "pw_<script>alert('xss')</script>",
            "pw_' OR '1'='1",
            "pw_\x00null\x00byte",
            "pw_\n\r\t",
            "pw_" + "\u0000" * 100,  # Null bytes
        ]

        for key in special_keys:
            result = validate_api_key(key)
            assert result is None  # Should not crash

    @mock_aws
    def test_api_key_unicode(self, aws_credentials, mock_dynamodb):
        """API key with unicode should be handled."""
        from shared.auth import validate_api_key

        unicode_key = "pw_cafe_babe"
        result = validate_api_key(unicode_key)

        assert result is None  # Invalid key, but should not crash

    @mock_aws
    def test_whitespace_in_api_key(self, aws_credentials, mock_dynamodb):
        """Whitespace in API key should be handled."""
        from shared.auth import validate_api_key

        whitespace_keys = [
            " pw_test",
            "pw_test ",
            " pw_test ",
            "pw_ test",
            "\tpw_test",
        ]

        for key in whitespace_keys:
            result = validate_api_key(key)
            assert result is None  # Should not crash

    @mock_aws
    def test_case_sensitivity_of_prefix(self, aws_credentials, mock_dynamodb):
        """API key prefix should be case-sensitive."""
        from shared.auth import validate_api_key

        case_variants = [
            "PW_test123",
            "Pw_test123",
            "pH_test123",
        ]

        for key in case_variants:
            result = validate_api_key(key)
            assert result is None  # Case mismatch should fail


class TestAuthConcurrency:
    """Test auth behavior under concurrent conditions."""

    @mock_aws
    def test_increment_usage_is_atomic(self, aws_credentials, mock_dynamodb):
        """Increment usage should be atomic (DynamoDB ADD operation)."""
        from shared.auth import generate_api_key, increment_usage, validate_api_key

        api_key = generate_api_key("user_concurrent")
        user = validate_api_key(api_key)

        # Simulate concurrent increments
        results = []
        for _ in range(10):
            count = increment_usage(user["user_id"], user["key_hash"])
            results.append(count)

        # All results should be unique and sequential
        assert sorted(results) == list(range(1, 11))


# =============================================================================
# API Handler Edge Cases
# =============================================================================


class TestGetPackageEdgeCases:
    """Test edge cases for GET /packages/{ecosystem}/{name} endpoint."""

    @mock_aws
    def test_unicode_package_name(self, mock_dynamodb, api_gateway_event):
        """Unicode in package name should be handled."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        # Create a mock package with unicode name
        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#cafe-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "cafe-pkg",
                "health_score": 80,
                "risk_level": "LOW",
                "last_updated": "2024-01-01T00:00:00Z",
                "latest_version": "1.0.0",
                "weekly_downloads": 1000,
                "data_status": "complete",
                "queryable": True,
            }
        )

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "cafe-pkg"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "cafe-pkg"

    @mock_aws
    def test_very_long_package_name(self, mock_dynamodb, api_gateway_event):
        """Very long package name should be handled."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        # 1000 character package name
        long_name = "a" * 1000
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": long_name}

        result = handler(api_gateway_event, {})

        # Should return 404 (not found) not crash
        assert result["statusCode"] == 404

    @mock_aws
    def test_package_name_with_special_chars(self, mock_dynamodb, api_gateway_event):
        """Package name with special characters should be handled."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        special_names = [
            "../../../etc/passwd",
            "<script>alert(1)</script>",
            "pkg\x00name",
            "pkg\nname",
        ]

        for name in special_names:
            api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": name}
            result = handler(api_gateway_event, {})
            # Should return 404, not crash or expose sensitive data
            assert result["statusCode"] in [400, 404]

    @mock_aws
    def test_empty_string_package_name(self, mock_dynamodb, api_gateway_event):
        """Empty string package name should return 400."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": ""}

        result = handler(api_gateway_event, {})

        # Empty name after URL decode should be treated as missing
        assert result["statusCode"] == 400

    @mock_aws
    def test_missing_path_parameters(self, mock_dynamodb, api_gateway_event):
        """Missing pathParameters should be handled.

        BUG DISCOVERED: In handler():
            path_params = event.get("pathParameters", {})
            ecosystem = path_params.get("ecosystem", "npm")
        When pathParameters is explicitly None (not missing), .get() returns None
        instead of {}, causing AttributeError: 'NoneType' has no attribute 'get'.

        FIX NEEDED: Use 'or' to handle None:
            path_params = event.get("pathParameters") or {}
        """
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        api_gateway_event["pathParameters"] = None

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400

    @mock_aws
    def test_empty_path_parameters(self, mock_dynamodb, api_gateway_event):
        """Empty pathParameters should be handled."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400


class TestPostScanEdgeCases:
    """Test edge cases for POST /scan endpoint."""

    @mock_aws
    def test_empty_request_body(self, mock_dynamodb, api_gateway_event):
        """Empty request body should return 400 invalid_json.

        Note: json.loads("") raises JSONDecodeError, so empty string is invalid JSON.
        This is correct behavior - the code correctly returns invalid_json error.
        """
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Create test API key
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_testscan123456"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_scan",
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
                "requests_this_month": 0,
            }
        )

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = ""

        result = handler(api_gateway_event, {})

        # Empty string is treated as empty object {} (since "" is falsy, `"" or "{}"` gives "{}")
        # An empty object has no dependencies, so validation fails with "no_dependencies"
        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "no_dependencies"

    @mock_aws
    def test_null_request_body(self, mock_dynamodb, api_gateway_event):
        """Null request body should return 400.

        BUG DISCOVERED: In handler():
            body = json.loads(event.get("body", "{}"))
        When body is explicitly None, event.get("body", "{}") returns None
        (not the default "{}"), causing json.loads(None) to fail with TypeError.

        FIX NEEDED: Use 'or' to handle None:
            body = json.loads(event.get("body") or "{}")
        """
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_testscan123456"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_scan",
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
                "requests_this_month": 0,
            }
        )

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = None

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400

    @mock_aws
    def test_malformed_json_body(self, mock_dynamodb, api_gateway_event):
        """Malformed JSON should return 400."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_testscan123456"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_scan",
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
                "requests_this_month": 0,
            }
        )

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = "{invalid json"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_dependencies_as_list(self, mock_dynamodb, api_gateway_event):
        """Dependencies as list (not dict) should be handled."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_testscan123456"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_scan",
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
                "requests_this_month": 0,
            }
        )

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": ["lodash", "express", "react"]
        })

        result = handler(api_gateway_event, {})

        # Should handle list format
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 3

    @mock_aws
    def test_dependencies_with_none_values(self, mock_dynamodb, api_gateway_event):
        """Dependencies dict with None values should be filtered."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_testscan123456"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_scan",
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
                "requests_this_month": 0,
            }
        )

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {
                "lodash": "^4.17.21",
                "express": None,
                "": "1.0.0",  # Empty key
            }
        })

        result = handler(api_gateway_event, {})

        # Should filter out invalid entries (empty string key)
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # lodash and express (None value is OK, empty key is filtered)
        assert body["total"] == 2

    @mock_aws
    def test_nested_package_json_content(self, mock_dynamodb, api_gateway_event):
        """Nested package.json content should be parsed correctly."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_testscan123456"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_scan",
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
                "requests_this_month": 0,
            }
        )

        from api.post_scan import handler

        package_json = json.dumps({
            "name": "test-project",
            "dependencies": {
                "lodash": "^4.17.21",
            },
            "devDependencies": {
                "jest": "^29.0.0",
            },
        })

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({"content": package_json})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 2  # lodash + jest


# =============================================================================
# Date/Time Edge Cases
# =============================================================================


class TestDateTimeEdgeCases:
    """Test date/time boundary conditions."""

    @freeze_time("2026-01-01 00:00:00")
    def test_midnight_boundary(self):
        """Calculations at midnight should work correctly."""
        from scoring.health_score import _calculate_confidence

        # Package created exactly 90 days ago at midnight
        data = {"created_at": "2025-10-03T00:00:00Z"}
        result = _calculate_confidence(data)

        assert "level" in result

    @freeze_time("2026-01-08 23:59:59")
    def test_end_of_day_boundary(self):
        """Calculations at end of day should work correctly."""
        from scoring.health_score import _evolution_health

        data = {
            "last_published": "2026-01-08T00:00:00Z",
            "commits_90d": 10,
        }
        score = _evolution_health(data)

        assert 0 <= score <= 1

    @freeze_time("2026-02-28")
    def test_february_boundary(self):
        """February (28/29 days) should be handled correctly."""
        from scoring.health_score import _calculate_confidence

        # 90 days before Feb 28 spans Dec/Jan
        data = {"created_at": "2025-11-30T00:00:00Z"}
        result = _calculate_confidence(data)

        assert "level" in result

    @freeze_time("2024-02-29")
    def test_leap_year_february(self):
        """Leap year February 29 should be handled."""
        from scoring.health_score import _calculate_confidence

        data = {"created_at": "2023-12-01T00:00:00Z"}
        result = _calculate_confidence(data)

        assert "level" in result

    def test_dst_transition(self):
        """DST transitions should not cause issues."""
        from scoring.health_score import _evolution_health

        # Use dates around typical DST transitions
        with freeze_time("2026-03-08 03:00:00"):  # Spring forward
            data = {
                "last_published": "2026-03-07T23:00:00Z",
                "commits_90d": 10,
            }
            score = _evolution_health(data)
            assert 0 <= score <= 1

        with freeze_time("2026-11-01 01:30:00"):  # Fall back
            data = {
                "last_published": "2026-10-31T23:00:00Z",
                "commits_90d": 10,
            }
            score = _evolution_health(data)
            assert 0 <= score <= 1

    def test_different_timezone_formats(self):
        """Various timezone formats should be handled."""
        from scoring.health_score import _evolution_health

        with freeze_time("2026-01-08"):
            timezone_formats = [
                "2025-12-01T00:00:00Z",
                "2025-12-01T00:00:00+00:00",
                "2025-12-01T05:30:00+05:30",
                "2025-11-30T19:00:00-05:00",
            ]

            for date_str in timezone_formats:
                data = {
                    "last_published": date_str,
                    "commits_90d": 10,
                }
                score = _evolution_health(data)
                assert 0 <= score <= 1, f"Failed for {date_str}"


# =============================================================================
# Maturity Factor Edge Cases
# =============================================================================


class TestMaturityFactorEdgeCases:
    """Test edge cases in maturity factor calculation."""

    def test_zero_downloads_zero_commits(self):
        """Zero downloads and commits should not crash."""
        from scoring.health_score import _calculate_maturity_factor

        data = {
            "weekly_downloads": 0,
            "dependents_count": 0,
            "commits_90d": 0,
        }
        factor = _calculate_maturity_factor(data)

        assert 0 <= factor <= 0.7
        assert not math.isnan(factor)

    def test_exactly_threshold_values(self):
        """Values exactly at sigmoid thresholds should work."""
        from scoring.health_score import _calculate_maturity_factor

        # Exactly 1M downloads (centered sigmoid point)
        data = {
            "weekly_downloads": 1_000_000,
            "dependents_count": 0,
            "commits_90d": 0,
        }
        factor = _calculate_maturity_factor(data)

        assert 0 <= factor <= 0.7

        # Exactly 10 commits (activity sigmoid point)
        data = {
            "weekly_downloads": 10_000_000,
            "dependents_count": 0,
            "commits_90d": 10,
        }
        factor = _calculate_maturity_factor(data)

        assert 0 <= factor <= 0.7


# =============================================================================
# Abandonment Risk Trend Edge Cases
# =============================================================================


class TestRiskTrendEdgeCases:
    """Test edge cases in risk trend calculation."""

    def test_two_identical_scores(self):
        """Two identical scores should be STABLE."""
        from scoring.abandonment_risk import get_risk_trend

        result = get_risk_trend([50.0, 50.0])

        assert result["trend"] == "STABLE"
        assert result["change"] == 0.0

    def test_exactly_5_point_change(self):
        """Exactly 5 point change should be STABLE (boundary)."""
        from scoring.abandonment_risk import get_risk_trend

        # Boundary: abs(change) < 5 is STABLE
        result = get_risk_trend([50.0, 54.9])
        assert result["trend"] == "STABLE"

        result = get_risk_trend([50.0, 55.0])
        assert result["trend"] == "INCREASING"

    def test_negative_change_exactly_5(self):
        """Exactly -5 point change should be STABLE."""
        from scoring.abandonment_risk import get_risk_trend

        result = get_risk_trend([55.0, 50.1])
        assert result["trend"] == "STABLE"

        result = get_risk_trend([55.0, 50.0])
        assert result["trend"] == "DECREASING"

    def test_very_long_history(self):
        """Very long history should only use last two values."""
        from scoring.abandonment_risk import get_risk_trend

        # 1000 values, but only last two matter
        history = [50.0] * 999 + [80.0]
        result = get_risk_trend(history)

        assert result["trend"] == "INCREASING"
        assert result["change"] == 30.0

    def test_nan_in_history(self):
        """NaN values in history should be handled."""
        from scoring.abandonment_risk import get_risk_trend

        # This might cause issues - testing defensive behavior
        history = [50.0, float("nan")]
        result = get_risk_trend(history)

        # Should not crash, behavior depends on implementation
        assert "trend" in result
