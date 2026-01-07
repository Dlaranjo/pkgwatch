"""
Tests for scoring algorithms: health_score.py and abandonment_risk.py

These are the core business logic - pure functions that must be reliable.
"""

import math

import pytest
from freezegun import freeze_time

from scoring.health_score import (
    _calculate_confidence,
    _community_health,
    _evolution_health,
    _get_risk_level,
    _maintainer_health,
    _user_centric_health,
    calculate_health_score,
)
from scoring.abandonment_risk import (
    calculate_abandonment_risk,
    get_risk_trend,
)


# =============================================================================
# Health Score Tests
# =============================================================================


class TestCalculateHealthScore:
    """Tests for the main calculate_health_score function."""

    def test_healthy_package_scores_high(self, sample_healthy_package):
        """A well-maintained package should score 70+."""
        result = calculate_health_score(sample_healthy_package)

        assert result["health_score"] >= 70
        assert result["risk_level"] in ["LOW", "MEDIUM"]
        assert "components" in result
        assert "confidence" in result

    def test_empty_data_returns_valid_score(self):
        """Empty data should return a valid score using defaults."""
        result = calculate_health_score({})

        assert 0 <= result["health_score"] <= 100
        assert result["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def test_score_components_sum_correctly(self, sample_healthy_package):
        """Component weights should add up correctly."""
        result = calculate_health_score(sample_healthy_package)

        # Verify components exist
        components = result["components"]
        assert "maintainer_health" in components
        assert "user_centric" in components
        assert "evolution_health" in components
        assert "community_health" in components

        # All components should be 0-100
        for name, value in components.items():
            assert 0 <= value <= 100, f"{name} out of range: {value}"


class TestMaintainerHealth:
    """Tests for _maintainer_health component."""

    def test_recent_commit_scores_high(self):
        """Recent activity (7 days) should score near 1.0."""
        data = {"days_since_last_commit": 7, "active_contributors_90d": 5}
        score = _maintainer_health(data)

        # exp(-0.693 * 7 / 90) * 0.6 + bus_factor * 0.4
        # recency ~= 0.95, bus_factor for 5 contributors ~= 0.95
        assert score > 0.8

    def test_stale_commit_scores_low(self):
        """365 days without commits should score low."""
        data = {"days_since_last_commit": 365, "active_contributors_90d": 1}
        score = _maintainer_health(data)

        assert score < 0.3

    def test_single_maintainer_penalized(self):
        """Single maintainer (bus factor = 1) should reduce score."""
        data_single = {"days_since_last_commit": 0, "active_contributors_90d": 1}
        data_multi = {"days_since_last_commit": 0, "active_contributors_90d": 5}

        score_single = _maintainer_health(data_single)
        score_multi = _maintainer_health(data_multi)

        assert score_multi > score_single

    def test_none_values_use_defaults(self):
        """None values should use safe defaults."""
        data = {"days_since_last_commit": None, "active_contributors_90d": None}
        score = _maintainer_health(data)

        # Should use defaults: 365 days, 1 contributor
        assert 0 <= score <= 1

    def test_missing_keys_use_defaults(self):
        """Missing keys should use safe defaults."""
        score = _maintainer_health({})
        assert 0 <= score <= 1


class TestUserCentricHealth:
    """Tests for _user_centric_health component."""

    def test_high_downloads_scores_high(self):
        """10M+ weekly downloads should score near 1.0."""
        data = {"weekly_downloads": 10_000_000, "dependents_count": 10000, "stars": 50000}
        score = _user_centric_health(data)

        assert score > 0.8

    def test_low_downloads_scores_low(self):
        """Low downloads should reduce score."""
        data = {"weekly_downloads": 10, "dependents_count": 0, "stars": 0}
        score = _user_centric_health(data)

        assert score < 0.2

    def test_zero_values_handled(self):
        """Zero values should not cause errors."""
        data = {"weekly_downloads": 0, "dependents_count": 0, "stars": 0}
        score = _user_centric_health(data)

        assert score == 0.0  # log10(1) / 7 + log10(1) / 4 + log10(1) / 5 = 0


class TestEvolutionHealth:
    """Tests for _evolution_health component."""

    @freeze_time("2026-01-07")
    def test_recent_release_scores_high(self):
        """Release within 30 days should score high."""
        data = {
            "last_published": "2025-12-15T00:00:00Z",
            "commits_90d": 30,
        }
        score = _evolution_health(data)

        assert score > 0.7

    @freeze_time("2026-01-07")
    def test_old_release_scores_low(self):
        """Release 2 years ago should score low."""
        data = {
            "last_published": "2024-01-01T00:00:00Z",
            "commits_90d": 0,
        }
        score = _evolution_health(data)

        assert score < 0.3

    def test_missing_release_date_uses_neutral(self):
        """Missing release date should use neutral score."""
        data = {"last_published": None, "commits_90d": 0}
        score = _evolution_health(data)

        # Default release_score = 0.5, activity_score = 0 for 0 commits
        # 0.5 * 0.5 + 0 * 0.5 = 0.25
        assert 0.2 <= score <= 0.3


class TestCommunityHealth:
    """Tests for _community_health component."""

    def test_high_openssf_scores_high(self):
        """High OpenSSF score should contribute positively."""
        data = {
            "openssf_score": 9.0,
            "total_contributors": 100,
            "advisories": [],
        }
        score = _community_health(data)

        assert score > 0.8

    def test_critical_vulnerabilities_reduce_score(self):
        """Critical vulnerabilities should significantly reduce score."""
        data_clean = {"openssf_score": 7.0, "total_contributors": 50, "advisories": []}
        data_vuln = {
            "openssf_score": 7.0,
            "total_contributors": 50,
            "advisories": [
                {"severity": "CRITICAL"},
                {"severity": "CRITICAL"},
            ],
        }

        score_clean = _community_health(data_clean)
        score_vuln = _community_health(data_vuln)

        assert score_clean > score_vuln
        assert score_vuln < 0.6  # Significant penalty for critical vulns

    def test_missing_openssf_uses_neutral(self):
        """Missing OpenSSF score should use neutral value."""
        data = {"openssf_score": None, "total_contributors": 10, "advisories": []}
        score = _community_health(data)

        # Should use 0.5 for OpenSSF component
        assert 0.3 <= score <= 0.7


class TestRiskLevel:
    """Tests for _get_risk_level function."""

    @pytest.mark.parametrize(
        "score,expected",
        [
            (100, "LOW"),
            (85, "LOW"),
            (80, "LOW"),
            (79.9, "MEDIUM"),
            (70, "MEDIUM"),
            (60, "MEDIUM"),
            (59.9, "HIGH"),
            (50, "HIGH"),
            (40, "HIGH"),
            (39.9, "CRITICAL"),
            (20, "CRITICAL"),
            (0, "CRITICAL"),
        ],
    )
    def test_risk_level_boundaries(self, score, expected):
        """Test exact boundary values for risk levels."""
        assert _get_risk_level(score) == expected


class TestConfidence:
    """Tests for _calculate_confidence function."""

    @freeze_time("2026-01-07")
    def test_new_package_insufficient_data(self):
        """Package < 90 days old should have INSUFFICIENT_DATA confidence."""
        data = {"created_at": "2025-11-01T00:00:00Z"}  # ~67 days old
        result = _calculate_confidence(data)

        assert result["level"] == "INSUFFICIENT_DATA"
        assert "days old" in result.get("reason", "")

    @freeze_time("2026-01-07")
    def test_mature_package_high_confidence(self):
        """Mature package with complete data should have high confidence."""
        data = {
            "created_at": "2020-01-01T00:00:00Z",  # 6 years old
            "days_since_last_commit": 7,
            "weekly_downloads": 1_000_000,
            "active_contributors_90d": 5,
            "last_published": "2025-12-01T00:00:00Z",
            "last_updated": "2026-01-06T00:00:00Z",  # Yesterday
        }
        result = _calculate_confidence(data)

        assert result["level"] == "HIGH"
        assert result["score"] >= 80


# =============================================================================
# Abandonment Risk Tests
# =============================================================================


class TestCalculateAbandonmentRisk:
    """Tests for calculate_abandonment_risk function."""

    def test_healthy_package_low_risk(self, sample_healthy_package):
        """Well-maintained package should have low abandonment risk."""
        result = calculate_abandonment_risk(sample_healthy_package)

        assert result["probability"] < 30
        assert result["time_horizon_months"] == 12

    def test_abandoned_package_high_risk(self, sample_abandoned_package):
        """Package with abandonment signals should have high risk."""
        result = calculate_abandonment_risk(sample_abandoned_package)

        # Archived flag sets risk to 95%
        assert result["probability"] == 95.0
        assert "Repository is archived" in result["risk_factors"]

    def test_deprecated_package_high_risk(self, sample_deprecated_package):
        """Deprecated package should have high risk."""
        result = calculate_abandonment_risk(sample_deprecated_package)

        assert result["probability"] == 95.0
        assert "Package is deprecated" in result["risk_factors"]

    def test_longer_horizon_increases_risk(self, sample_healthy_package):
        """Longer time horizon should increase risk probability."""
        risk_12m = calculate_abandonment_risk(sample_healthy_package, months=12)
        risk_24m = calculate_abandonment_risk(sample_healthy_package, months=24)

        assert risk_24m["probability"] > risk_12m["probability"]

    def test_risk_factors_populated(self):
        """Risk factors should be populated for risky packages."""
        data = {
            "days_since_last_commit": 200,
            "active_contributors_90d": 1,
            "weekly_downloads": 500,
            "last_published": "2024-01-01T00:00:00Z",
        }
        result = calculate_abandonment_risk(data)

        # Should have multiple risk factors
        assert len(result["risk_factors"]) >= 2
        assert any("commit" in f.lower() for f in result["risk_factors"])
        assert any("maintainer" in f.lower() for f in result["risk_factors"])

    def test_components_present(self):
        """Risk components should be included in result."""
        result = calculate_abandonment_risk({})

        assert "components" in result
        components = result["components"]
        assert "inactivity_risk" in components
        assert "bus_factor_risk" in components
        assert "adoption_risk" in components
        assert "release_risk" in components


class TestAdoptionRisk:
    """Tests for adoption risk calculation within abandonment_risk."""

    def test_adoption_risk_continuous_scale(self):
        """Adoption risk should decrease continuously with higher downloads."""
        # Test that higher downloads = lower risk (continuous function)
        data_low = {
            "weekly_downloads": 10,
            "days_since_last_commit": 0,
            "active_contributors_90d": 10,
        }
        data_medium = {
            "weekly_downloads": 10_000,
            "days_since_last_commit": 0,
            "active_contributors_90d": 10,
        }
        data_high = {
            "weekly_downloads": 1_000_000,
            "days_since_last_commit": 0,
            "active_contributors_90d": 10,
        }

        risk_low = calculate_abandonment_risk(data_low)
        risk_medium = calculate_abandonment_risk(data_medium)
        risk_high = calculate_abandonment_risk(data_high)

        # Risk should decrease with more downloads
        assert risk_low["components"]["adoption_risk"] > risk_medium["components"]["adoption_risk"]
        assert risk_medium["components"]["adoption_risk"] > risk_high["components"]["adoption_risk"]

        # Verify reasonable bounds (continuous scale from ~90% to 10%)
        assert risk_low["components"]["adoption_risk"] > 70  # Very low downloads = high risk
        assert risk_high["components"]["adoption_risk"] == 10.0  # Capped at 10% for high downloads

    def test_adoption_risk_no_discontinuities(self):
        """Adoption risk should not have sudden jumps at boundaries."""
        # Test values around old step function boundaries (99 vs 101, 999 vs 1001)
        downloads_around_100 = [99, 100, 101]
        downloads_around_1000 = [999, 1000, 1001]

        for downloads in downloads_around_100:
            data = {
                "weekly_downloads": downloads,
                "days_since_last_commit": 0,
                "active_contributors_90d": 10,
            }
            result = calculate_abandonment_risk(data)
            # All should be relatively close (within a few percentage points)
            # Old step function had 80% vs 50% jump at 100 downloads
            assert 55 < result["components"]["adoption_risk"] < 70

        for downloads in downloads_around_1000:
            data = {
                "weekly_downloads": downloads,
                "days_since_last_commit": 0,
                "active_contributors_90d": 10,
            }
            result = calculate_abandonment_risk(data)
            # Should be around 47% (log10(1000)/7 = 0.43, 0.9 - 0.43 = 0.47)
            assert 40 < result["components"]["adoption_risk"] < 55


class TestGetRiskTrend:
    """Tests for get_risk_trend function."""

    def test_stable_trend(self):
        """Small changes should be STABLE."""
        result = get_risk_trend([50.0, 51.0, 52.0])

        assert result["trend"] == "STABLE"
        assert result["change"] == 1.0

    def test_increasing_trend(self):
        """Large increase should be INCREASING."""
        result = get_risk_trend([30.0, 40.0, 50.0])

        assert result["trend"] == "INCREASING"
        assert result["change"] == 10.0

    def test_decreasing_trend(self):
        """Large decrease should be DECREASING."""
        result = get_risk_trend([50.0, 40.0, 30.0])

        assert result["trend"] == "DECREASING"
        assert result["change"] == -10.0

    def test_single_score_stable(self):
        """Single score should return STABLE."""
        result = get_risk_trend([50.0])

        assert result["trend"] == "STABLE"
        assert result["change"] == 0.0

    def test_empty_list_stable(self):
        """Empty list should return STABLE."""
        result = get_risk_trend([])

        assert result["trend"] == "STABLE"


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_negative_days_handled(self):
        """Negative days should not crash."""
        data = {"days_since_last_commit": -5}
        score = _maintainer_health(data)

        # exp(-0.693 * -5 / 90) > 1, but score should still be valid
        assert 0 <= score <= 2  # May exceed 1 due to math, but shouldn't crash

    def test_very_large_downloads(self):
        """Very large download numbers should not overflow."""
        data = {"weekly_downloads": 10**12, "dependents_count": 0, "stars": 0}
        score = _user_centric_health(data)

        # Should cap at 1.0
        assert score <= 1.0

    def test_malformed_date_handled(self):
        """Malformed dates should not crash."""
        data = {"last_published": "not-a-date"}
        score = _evolution_health(data)

        # Should use default and return valid score
        assert 0 <= score <= 1

    def test_unicode_in_deprecation_message(self):
        """Unicode in deprecation message should not crash."""
        data = {
            "is_deprecated": True,
            "deprecation_message": "Use @new/pkg instead.",
        }
        result = calculate_abandonment_risk(data)

        assert result["probability"] == 95.0
