"""
Scoring Validation Tests - Backtesting against real package histories.

These tests validate the health score and abandonment risk algorithms
against real packages with known outcomes. They are framed as validation
EXAMPLES, not statistical proof. A small set of case studies cannot prove
accuracy, but they can catch obviously wrong behavior.

Test categories:
1. Abandoned packages should score below healthy ones
2. Healthy packages should score above abandoned ones
3. Component scores should reflect known characteristics
4. Abandonment risk should flag known pre-abandonment states

IMPORTANT: These tests freeze time to the evaluation_date in each fixture,
because the scoring functions use datetime.now() to compute age, freshness,
and release recency.
"""

import pytest
from freezegun import freeze_time

from scoring.abandonment_risk import calculate_abandonment_risk
from scoring.health_score import calculate_health_score

from .conftest import (
    abandoned_fixture_names,
    healthy_fixture_names,
    load_fixture,
)

# =============================================================================
# Health Score Validation - Abandoned Packages
# =============================================================================


class TestAbandonedPackageHealthScores:
    """Abandoned packages should have lower health scores than healthy ones."""

    @pytest.mark.parametrize("name", abandoned_fixture_names(), ids=lambda n: n)
    def test_abandoned_package_below_threshold(self, name):
        """Each abandoned package should score below its expected maximum."""
        fixture = load_fixture(name)
        eval_date = fixture["meta"]["evaluation_date"]
        expected = fixture["expected"]

        with freeze_time(eval_date):
            result = calculate_health_score(fixture["data"])

        score = result["health_score"]
        max_score = expected["health_score_max"]

        assert score <= max_score, (
            f"{name}: health_score={score} exceeds max={max_score}. "
            f"Components: {result['components']}. "
            f"Failure mode: {expected['failure_mode']}"
        )

    @pytest.mark.parametrize("name", abandoned_fixture_names(), ids=lambda n: n)
    def test_abandoned_package_not_low_risk(self, name):
        """No abandoned package (pre-abandonment) should be rated LOW risk."""
        fixture = load_fixture(name)
        eval_date = fixture["meta"]["evaluation_date"]

        with freeze_time(eval_date):
            result = calculate_health_score(fixture["data"])

        # Packages that were about to be abandoned should not be LOW risk
        # (score >= 80). They may be MEDIUM (60-79) due to high adoption.
        assert result["risk_level"] != "LOW", (
            f"{name}: rated LOW risk with score={result['health_score']} "
            f"despite being abandoned on {fixture['expected']['abandoned_date']}. "
            f"Components: {result['components']}"
        )


class TestAbandonedPackageComponents:
    """Component-level assertions for abandoned packages."""

    @pytest.mark.parametrize("name", ["event-stream", "colors", "left-pad"])
    def test_single_maintainer_low_maintainer_health(self, name):
        """Packages with bus_factor=1 should have low maintainer health."""
        fixture = load_fixture(name)
        eval_date = fixture["meta"]["evaluation_date"]

        with freeze_time(eval_date):
            result = calculate_health_score(fixture["data"])

        maintainer = result["components"]["maintainer_health"]
        assert maintainer < 40, (
            f"{name}: maintainer_health={maintainer} too high for single-maintainer package with low activity"
        )

    @pytest.mark.parametrize("name", ["event-stream"])
    def test_stale_packages_low_evolution(self, name):
        """Packages with no releases in years should have low evolution health.
        Note: left-pad excluded because its last release was only ~54 days before
        evaluation, so evolution score is moderate despite no commits."""
        fixture = load_fixture(name)
        eval_date = fixture["meta"]["evaluation_date"]

        with freeze_time(eval_date):
            result = calculate_health_score(fixture["data"])

        evolution = result["components"]["evolution_health"]
        assert evolution < 50, (
            f"{name}: evolution_health={evolution} too high for package with no recent releases or commits"
        )

    @pytest.mark.parametrize("name", ["request", "moment", "colors"])
    def test_high_adoption_packages_good_user_centric(self, name):
        """Abandoned packages with high downloads should still score well on user-centric."""
        fixture = load_fixture(name)
        eval_date = fixture["meta"]["evaluation_date"]

        with freeze_time(eval_date):
            result = calculate_health_score(fixture["data"])

        user_centric = result["components"]["user_centric"]
        assert user_centric >= 60, (
            f"{name}: user_centric={user_centric} too low for "
            f"package with {fixture['data']['weekly_downloads']:,} weekly downloads"
        )


# =============================================================================
# Health Score Validation - Healthy Controls
# =============================================================================


class TestHealthyPackageHealthScores:
    """Healthy packages should have high health scores."""

    @pytest.mark.parametrize("name", healthy_fixture_names(), ids=lambda n: n)
    def test_healthy_package_above_threshold(self, name):
        """Each healthy package should score above its expected minimum."""
        fixture = load_fixture(name)
        eval_date = fixture["meta"]["evaluation_date"]
        expected = fixture["expected"]

        with freeze_time(eval_date):
            result = calculate_health_score(fixture["data"])

        score = result["health_score"]
        min_score = expected["health_score_min"]

        assert score >= min_score, (
            f"{name}: health_score={score} below min={min_score}. Components: {result['components']}"
        )

    @pytest.mark.parametrize("name", ["react", "numpy"])
    def test_top_tier_packages_low_risk(self, name):
        """Best-in-class packages should be rated LOW risk."""
        fixture = load_fixture(name)
        eval_date = fixture["meta"]["evaluation_date"]

        with freeze_time(eval_date):
            result = calculate_health_score(fixture["data"])

        assert result["risk_level"] == "LOW", (
            f"{name}: rated {result['risk_level']} risk with "
            f"score={result['health_score']}. "
            f"Components: {result['components']}"
        )


# =============================================================================
# Abandonment Risk Validation
# =============================================================================


class TestAbandonedPackageRisk:
    """Abandonment risk should be elevated for packages that were actually abandoned."""

    @pytest.mark.parametrize("name", abandoned_fixture_names(), ids=lambda n: n)
    def test_abandoned_package_elevated_risk(self, name):
        """Each abandoned package should have risk above its expected minimum."""
        fixture = load_fixture(name)
        eval_date = fixture["meta"]["evaluation_date"]
        expected = fixture["expected"]

        with freeze_time(eval_date):
            result = calculate_abandonment_risk(fixture["data"])

        risk = result["probability"]
        min_risk = expected["abandonment_risk_min"]

        assert risk >= min_risk, (
            f"{name}: abandonment_risk={risk}% below min={min_risk}%. "
            f"Components: {result['components']}. "
            f"Factors: {result['risk_factors']}"
        )

    @pytest.mark.parametrize("name", ["event-stream", "colors", "left-pad"])
    def test_single_maintainer_bus_factor_flagged(self, name):
        """Single-maintainer packages should have bus factor in risk factors."""
        fixture = load_fixture(name)
        eval_date = fixture["meta"]["evaluation_date"]

        with freeze_time(eval_date):
            result = calculate_abandonment_risk(fixture["data"])

        factor_text = " ".join(result["risk_factors"])
        assert "maintainer" in factor_text.lower() or "bus factor" in factor_text.lower(), (
            f"{name}: bus factor risk not flagged. Factors: {result['risk_factors']}"
        )


class TestHealthyPackageRisk:
    """Healthy packages should have low abandonment risk."""

    @pytest.mark.parametrize("name", healthy_fixture_names(), ids=lambda n: n)
    def test_healthy_package_low_risk(self, name):
        """Each healthy package should have risk below its expected maximum."""
        fixture = load_fixture(name)
        eval_date = fixture["meta"]["evaluation_date"]
        expected = fixture["expected"]

        with freeze_time(eval_date):
            result = calculate_abandonment_risk(fixture["data"])

        risk = result["probability"]
        max_risk = expected["abandonment_risk_max"]

        assert risk <= max_risk, (
            f"{name}: abandonment_risk={risk}% exceeds max={max_risk}%. "
            f"Components: {result['components']}. "
            f"Factors: {result['risk_factors']}"
        )

    @pytest.mark.parametrize("name", ["react", "numpy"])
    def test_top_tier_packages_minimal_risk(self, name):
        """Best-in-class packages should have very low abandonment risk."""
        fixture = load_fixture(name)
        eval_date = fixture["meta"]["evaluation_date"]

        with freeze_time(eval_date):
            result = calculate_abandonment_risk(fixture["data"])

        assert result["probability"] < 15, (
            f"{name}: abandonment_risk={result['probability']}% "
            f"is too high for a top-tier package. "
            f"Components: {result['components']}"
        )


# =============================================================================
# Cross-Comparison Tests
# =============================================================================


class TestHealthScoreSeparation:
    """Abandoned packages should consistently score lower than healthy ones."""

    def test_abandoned_vs_healthy_separation(self):
        """The average abandoned score should be meaningfully lower than average healthy score."""
        abandoned_scores = []
        healthy_scores = []

        for name in abandoned_fixture_names():
            fixture = load_fixture(name)
            with freeze_time(fixture["meta"]["evaluation_date"]):
                result = calculate_health_score(fixture["data"])
                abandoned_scores.append(result["health_score"])

        for name in healthy_fixture_names():
            fixture = load_fixture(name)
            with freeze_time(fixture["meta"]["evaluation_date"]):
                result = calculate_health_score(fixture["data"])
                healthy_scores.append(result["health_score"])

        avg_abandoned = sum(abandoned_scores) / len(abandoned_scores)
        avg_healthy = sum(healthy_scores) / len(healthy_scores)
        separation = avg_healthy - avg_abandoned

        assert separation > 10, (
            f"Insufficient separation between groups. "
            f"Avg abandoned={avg_abandoned:.1f}, avg healthy={avg_healthy:.1f}, "
            f"separation={separation:.1f}. "
            f"Abandoned scores: {abandoned_scores}, "
            f"Healthy scores: {healthy_scores}"
        )

    def test_risk_separation(self):
        """Average abandonment risk should be higher for abandoned packages."""
        abandoned_risks = []
        healthy_risks = []

        for name in abandoned_fixture_names():
            fixture = load_fixture(name)
            with freeze_time(fixture["meta"]["evaluation_date"]):
                result = calculate_abandonment_risk(fixture["data"])
                abandoned_risks.append(result["probability"])

        for name in healthy_fixture_names():
            fixture = load_fixture(name)
            with freeze_time(fixture["meta"]["evaluation_date"]):
                result = calculate_abandonment_risk(fixture["data"])
                healthy_risks.append(result["probability"])

        avg_abandoned = sum(abandoned_risks) / len(abandoned_risks)
        avg_healthy = sum(healthy_risks) / len(healthy_risks)
        separation = avg_abandoned - avg_healthy

        assert separation > 10, (
            f"Insufficient risk separation between groups. "
            f"Avg abandoned risk={avg_abandoned:.1f}%, avg healthy risk={avg_healthy:.1f}%, "
            f"separation={separation:.1f}pp. "
            f"Abandoned risks: {abandoned_risks}, "
            f"Healthy risks: {healthy_risks}"
        )

    def test_no_healthy_scores_below_worst_abandoned(self):
        """No healthy package should score lower than the worst abandoned package."""
        abandoned_scores = []
        healthy_scores = {}

        for name in abandoned_fixture_names():
            fixture = load_fixture(name)
            with freeze_time(fixture["meta"]["evaluation_date"]):
                result = calculate_health_score(fixture["data"])
                abandoned_scores.append(result["health_score"])

        worst_abandoned = min(abandoned_scores)

        for name in healthy_fixture_names():
            fixture = load_fixture(name)
            with freeze_time(fixture["meta"]["evaluation_date"]):
                result = calculate_health_score(fixture["data"])
                healthy_scores[name] = result["health_score"]

        for name, score in healthy_scores.items():
            assert score > worst_abandoned, (
                f"Healthy package {name} (score={score}) scored lower than "
                f"worst abandoned package (score={worst_abandoned})"
            )


# =============================================================================
# Diagnostic Test (always passes, prints summary)
# =============================================================================


class TestScoringDiagnostics:
    """Diagnostic output for manual review. Always passes."""

    def test_print_all_scores(self, capsys):
        """Print a summary table of all fixture scores for manual review."""
        rows = []

        for name in abandoned_fixture_names() + healthy_fixture_names():
            fixture = load_fixture(name)
            is_abandoned = fixture["expected"].get("known_abandoned", False)

            with freeze_time(fixture["meta"]["evaluation_date"]):
                health = calculate_health_score(fixture["data"])
                risk = calculate_abandonment_risk(fixture["data"])

            rows.append(
                {
                    "name": name,
                    "group": "ABANDONED" if is_abandoned else "HEALTHY",
                    "health_score": health["health_score"],
                    "risk_level": health["risk_level"],
                    "abandonment_risk": risk["probability"],
                    "maintainer": health["components"]["maintainer_health"],
                    "user_centric": health["components"]["user_centric"],
                    "evolution": health["components"]["evolution_health"],
                    "community": health["components"]["community_health"],
                    "security": health["components"]["security_health"],
                    "confidence": health["confidence"]["level"],
                }
            )

        # Print formatted table
        print("\n" + "=" * 120)
        print("SCORING VALIDATION SUMMARY")
        print("=" * 120)
        print(
            f"{'Name':<16} {'Group':<10} {'Health':>7} {'Risk':>6} "
            f"{'Aband%':>7} {'Maint':>6} {'User':>6} {'Evol':>6} "
            f"{'Comm':>6} {'Sec':>6} {'Conf':<8}"
        )
        print("-" * 120)

        for r in rows:
            print(
                f"{r['name']:<16} {r['group']:<10} {r['health_score']:>7.1f} "
                f"{r['risk_level']:>6} {r['abandonment_risk']:>6.1f}% "
                f"{r['maintainer']:>6.1f} {r['user_centric']:>6.1f} "
                f"{r['evolution']:>6.1f} {r['community']:>6.1f} "
                f"{r['security']:>6.1f} {r['confidence']:<8}"
            )

        print("=" * 120)
