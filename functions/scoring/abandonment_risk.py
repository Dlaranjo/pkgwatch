"""
Abandonment Risk Calculator - Predicts likelihood of package abandonment.

Uses continuous risk factors with adjustable time horizons.
"""

import logging
import math
import re

logger = logging.getLogger(__name__)


def _calculate_time_adjusted_risk(base_risk: float, months: int) -> float:
    """
    Adjust risk using Weibull survival analysis.

    The Weibull distribution is commonly used for reliability/survival analysis.
    Shape parameter k > 1 means increasing hazard rate over time.

    Args:
        base_risk: Base risk score (0-1)
        months: Time horizon in months (must be >= 1)

    Returns:
        Time-adjusted risk probability (0-0.95)

    Raises:
        ValueError: If months < 1
    """
    # Input validation
    if not 0 <= base_risk <= 1:
        logger.warning(f"base_risk {base_risk} out of [0,1] range, clamping")
        base_risk = max(0.0, min(1.0, base_risk))

    if months < 1:
        raise ValueError(f"months must be >= 1, got {months}")

    # Parameters would ideally be fit from historical data
    k = 1.5  # Shape parameter (k > 1 = increasing failure rate)
    lambda_ = 18  # Scale parameter (median time to abandonment in months)

    # Combine with base risk
    # High base risk = faster decline in survival
    adjusted_lambda = lambda_ * (1 - base_risk * 0.5)

    # Survival probability using Weibull distribution
    survival_prob = math.exp(-((months / adjusted_lambda) ** k))

    # Risk is inverse of survival, capped at 0.95
    return min(1 - survival_prob, 0.95)


def calculate_abandonment_risk(data: dict, months: int = 12) -> dict:
    """
    Predict abandonment probability over a given time horizon.

    Args:
        data: Package data dictionary
        months: Prediction time horizon (default 12 months)

    Returns:
        Dictionary with probability, time horizon, and risk factors

    Raises:
        TypeError: If data is not a dictionary or months is not an integer
    """
    # Type validation - guard against None or non-dict inputs
    if data is None:
        logger.warning("calculate_abandonment_risk received None, using empty dict")
        data = {}
    elif not isinstance(data, dict):
        raise TypeError(f"data must be a dict, got {type(data).__name__}")

    # Validate months parameter type
    if not isinstance(months, int):
        original_type = type(months).__name__  # Capture before conversion
        try:
            months = int(months)
            logger.warning(f"months converted from {original_type} to int")
        except (TypeError, ValueError):
            logger.warning(f"Invalid months type {original_type}, using default 12")
            months = 12

    # Clamp months to valid range (minimum 1 to prevent negative/zero probabilities)
    if months < 1:
        logger.warning(f"Invalid months value {months}, clamping to 1")
        months = max(1, months)

    # Risk signals (0-1 scale, higher = riskier)

    # 1. Inactivity risk: exponential increase with days since commit
    days = data.get("days_since_last_commit", 365)
    if days is None:
        days = 365
    # Clamp to non-negative (negative days would break risk calculation)
    if days < 0:
        logger.warning(f"Negative days_since_last_commit in abandonment: {days}, clamping to 0")
        days = 0
    days = max(0, days)  # Defense in depth
    inactivity_risk = 1 - math.exp(-days / 180)

    # 2. Bus factor risk: exponential decay with contributor count
    maintainers = data.get("active_contributors_90d", 1)
    if maintainers is None:
        maintainers = 1
    # Guard against negative values which would cause bus_factor_risk > 1
    if maintainers < 0:
        logger.warning(f"Negative active_contributors_90d: {maintainers}, clamping to 1")
        maintainers = 1
    maintainers = max(1, maintainers)  # Defense in depth
    bus_factor_risk = math.exp(-maintainers / 2)

    # 3. Adoption risk: low downloads indicate abandonment risk
    # Use continuous logarithmic function instead of discrete steps
    # for consistency with other algorithms
    downloads = max(0, data.get("weekly_downloads", 0) or 0)  # Clamp negative
    # Scale: 10 downloads = 0.8 risk, 10K downloads = 0.2 risk, 1M+ = 0.1 risk
    # Formula: max(0.1, 0.9 - log10(downloads + 1) / 7)
    adoption_risk = max(0.1, min(0.9, 0.9 - math.log10(downloads + 1) / 7))

    # 4. Release cadence risk
    days_since_release = 365  # Default
    last_published = data.get("last_published")
    if last_published:
        try:
            from datetime import datetime, timezone

            if isinstance(last_published, str):
                published_date = datetime.fromisoformat(last_published.replace("Z", "+00:00"))
            else:
                published_date = last_published

            now = datetime.now(timezone.utc)
            if published_date.tzinfo is None:
                published_date = published_date.replace(tzinfo=timezone.utc)

            days_since_release = (now - published_date).days
            # Clamp to non-negative (future dates would break risk calculation)
            if days_since_release < 0:
                logger.warning(f"Negative days_since_release in abandonment: {days_since_release}, clamping to 0")
                days_since_release = 0
            days_since_release = max(0, days_since_release)  # Defense in depth
        except (ValueError, TypeError):
            pass

    release_risk = 1 - math.exp(-days_since_release / 365)

    # Weighted combination
    risk_score = inactivity_risk * 0.35 + bus_factor_risk * 0.30 + adoption_risk * 0.20 + release_risk * 0.15

    # Adjust for time horizon using Weibull survival analysis
    # This provides more realistic risk progression than linear scaling
    adjusted_risk = _calculate_time_adjusted_risk(risk_score, months)

    # Identify specific risk factors for explanation
    factors = []

    if days > 180:
        factors.append(f"No commits in {days} days")
    elif days > 90:
        factors.append(f"Low commit activity ({days} days since last commit)")

    if maintainers <= 1:
        factors.append("Single maintainer (bus factor = 1)")
    elif maintainers <= 2:
        factors.append(f"Small maintainer pool ({maintainers} active contributors)")

    if downloads < 1000:
        factors.append(f"Low adoption ({downloads:,} weekly downloads)")

    if days_since_release > 365:
        factors.append(f"No releases in {days_since_release} days")
    elif days_since_release > 180:
        factors.append(f"Infrequent releases ({days_since_release} days since last)")

    # Check for explicit abandonment signals
    if data.get("archived"):
        factors.append("Repository is archived")
        adjusted_risk = 0.95

    if data.get("is_deprecated"):
        factors.append("Package is deprecated")
        adjusted_risk = 0.95

    deprecation_msg = data.get("deprecation_message")
    if deprecation_msg:
        # Sanitize to prevent XSS - strip only HTML-dangerous characters
        # Preserves useful chars like :, /, @, ' for package references and URLs
        # This is user-controlled data from npm registry that could contain malicious content
        sanitized = re.sub(r'[<>&"]', "", str(deprecation_msg)[:200])
        if sanitized.strip():
            factors.append(f"Deprecation note: {sanitized.strip()}")

    return {
        "probability": round(adjusted_risk * 100, 1),
        "time_horizon_months": months,
        "risk_factors": factors,
        "components": {
            "inactivity_risk": round(inactivity_risk * 100, 1),
            "bus_factor_risk": round(bus_factor_risk * 100, 1),
            "adoption_risk": round(adoption_risk * 100, 1),
            "release_risk": round(release_risk * 100, 1),
        },
    }


def get_risk_trend(historical_scores: list[float]) -> dict:
    """
    Analyze risk trend over time.

    Args:
        historical_scores: List of risk probabilities (oldest first)

    Returns:
        Dictionary with trend direction and magnitude
    """
    if len(historical_scores) < 2:
        return {"trend": "STABLE", "change": 0.0}

    recent = historical_scores[-1]
    previous = historical_scores[-2]

    # Guard against None, NaN, or non-numeric values
    try:
        recent = float(recent) if recent is not None else 0.0
        previous = float(previous) if previous is not None else 0.0
        # Check for NaN (NaN != NaN is True)
        if recent != recent or previous != previous:
            logger.warning("NaN detected in historical_scores, returning STABLE")
            return {"trend": "STABLE", "change": 0.0}
    except (TypeError, ValueError) as e:
        logger.warning(f"Invalid values in historical_scores: {e}")
        return {"trend": "STABLE", "change": 0.0}

    change = recent - previous

    if abs(change) < 5:
        trend = "STABLE"
    elif change > 0:
        trend = "INCREASING"
    else:
        trend = "DECREASING"

    return {
        "trend": trend,
        "change": round(change, 1),
        "current": round(recent, 1),
        "previous": round(previous, 1),
    }
