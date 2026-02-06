"""
Health Score Calculator - Core scoring algorithm.

Uses continuous functions (log-scale, exponential decay, sigmoid)
to calculate health scores based on multiple signals.

Components (v2 - revised weights):
- Maintainer Health: 25%
- User-Centric: 30% (most predictive per research)
- Evolution: 20%
- Community: 10% (contributor diversity only)
- Security: 15% (NEW - OpenSSF, vulnerabilities, security policy)
"""

import logging
import math
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def calculate_health_score(data: dict) -> dict:
    """
    Calculate overall health score (0-100).

    Args:
        data: Package data dictionary with all collected signals

    Returns:
        Dictionary with health score, risk level, components, and confidence

    Raises:
        TypeError: If data is not a dictionary
    """
    # Type validation - guard against None or non-dict inputs
    if data is None:
        logger.warning("calculate_health_score received None, using empty dict")
        data = {}
    elif not isinstance(data, dict):
        raise TypeError(f"data must be a dict, got {type(data).__name__}")

    # Calculate component scores with explicit clamping for defense-in-depth
    # Each component should return 0-1, but we clamp to ensure bounds
    maintainer = max(0.0, min(1.0, _maintainer_health(data)))
    user_centric = max(0.0, min(1.0, _user_centric_health(data)))
    evolution = max(0.0, min(1.0, _evolution_health(data)))
    community = max(0.0, min(1.0, _community_health(data)))
    security = max(0.0, min(1.0, _security_health(data)))

    # Weighted combination (v2 weights)
    # Security extracted from Community and given dedicated 15% weight
    raw_score = (
        maintainer * 0.25  # was 0.30
        + user_centric * 0.30  # unchanged - most predictive
        + evolution * 0.20  # was 0.25
        + community * 0.10  # was 0.15 (security extracted)
        + security * 0.15  # NEW
    )

    # Clamp final score to valid range (0-100)
    health_score = round(max(0, min(100, raw_score * 100)), 1)
    confidence = _calculate_confidence(data)

    # Add confidence interval to the score
    margin = confidence.get("interval_margin", 10)
    confidence_interval = [max(0, health_score - margin), min(100, health_score + margin)]

    return {
        "health_score": health_score,
        "confidence_interval": confidence_interval,
        "risk_level": _get_risk_level(health_score),
        "components": {
            "maintainer_health": round(maintainer * 100, 1),
            "user_centric": round(user_centric * 100, 1),
            "evolution_health": round(evolution * 100, 1),
            "community_health": round(community * 100, 1),
            "security_health": round(security * 100, 1),
        },
        "confidence": confidence,
    }


def _issue_response_score(data: dict) -> float:
    """
    Calculate score based on average issue response time.

    Fast response (< 24h) = 1.0
    Moderate response (24-72h) = 0.7-1.0 (linear decay)
    Slow response (> 72h) = exponential decay
    No data = 0.5 (neutral)

    NOTE: Response times are currently estimated using heuristics:
    - Closed issues with comments: assumed 24h average response
    - Open issues with comments: assumed 48h average response
    This is a simplification to avoid additional GitHub API calls.
    Future enhancement: fetch actual response times from GitHub Timeline API.
    """
    avg_response_hours = data.get("avg_issue_response_hours")
    if avg_response_hours is None:
        return 0.5  # Neutral if no data

    # Guard against NaN, infinity, and negative values
    try:
        avg_response_hours = float(avg_response_hours)
        if math.isnan(avg_response_hours) or math.isinf(avg_response_hours):
            logger.warning(f"Invalid avg_issue_response_hours: {avg_response_hours}")
            return 0.5
        if avg_response_hours < 0:
            logger.warning(f"Negative avg_issue_response_hours: {avg_response_hours}")
            avg_response_hours = 0
    except (TypeError, ValueError):
        logger.warning(f"Non-numeric avg_issue_response_hours: {type(avg_response_hours)}")
        return 0.5

    if avg_response_hours <= 24:
        return 1.0
    elif avg_response_hours <= 72:
        return 0.7 + 0.3 * (1 - (avg_response_hours - 24) / 48)
    else:
        # Exponential decay after 72 hours
        return 0.7 * math.exp(-0.01 * (avg_response_hours - 72))


def _pr_velocity_score(data: dict) -> float:
    """
    Calculate score based on PR merge velocity.

    Looks at: merged_prs / opened_prs ratio over last 90 days
    High velocity (> 0.8) = 1.0
    Low velocity (< 0.3) = indicates problems
    No data = 0.5 (neutral, could be stable package)
    """
    merged = data.get("prs_merged_90d", 0)
    opened = data.get("prs_opened_90d", 0)

    # Handle None values (explicit None differs from missing key with default)
    if merged is None:
        merged = 0
    if opened is None:
        opened = 0

    # Guard against non-numeric and negative values
    try:
        merged = max(0, int(merged))
        opened = max(0, int(opened))
    except (TypeError, ValueError):
        logger.warning(f"Non-numeric PR values: merged={merged}, opened={opened}")
        return 0.5

    if opened == 0:
        return 0.5  # No PRs is neutral (could be stable package)

    velocity = merged / opened
    # Sigmoid centered at 0.5 velocity
    return 1 / (1 + math.exp(-5 * (velocity - 0.5)))


def _maintainer_health(data: dict) -> float:
    """
    Maintainer activity signals.

    Uses smooth exponential decay for recency and sigmoid for bus factor.
    Bus factor uses true contribution distribution when available.
    Now includes PR merge velocity to assess maintainer responsiveness.
    """
    # Recency score: exponential decay with 90-day half-life
    # Half-life means score = 0.5 after 90 days of inactivity
    days = data.get("days_since_last_commit", 365)
    if days is None:
        days = 365
    # Clamp to non-negative (negative days would cause exp() > 1)
    if days < 0:
        logger.warning(f"Negative days_since_last_commit: {days}, clamping to 0")
        days = 0
    days = max(0, days)  # Defense in depth
    recency = math.exp(-0.693 * days / 90)  # 0.693 = ln(2)

    # Bus factor score: sigmoid centered at 2 contributors
    # Use true bus factor (contribution distribution) if available
    # 1 contributor ~= 0.27, 2 ~= 0.5, 3+ ~= 0.73+
    true_bus_factor = data.get("true_bus_factor")
    if true_bus_factor and true_bus_factor > 0:
        # True bus factor: minimum contributors for 50% of commits
        bus_factor_score = 1 / (1 + math.exp(-(true_bus_factor - 2)))
    else:
        # Fallback to simple contributor count
        contributors = data.get("active_contributors_90d", 1)
        if contributors is None:
            contributors = 1
        bus_factor_score = 1 / (1 + math.exp(-(contributors - 2)))

    # PR velocity score: measures maintainer responsiveness
    pr_velocity = _pr_velocity_score(data)

    return recency * 0.5 + bus_factor_score * 0.3 + pr_velocity * 0.2


def _user_centric_health(data: dict) -> float:
    """
    User adoption signals - MOST PREDICTIVE per research.

    Uses continuous log-scale functions instead of step functions.
    """
    # Download score: log-scaled continuous function
    # log10(1M) = 6, log10(10M) = 7, normalize so 10M+ = 1.0
    downloads = max(0, data.get("weekly_downloads", 0) or 0)  # Clamp negative
    download_score = min(math.log10(downloads + 1) / 7, 1.0)

    # Dependents: log-scaled (ecosystem position)
    # log10(10K) = 4, normalize so 10K+ = 1.0
    dependents = max(0, data.get("dependents_count", 0) or 0)  # Clamp negative
    dependent_score = min(math.log10(dependents + 1) / 4, 1.0)

    # Stars: log-scaled community interest proxy
    # log10(100K) = 5, normalize so 100K+ = 1.0
    stars = max(0, data.get("stars", 0) or 0)  # Clamp negative
    star_score = min(math.log10(stars + 1) / 5, 1.0)

    return download_score * 0.5 + dependent_score * 0.3 + star_score * 0.2


def _calculate_maturity_factor(data: dict) -> float:
    """
    Calculate maturity factor for stable packages.

    High-adoption + low-activity = stable, not dead.

    Uses smooth sigmoid transitions instead of hard thresholds
    to avoid gaming incentives and score cliffs.

    Returns:
        0.0 to 0.7 factor to use as floor for activity score
    """
    downloads = max(0, data.get("weekly_downloads", 0) or 0)  # Clamp negative
    dependents = max(0, data.get("dependents_count", 0) or 0)  # Clamp negative
    commits_90d = max(0, data.get("commits_90d", 0) or 0)  # Clamp negative

    # Smooth adoption signal using sigmoid
    # Downloads: sigmoid centered at 1M (log10(1M) = 6)
    download_signal = 1 / (1 + math.exp(-(math.log10(downloads + 1) - 6) / 0.5))
    # Dependents: sigmoid centered at 5K (log10(5K) ≈ 3.7)
    dependent_signal = 1 / (1 + math.exp(-(math.log10(dependents + 1) - 3.7) / 0.5))
    # Use whichever adoption signal is stronger
    adoption = max(download_signal, dependent_signal)

    # Low activity check (also smooth sigmoid)
    # Centered at 10 commits - below 10 = high maturity eligibility
    # Clamp sigmoid argument to prevent overflow (exp(700) is near max float)
    sigmoid_arg = (commits_90d - 10) / 3
    sigmoid_arg = max(-700, min(700, sigmoid_arg))
    activity_low = 1 / (1 + math.exp(sigmoid_arg))

    # Maturity = high adoption AND low activity
    # Max factor of 0.7 to prevent gaming
    return adoption * activity_low * 0.7


def _evolution_health(data: dict) -> float:
    """
    Project evolution signals.

    Uses continuous exponential decay for release recency
    and log-scale for commit activity.

    Applies maturity factor as floor for stable high-adoption packages.
    """
    # Release recency: exponential decay with 180-day half-life
    last_published = data.get("last_published")
    release_score = 0.5  # Default neutral

    if last_published:
        try:
            if isinstance(last_published, str):
                published_date = datetime.fromisoformat(last_published.replace("Z", "+00:00"))
            else:
                published_date = last_published

            now = datetime.now(timezone.utc)
            if published_date.tzinfo is None:
                published_date = published_date.replace(tzinfo=timezone.utc)

            days_since_release = (now - published_date).days
            # Clamp to non-negative (future dates would cause exp() > 1)
            if days_since_release < 0:
                logger.warning(f"Negative days_since_release: {days_since_release}, clamping to 0")
                days_since_release = 0
            days_since_release = max(0, days_since_release)  # Defense in depth
            release_score = math.exp(-0.693 * days_since_release / 180)
        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse last_published '{last_published}': {e}")

    # Commit activity: log-scaled continuous function
    # log10(50) ~= 1.7, normalize so 50+ commits/90d = ~1.0
    # Prefer bot-filtered commit count if available
    commits_90d = max(0, data.get("commits_90d_non_bot", data.get("commits_90d", 0)) or 0)  # Clamp negative
    activity_score = min(math.log10(commits_90d + 1) / 1.7, 1.0)

    # Apply maturity factor as floor for stable packages
    # This prevents penalizing mature packages that don't need frequent updates
    maturity_factor = _calculate_maturity_factor(data)
    activity_score = max(activity_score, maturity_factor)

    return release_score * 0.5 + activity_score * 0.5


def _community_health(data: dict) -> float:
    """
    Community engagement signals.

    NOTE: OpenSSF and security signals moved to _security_health()
    to avoid double-counting. Now includes contributor diversity and issue responsiveness.
    """
    # Contributors: log-scaled continuous
    # log10(50) ~= 1.7, normalize so 50+ contributors = ~1.0
    # Handle 0 contributors as a data quality issue (distinct from None/missing)
    contributors = data.get("total_contributors")
    if contributors is None:
        contributors = 1  # Missing data - use neutral default
    elif contributors == 0:
        # 0 contributors likely indicates data collection failure or very new package
        logger.warning("total_contributors is 0 - possible data collection issue")
        contributors = 1  # Treat as single maintainer for scoring
    contributors = max(1, contributors)  # Defense in depth
    contributor_score = min(math.log10(contributors + 1) / 1.7, 1.0)

    # Issue response time: measures community engagement and maintainer interaction
    issue_response = _issue_response_score(data)

    return contributor_score * 0.6 + issue_response * 0.4


def _security_health(data: dict) -> float:
    """
    Security posture assessment.

    Components:
    - OpenSSF Scorecard (50%): Overall security practices
    - Vulnerability History (30%): Active advisories weighted by severity
    - Security Policy (20%): Has SECURITY.md, responsible disclosure

    NOTE: Missing OpenSSF data defaults to 0.3 (penalize unknown),
    not 0.5 (neutral), to incentivize security transparency.
    """
    # OpenSSF score (already 0-10 scale from deps.dev)
    # Default to 0.3 (penalize unknown) instead of 0.5 (neutral)
    openssf = data.get("openssf_score")
    if openssf is not None:
        try:
            # Defensive: ensure openssf is numeric before division
            openssf_val = float(openssf)
            # Check for NaN and infinity which would propagate through calculations
            if math.isnan(openssf_val) or math.isinf(openssf_val):
                logger.warning(f"Invalid openssf_score value ({openssf_val}), using default")
                openssf_score = 0.3
            else:
                openssf_score = max(0.0, min(openssf_val / 10.0, 1.0))
        except (TypeError, ValueError):
            logger.warning(f"Invalid openssf_score type: {type(openssf)}, using default")
            openssf_score = 0.3
    else:
        openssf_score = 0.3  # Penalize missing security data

    # Vulnerability assessment (same logic as before)
    # Limit to first 1000 advisories to prevent DoS from malformed data
    MAX_ADVISORIES = 1000
    advisories = (data.get("advisories", []) or [])[:MAX_ADVISORIES]
    # Defensive: ensure each advisory is a dict before calling .get()
    # Single pass through advisories for efficiency
    critical = high = medium = 0
    for a in advisories:
        if isinstance(a, dict):
            severity = a.get("severity")
            if severity == "CRITICAL":
                critical += 1
            elif severity == "HIGH":
                high += 1
            elif severity == "MEDIUM":
                medium += 1

    # Weighted vulnerability score (higher = worse)
    vuln_score = critical * 3 + high * 2 + medium * 1

    # Sigmoid decay: 0 vulns ~= 0.79, 2 = 0.5, 5+ weighted vulns ~= 0.12
    vulnerability_score = 1 / (1 + math.exp((vuln_score - 2) / 1.5))

    # Security policy check (from OpenSSF checks if available)
    # Limit to first 100 checks to prevent DoS from malformed data
    MAX_OPENSSF_CHECKS = 100
    openssf_checks = (data.get("openssf_checks", []) or [])[:MAX_OPENSSF_CHECKS]
    has_security_policy = any(
        isinstance(c, dict) and c.get("name") == "Security-Policy" and c.get("score", 0) >= 5 for c in openssf_checks
    )
    security_policy_score = 1.0 if has_security_policy else 0.3

    return openssf_score * 0.50 + vulnerability_score * 0.30 + security_policy_score * 0.20


def _calculate_confidence(data: dict) -> dict:
    """
    Calculate confidence in the score with intervals.

    Returns INSUFFICIENT_DATA for packages < 90 days old.
    Includes confidence intervals based on data quality.
    """
    # Data completeness check - expanded to include new signals
    required_fields = [
        "days_since_last_commit",
        "weekly_downloads",
        "active_contributors_90d",
        "last_published",
        "avg_issue_response_hours",
        "prs_merged_90d",
        "prs_opened_90d",
    ]
    present = sum(1 for f in required_fields if data.get(f) is not None and data.get(f) != 0)
    completeness = present / len(required_fields)

    # Package age (cold start penalty)
    created = data.get("created_at")
    age_score = 0.5

    if created:
        try:
            if isinstance(created, str):
                created_date = datetime.fromisoformat(created.replace("Z", "+00:00"))
            else:
                created_date = created

            now = datetime.now(timezone.utc)
            if created_date.tzinfo is None:
                created_date = created_date.replace(tzinfo=timezone.utc)

            age_days = (now - created_date).days

            if age_days < 90:
                # Package too new - insufficient data
                return {
                    "score": 20.0,
                    "level": "INSUFFICIENT_DATA",
                    "reason": f"Package is only {age_days} days old. Scores may be unreliable.",
                }
            elif age_days < 180:
                age_score = 0.5
            elif age_days < 365:
                age_score = 0.7
            else:
                age_score = 1.0

        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse created_at '{created}': {e}")

    # Data freshness penalty
    last_updated = data.get("last_updated")
    freshness_score = 1.0

    if last_updated:
        try:
            if isinstance(last_updated, str):
                updated_date = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
            else:
                updated_date = last_updated

            now = datetime.now(timezone.utc)
            if updated_date.tzinfo is None:
                updated_date = updated_date.replace(tzinfo=timezone.utc)

            hours_since_update = (now - updated_date).total_seconds() / 3600

            if hours_since_update > 168:  # > 1 week old
                freshness_score = 0.7
            elif hours_since_update > 48:
                freshness_score = 0.9
        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse last_updated '{last_updated}': {e}")

    # Calculate overall confidence
    confidence_score = completeness * 0.5 + age_score * 0.3 + freshness_score * 0.2

    # Check for collection errors - these indicate incomplete data
    # that may cause artificially low scores
    collection_error_fields = ["github_error", "npm_error", "pypi_error", "depsdev_error"]
    error_count = sum(1 for e in collection_error_fields if data.get(e))
    has_github_error = bool(data.get("github_error"))

    # Apply penalty for collection errors
    # Each error reduces confidence by 10% (affects multiple components)
    if error_count > 0:
        error_penalty = error_count * 0.1
        confidence_score = max(0.2, confidence_score - error_penalty)
        logger.debug(
            f"Collection errors detected ({error_count}), "
            f"reduced confidence from {confidence_score + error_penalty:.2f} to {confidence_score:.2f}"
        )

    if confidence_score >= 0.8:
        level = "HIGH"
    elif confidence_score >= 0.5:
        level = "MEDIUM"
    else:
        level = "LOW"

    # Determine data quality and confidence interval margin
    # Based on data completeness ratio
    if completeness >= 0.8 and error_count == 0:
        data_quality = "high"
        margin = 5
    elif completeness >= 0.5 and error_count == 0:
        data_quality = "medium"
        margin = 10
    else:
        data_quality = "low"
        margin = 15

    # Widen margin significantly for GitHub errors since they affect
    # multiple components (stars, commits, contributors, bus factor)
    if has_github_error:
        margin = max(margin, 15)
        # Further widen for packages where GitHub data is particularly important
        # (packages with repository_url but no GitHub data)
        if data.get("repository_url"):
            margin = max(margin, 20)
            logger.debug(f"GitHub error with repository_url present, widened margin to {margin}")

    return {
        "score": round(confidence_score * 100, 1),
        "level": level,
        "data_quality": data_quality,
        "interval_margin": margin,
    }


def _get_risk_level(score: float) -> str:
    """Map health score to risk level."""
    if score >= 80:
        return "LOW"
    elif score >= 60:
        return "MEDIUM"
    elif score >= 40:
        return "HIGH"
    else:
        return "CRITICAL"
