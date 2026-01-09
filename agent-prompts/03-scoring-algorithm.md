# Agent Prompt: Scoring Algorithm Enhancements

## Context

You are working on DepHealth, a dependency health intelligence platform. The core value proposition is the health scoring and abandonment risk prediction algorithms. These algorithms are well-designed but need enhancements for better accuracy and additional signals.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 3: Scoring Algorithm Review)

## Your Mission

Enhance the scoring algorithms with additional signals, improve statistical validity, and add confidence intervals to predictions.

## Current Algorithm Overview

### Health Score Components (v2)
| Component | Weight | Current Signals |
|-----------|--------|-----------------|
| Maintainer Health | 25% | Commit recency, bus factor |
| User-Centric | 30% | Downloads, dependents, stars |
| Evolution | 20% | Release recency, commit activity |
| Community | 10% | Contributor count |
| Security | 15% | OpenSSF score, vulnerabilities |

### Files to Work With
- `functions/scoring/health_score.py` - Main health score calculation
- `functions/scoring/abandonment_risk.py` - Risk prediction
- `functions/scoring/score_package.py` - Orchestration and stream handler
- `tests/test_scoring.py` - Comprehensive test suite (1588 lines)

## Improvements to Implement

### 1. Add Issue Response Time Signal (HIGH PRIORITY)

**Location:** `functions/scoring/health_score.py` - Add to `_community_health()` or create new component

**Rationale:** Fast issue response time is a strong indicator of maintainer engagement and project health.

**Implementation:**
```python
def _issue_response_score(data: dict) -> float:
    """
    Calculate score based on average issue response time.

    Fast response (< 24h) = 1.0
    Moderate response (24-72h) = 0.7
    Slow response (> 72h) = decays exponentially
    No data = 0.5 (neutral)
    """
    avg_response_hours = data.get("avg_issue_response_hours")
    if avg_response_hours is None:
        return 0.5  # Neutral if no data

    if avg_response_hours <= 24:
        return 1.0
    elif avg_response_hours <= 72:
        return 0.7 + 0.3 * (1 - (avg_response_hours - 24) / 48)
    else:
        # Exponential decay after 72 hours
        return 0.7 * math.exp(-0.01 * (avg_response_hours - 72))
```

**Data Collection:** This requires updating `github_collector.py` to fetch issue response times from GitHub API.

### 2. Add PR Merge Velocity Signal (HIGH PRIORITY)

**Location:** `functions/scoring/health_score.py` - Add to `_community_health()` or `_maintainer_health()`

**Rationale:** Declining PR merge rates indicate maintainer overload or abandonment.

**Implementation:**
```python
def _pr_velocity_score(data: dict) -> float:
    """
    Calculate score based on PR merge velocity.

    Looks at: merged_prs / opened_prs ratio over last 90 days
    High velocity (> 0.8) = 1.0
    Low velocity (< 0.3) = indicates problems
    """
    merged = data.get("prs_merged_90d", 0)
    opened = data.get("prs_opened_90d", 0)

    if opened == 0:
        return 0.5  # No PRs is neutral (could be stable package)

    velocity = merged / opened
    # Sigmoid centered at 0.5 velocity
    return 1 / (1 + math.exp(-5 * (velocity - 0.5)))
```

### 3. Improve Abandonment Risk Time Scaling (MEDIUM PRIORITY)

**Location:** `functions/scoring/abandonment_risk.py`

**Current Problem:**
```python
# Linear scaling is naive
time_factor = min(months / 12, 2.0)
adjusted_risk = min(risk_score * time_factor, 0.95)
```

**Better Approach:** Use Weibull survival function
```python
def _calculate_time_adjusted_risk(base_risk: float, months: int) -> float:
    """
    Adjust risk using Weibull survival analysis.

    The Weibull distribution is commonly used for reliability/survival analysis.
    Shape parameter k > 1 means increasing hazard rate over time.
    """
    # Parameters would ideally be fit from historical data
    k = 1.5  # Shape parameter
    lambda_ = 18  # Scale parameter (median time to abandonment)

    # Survival probability
    survival_prob = math.exp(-((months / lambda_) ** k))

    # Combine with base risk
    # High base risk = faster decline in survival
    adjusted_lambda = lambda_ * (1 - base_risk * 0.5)
    survival_prob = math.exp(-((months / adjusted_lambda) ** k))

    return min(1 - survival_prob, 0.95)
```

### 4. Add Confidence Intervals (MEDIUM PRIORITY)

**Location:** Both `health_score.py` and `abandonment_risk.py`

**Current Problem:** Scores are point estimates with no uncertainty quantification.

**Implementation:**
```python
def calculate_health_score_with_confidence(data: dict) -> dict:
    """
    Calculate health score with confidence interval.

    Returns:
        {
            "health_score": 72.5,
            "confidence_interval": [68.2, 76.8],
            "confidence_level": 0.90,
            "data_quality": "high"  # or "medium", "low"
        }
    """
    base_score = calculate_health_score(data)

    # Calculate data quality based on available signals
    available_signals = sum(1 for k in REQUIRED_SIGNALS if data.get(k) is not None)
    total_signals = len(REQUIRED_SIGNALS)
    data_quality_ratio = available_signals / total_signals

    # Wider intervals for lower data quality
    if data_quality_ratio >= 0.8:
        margin = 5
        quality = "high"
    elif data_quality_ratio >= 0.5:
        margin = 10
        quality = "medium"
    else:
        margin = 15
        quality = "low"

    return {
        "health_score": base_score,
        "confidence_interval": [
            max(0, base_score - margin),
            min(100, base_score + margin)
        ],
        "confidence_level": 0.90,
        "data_quality": quality,
    }
```

### 5. Add Funding/Sustainability Signal (LOW PRIORITY)

**Location:** `functions/scoring/health_score.py` - New component or add to existing

**Rationale:** Funded projects are less likely to be abandoned.

**Implementation:**
```python
def _sustainability_score(data: dict) -> float:
    """
    Calculate sustainability score based on funding indicators.

    Signals:
    - has_funding: GitHub Sponsors, Open Collective, etc.
    - corporate_backed: Known corporate maintainer
    - foundation_project: Part of OpenJS, Apache, etc.
    """
    score = 0.5  # Base neutral score

    if data.get("has_funding"):
        score += 0.2
    if data.get("corporate_backed"):
        score += 0.2
    if data.get("foundation_project"):
        score += 0.1

    return min(score, 1.0)
```

### 6. Filter Bot Commits from Activity Metrics (MEDIUM PRIORITY)

**Location:** `functions/scoring/health_score.py` - `_evolution_health()`

**Current Problem:** Bot commits (dependabot, renovate) inflate activity metrics.

**Implementation:**
```python
BOT_PATTERNS = [
    "dependabot", "renovate", "greenkeeper", "snyk-bot",
    "github-actions", "semantic-release", "release-please"
]

def _filter_bot_commits(commits: list) -> list:
    """Filter out commits from known bot accounts."""
    return [
        c for c in commits
        if not any(bot in c.get("author", "").lower() for bot in BOT_PATTERNS)
    ]
```

**Note:** This requires the collector to include commit author information.

## Weight Rebalancing Consideration

Based on research, consider these weight adjustments (document rationale if changing):

| Component | Current | Proposed | Rationale |
|-----------|---------|----------|-----------|
| Maintainer Health | 25% | 30% | Most predictive of abandonment |
| User-Centric | 30% | 25% | Susceptible to gaming |
| Evolution | 20% | 20% | Unchanged |
| Community | 10% | 10% | Needs richer signals first |
| Security | 15% | 15% | Unchanged |

**Important:** Any weight changes require updating tests and documentation.

## Files to Modify

| File | Changes |
|------|---------|
| `functions/scoring/health_score.py` | Add new signals, confidence intervals |
| `functions/scoring/abandonment_risk.py` | Improve time scaling |
| `functions/collectors/github_collector.py` | Collect issue response times, PR data |
| `tests/test_scoring.py` | Add tests for new signals |
| `landing-page/src/pages/methodology.astro` | Update documentation |

## Data Collection Requirements

New data needed from collectors:
```python
# From GitHub API
"avg_issue_response_hours": float,  # Average time to first response
"prs_merged_90d": int,              # PRs merged in last 90 days
"prs_opened_90d": int,              # PRs opened in last 90 days
"has_funding": bool,                # GitHub Sponsors enabled
"commit_authors_90d": list,         # For bot filtering
```

## Success Criteria

1. Issue response time signal implemented and tested
2. PR merge velocity signal implemented and tested
3. Abandonment risk uses proper survival analysis
4. Confidence intervals returned with scores
5. Bot commits filtered from activity metrics
6. All existing tests pass (1588 lines of tests!)
7. Methodology documentation updated

## Testing Requirements

The scoring module has excellent test coverage. Run:
```bash
cd /home/iebt/projects/startup-experiment/work/dephealth
pytest tests/test_scoring.py -v
```

Add new tests for:
- Issue response time score calculation
- PR velocity score calculation
- Confidence interval generation
- Bot commit filtering
- Weibull-based risk calculation

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 3 for full algorithm analysis.

Also review `landing-page/src/pages/methodology.astro` for current documentation that needs updating.
