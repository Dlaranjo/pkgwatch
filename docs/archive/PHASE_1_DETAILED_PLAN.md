# Phase 1: MVP Build - Detailed Implementation Plan

**Created:** January 7, 2026
**Target Duration:** 6 weeks (Weeks 3-8 of overall plan)
**Goal:** Working API + CLI for npm packages with validated accuracy

---

## Overview

Phase 1 is divided into three sub-phases:
1. **Data Pipeline (Week 3-4)** - Collect and store package health data
2. **Scoring Engine (Week 5-6)** - Implement and validate health scoring
3. **API + CLI (Week 7-8)** - Build user-facing interfaces

---

## Part 1: Data Pipeline (Week 3-4)

### 1.1 Infrastructure Setup

#### AWS Account Configuration
```
Tasks:
├── 1.1.1 Create/configure AWS account
├── 1.1.2 Set up AWS CLI and credentials
├── 1.1.3 Configure AWS CDK or SAM for IaC
├── 1.1.4 Set up cost alerts ($50, $100, $200 thresholds)
└── 1.1.5 Create development and production environments
```

**Tech Stack:**
- AWS CDK (TypeScript) for infrastructure as code
- Separate dev/prod stages

#### DynamoDB Tables
```
Tables to create:
├── packages (main package data)
│   ├── PK: ecosystem#package_name
│   ├── SK: version or "LATEST"
│   └── GSI: health_score for querying risky packages
├── package_metrics (time-series health data)
│   ├── PK: ecosystem#package_name
│   ├── SK: timestamp
│   └── TTL: 2 years retention
├── github_repos (GitHub repository data)
│   ├── PK: owner/repo
│   └── Attributes: commits, issues, prs, contributors
├── api_keys (user API key management)
│   ├── PK: api_key_hash
│   └── Attributes: user_id, tier, usage_count
└── users (user accounts)
    ├── PK: user_id
    └── Attributes: email, plan, created_at
```

#### S3 Buckets
```
Buckets:
├── dephealth-raw-data-{env}     # Raw API responses
├── dephealth-processed-{env}    # Processed datasets
└── dephealth-exports-{env}      # User exports, reports
```

### 1.2 GitHub Data Collection

#### GitHub Token Management
```
Tasks:
├── 1.2.1 Create 5 GitHub accounts for token rotation
├── 1.2.2 Generate Personal Access Tokens (classic)
│         Scopes needed: public_repo (read-only)
├── 1.2.3 Store tokens in AWS Secrets Manager
├── 1.2.4 Implement token rotation logic
│         - Track rate limit remaining per token
│         - Auto-switch when approaching limit
└── 1.2.5 Set up monitoring for rate limit usage
```

**Rate Limit Strategy:**
- 5 tokens × 5,000 requests/hour = 25,000 requests/hour
- With caching and batching, sufficient for 10K packages daily

#### GitHub Metrics Collector (Lambda)
```python
# Pseudo-code for github_collector.py
def collect_github_metrics(repo_url):
    """
    Collects:
    - Repository metadata (stars, forks, watchers, created, updated)
    - Commit activity (last 100 commits with dates)
    - Open/closed issue counts
    - Open/closed PR counts
    - Contributors list with commit counts
    - Releases (last 20 with dates)
    - Languages breakdown
    """

    metrics = {
        "repo": repo_url,
        "collected_at": timestamp,
        "stars": int,
        "forks": int,
        "open_issues": int,
        "closed_issues": int,
        "open_prs": int,
        "closed_prs": int,
        "last_commit_date": datetime,
        "commits_last_90_days": int,
        "contributors_active_90d": int,
        "total_contributors": int,
        "bus_factor": int,  # Calculated
        "last_release_date": datetime,
        "releases_last_year": int,
        "avg_issue_response_hours": float,
    }
    return metrics
```

### 1.3 npm Data Collection

#### npm Metadata Collector (Lambda)
```python
# Pseudo-code for npm_collector.py
def collect_npm_metadata(package_name):
    """
    Collects from registry.npmjs.org/{package}:
    - Package metadata
    - Version history
    - Dependencies
    - Repository link
    - Maintainers
    - Deprecation status
    """

    metadata = {
        "package": package_name,
        "collected_at": timestamp,
        "latest_version": str,
        "versions_count": int,
        "last_publish_date": datetime,
        "created_date": datetime,
        "repository_url": str,
        "maintainers": list[str],
        "is_deprecated": bool,
        "deprecation_message": str,
        "dependencies_count": int,
        "weekly_downloads": int,  # From api.npmjs.org
    }
    return metadata
```

#### Target Package Selection
```
Initial Scope: Top 10,000 npm packages by weekly downloads

Selection criteria:
├── Has GitHub repository linked
├── At least 1,000 weekly downloads
├── Not deprecated (for healthy baseline)
└── Mix of package ages (1-10 years)

Additional 200 packages for validation:
├── 50 known abandoned packages
├── 50 known compromised packages
├── 50 at-risk packages (core-js, etc.)
└── 50 confirmed healthy packages
```

### 1.4 BigQuery Integration (Historical Data)

#### GH Archive Queries
```sql
-- Example: Get commit activity for a repo over 12 months
SELECT
  DATE_TRUNC(DATE(created_at), MONTH) as month,
  COUNT(*) as commit_count,
  COUNT(DISTINCT actor.login) as unique_committers
FROM `githubarchive.year.2025`
WHERE
  type = 'PushEvent'
  AND repo.name = 'lodash/lodash'
GROUP BY month
ORDER BY month DESC
```

```
Tasks:
├── 1.4.1 Set up GCP project with BigQuery access
├── 1.4.2 Create service account for Lambda access
├── 1.4.3 Write query templates for key metrics:
│   ├── Monthly commit counts by repo
│   ├── Monthly contributor counts
│   ├── Issue creation/resolution trends
│   ├── Star/fork growth trajectory
│   └── Release frequency
├── 1.4.4 Build Lambda function for BigQuery queries
├── 1.4.5 Optimize queries for cost (partition filters)
└── 1.4.6 Backfill 24 months of historical data
```

**Cost Estimate:**
- Free tier: 1 TB/month
- Expected usage: ~200 GB/month for 10K packages
- Within free tier initially

### 1.5 deps.dev Integration

#### deps.dev Data Enrichment
```python
# Pseudo-code for depsdev_enricher.py
def enrich_with_depsdev(package_name, ecosystem="npm"):
    """
    Enriches from deps.dev API:
    - Dependency count (direct and transitive)
    - Dependents count (who uses this package)
    - Security advisories
    - License information
    - OpenSSF Scorecard data
    """

    enrichment = {
        "package": package_name,
        "ecosystem": ecosystem,
        "dependencies_direct": int,
        "dependencies_transitive": int,
        "dependents_count": int,
        "advisories": list[advisory],
        "license": str,
        "openssf_score": float,  # 0-10
        "openssf_checks": dict,
    }
    return enrichment
```

### 1.6 Data Pipeline Orchestration

#### EventBridge Scheduler
```
Schedule:
├── Daily at 00:00 UTC: npm metadata refresh (top 10K)
├── Daily at 02:00 UTC: GitHub metrics refresh
├── Daily at 04:00 UTC: deps.dev enrichment
├── Weekly Sunday 00:00: Full re-score all packages
└── Hourly: Process new package additions queue
```

#### Pipeline Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    EventBridge Scheduler                     │
└────────┬──────────────────────────────────────────┬─────────┘
         │                                          │
         v                                          v
┌──────────────────┐                    ┌──────────────────────┐
│  npm_collector   │                    │  github_collector    │
│     Lambda       │                    │      Lambda          │
└────────┬─────────┘                    └──────────┬───────────┘
         │                                         │
         v                                         v
┌──────────────────────────────────────────────────────────────┐
│                        SQS Queue                              │
│              (package processing messages)                    │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             v
                    ┌──────────────────┐
                    │  depsdev_enricher│
                    │     Lambda       │
                    └────────┬─────────┘
                             │
                             v
                    ┌──────────────────┐
                    │   score_engine   │
                    │     Lambda       │
                    └────────┬─────────┘
                             │
                             v
                    ┌──────────────────┐
                    │    DynamoDB      │
                    │   (packages)     │
                    └──────────────────┘
```

---

## Part 2: Scoring Engine (Week 5-6)

### 2.1 Health Score Algorithm

Based on technical validation research (arXiv 2507.21678):

```python
# scoring_engine.py

def calculate_health_score(package_data: dict) -> dict:
    """
    Overall Health Score: 0-100

    Components (weighted):
    - Maintainer Health: 35%
    - Community Health: 25%
    - Security Health: 20%
    - Evolution Health: 20%
    """

    maintainer = calculate_maintainer_health(package_data)  # 0-1
    community = calculate_community_health(package_data)     # 0-1
    security = calculate_security_health(package_data)       # 0-1
    evolution = calculate_evolution_health(package_data)     # 0-1

    health_score = (
        maintainer * 0.35 +
        community * 0.25 +
        security * 0.20 +
        evolution * 0.20
    ) * 100

    return {
        "health_score": round(health_score, 1),
        "components": {
            "maintainer_health": round(maintainer * 100, 1),
            "community_health": round(community * 100, 1),
            "security_health": round(security * 100, 1),
            "evolution_health": round(evolution * 100, 1),
        },
        "risk_level": get_risk_level(health_score),
    }


def calculate_maintainer_health(data: dict) -> float:
    """
    Signals:
    - Recency of last commit (40%)
    - Bus factor / contributor concentration (30%)
    - Issue response latency (30%)
    """
    recency = recency_score(data["days_since_last_commit"])
    bus_factor = bus_factor_score(data["active_maintainers_90d"])
    response = response_latency_score(data["avg_issue_response_hours"])

    return recency * 0.40 + bus_factor * 0.30 + response * 0.30


def recency_score(days: int) -> float:
    """Score based on days since last commit"""
    if days <= 7: return 1.0
    if days <= 30: return 0.9
    if days <= 90: return 0.7
    if days <= 180: return 0.5
    if days <= 365: return 0.3
    if days <= 730: return 0.1
    return 0.0


def bus_factor_score(active_maintainers: int) -> float:
    """Score based on active maintainer count (last 90 days)"""
    if active_maintainers >= 5: return 1.0
    if active_maintainers >= 3: return 0.8
    if active_maintainers >= 2: return 0.5
    if active_maintainers == 1: return 0.2
    return 0.0


def response_latency_score(median_hours: float) -> float:
    """Score based on median time to first response on issues"""
    if median_hours <= 24: return 1.0
    if median_hours <= 72: return 0.8
    if median_hours <= 168: return 0.6  # 1 week
    if median_hours <= 720: return 0.3  # 1 month
    return 0.0


def calculate_community_health(data: dict) -> float:
    """
    Signals:
    - Contributor diversity (30%)
    - Issue resolution rate (25%)
    - PR merge rate (25%)
    - Engagement trend (20%)
    """
    # Implementation details...
    pass


def calculate_security_health(data: dict) -> float:
    """
    Signals:
    - OpenSSF Scorecard score (40%)
    - Known vulnerabilities (30%)
    - Security policy presence (15%)
    - Dependency freshness (15%)
    """
    # Implementation details...
    pass


def calculate_evolution_health(data: dict) -> float:
    """
    Signals:
    - Release cadence (35%)
    - Commit trend (35%)
    - Feature vs bugfix ratio (30%)
    """
    # Implementation details...
    pass


def get_risk_level(score: float) -> str:
    if score >= 80: return "LOW"
    if score >= 60: return "MEDIUM"
    if score >= 40: return "HIGH"
    return "CRITICAL"
```

### 2.2 Abandonment Risk Model

```python
# abandonment_model.py

def predict_abandonment_risk(package_data: dict, time_horizon_months: int = 12) -> dict:
    """
    Predicts probability of abandonment within time horizon.

    Based on survival analysis approach from arXiv 2507.21678.
    Simplified implementation using weighted risk factors.
    """

    # Risk factors (higher = more likely to be abandoned)
    risk_factors = {
        "no_commits_180d": package_data["days_since_last_commit"] > 180,
        "single_maintainer": package_data["active_maintainers_90d"] <= 1,
        "no_releases_year": package_data["days_since_last_release"] > 365,
        "declining_downloads": package_data["download_trend"] < 0,
        "high_issue_backlog": package_data["open_issues"] > 100 and
                              package_data["issue_resolution_rate"] < 0.3,
        "no_response_to_issues": package_data["avg_issue_response_hours"] > 720,
        "declining_contributors": package_data["contributor_trend"] < 0,
        "deprecation_signals": package_data.get("is_deprecated", False),
    }

    # Weighted risk calculation
    weights = {
        "no_commits_180d": 0.25,
        "single_maintainer": 0.20,
        "no_releases_year": 0.15,
        "declining_downloads": 0.10,
        "high_issue_backlog": 0.10,
        "no_response_to_issues": 0.10,
        "declining_contributors": 0.05,
        "deprecation_signals": 0.05,
    }

    risk_score = sum(
        weights[factor] for factor, is_present in risk_factors.items()
        if is_present
    )

    # Adjust for time horizon
    time_multiplier = min(time_horizon_months / 12, 2.0)  # Caps at 24 months
    adjusted_risk = min(risk_score * time_multiplier, 1.0)

    return {
        "abandonment_probability": round(adjusted_risk * 100, 1),
        "time_horizon_months": time_horizon_months,
        "risk_factors": {k: v for k, v in risk_factors.items() if v},
        "confidence": calculate_confidence(package_data),
    }
```

### 2.3 Confidence Scoring

```python
def calculate_confidence(data: dict) -> dict:
    """
    How confident are we in our predictions?

    Based on:
    - Data completeness (40%)
    - Data recency (30%)
    - Historical depth (30%)
    """

    # Data completeness: what percentage of signals do we have?
    required_fields = [
        "days_since_last_commit",
        "active_maintainers_90d",
        "avg_issue_response_hours",
        "open_issues",
        "weekly_downloads",
        "last_release_date",
        "openssf_score",
    ]
    completeness = sum(1 for f in required_fields if data.get(f) is not None) / len(required_fields)

    # Data recency: how fresh is our data?
    hours_since_update = (datetime.now() - data["collected_at"]).total_seconds() / 3600
    recency = 1.0 if hours_since_update < 24 else (1.0 - min(hours_since_update / 168, 1.0))

    # Historical depth: how much history do we have?
    months_of_history = data.get("history_months", 0)
    depth = min(months_of_history / 12, 1.0)

    confidence_score = completeness * 0.40 + recency * 0.30 + depth * 0.30

    return {
        "score": round(confidence_score * 100, 1),
        "level": get_confidence_level(confidence_score),
        "factors": {
            "data_completeness": round(completeness * 100, 1),
            "data_recency": round(recency * 100, 1),
            "historical_depth": round(depth * 100, 1),
        }
    }


def get_confidence_level(score: float) -> str:
    if score >= 0.8: return "VERY_HIGH"
    if score >= 0.6: return "HIGH"
    if score >= 0.4: return "MEDIUM"
    return "LOW"
```

### 2.4 Backtest Validation

#### Backtest Dataset (30 packages minimum)
```
Category A: Known Abandoned (10 packages)
├── left-pad (March 2016)
├── request (February 2020)
├── moment (September 2020 - maintenance mode)
├── event-stream (September 2018)
├── colors (January 2022)
├── faker (January 2022)
├── hawk 3.x (2016)
├── trim (~2014)
├── node-uuid (deprecated)
└── underscore.string (stale)

Category B: At-Risk (5 packages)
├── core-js
├── debug (single maintainer)
├── qs (minimal maintenance)
├── node-fetch (maintenance mode)
└── uuid (minimal updates)

Category C: Healthy Control (15 packages)
├── react
├── express
├── lodash
├── axios
├── typescript
├── eslint
├── webpack
├── vue
├── next
├── nest
├── jest
├── prettier
├── tailwindcss
├── vite
└── esbuild
```

#### Backtest Process
```python
# backtest.py

def run_backtest(test_packages: list, historical_date: str) -> dict:
    """
    1. Take historical snapshot at date T (e.g., 12 months ago)
    2. Calculate health score using only data available at T
    3. Compare prediction to actual outcome today
    4. Measure precision, recall, F1 score
    """

    results = []
    for package in test_packages:
        # Get historical data as of test date
        historical_data = get_historical_snapshot(package["name"], historical_date)

        # Calculate score using only historical data
        prediction = calculate_health_score(historical_data)
        abandonment_risk = predict_abandonment_risk(historical_data, 12)

        # Get actual current status
        current_status = get_current_status(package["name"])
        actual_abandoned = current_status["is_abandoned"]

        # Record result
        results.append({
            "package": package["name"],
            "predicted_score": prediction["health_score"],
            "predicted_risk": abandonment_risk["abandonment_probability"],
            "predicted_abandoned": prediction["health_score"] < 40,
            "actual_abandoned": actual_abandoned,
            "correct": (prediction["health_score"] < 40) == actual_abandoned,
        })

    # Calculate metrics
    true_positives = sum(1 for r in results if r["predicted_abandoned"] and r["actual_abandoned"])
    false_positives = sum(1 for r in results if r["predicted_abandoned"] and not r["actual_abandoned"])
    false_negatives = sum(1 for r in results if not r["predicted_abandoned"] and r["actual_abandoned"])
    true_negatives = sum(1 for r in results if not r["predicted_abandoned"] and not r["actual_abandoned"])

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "accuracy": (true_positives + true_negatives) / len(results),
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "confusion_matrix": {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "true_negatives": true_negatives,
        },
        "detailed_results": results,
    }
```

**Target Metrics:**
- Accuracy: ≥75%
- Precision: ≥70% (avoid false alarms)
- Recall: ≥80% (catch real risks)

---

## Part 3: API + CLI (Week 7-8)

### 3.1 API Schema (OpenAPI)

```yaml
# openapi.yaml
openapi: 3.0.3
info:
  title: PkgWatch API
  version: 1.0.0
  description: Predictive health intelligence for open source packages

servers:
  - url: https://api.dephealth.laranjo.dev/v1

security:
  - ApiKeyAuth: []

paths:
  /packages/{ecosystem}/{name}:
    get:
      summary: Get package health score
      parameters:
        - name: ecosystem
          in: path
          required: true
          schema:
            type: string
            enum: [npm, pypi, cargo]
        - name: name
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Package health data
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/PackageHealth'

  /packages/{ecosystem}/{name}/history:
    get:
      summary: Get health score history
      parameters:
        - name: ecosystem
          in: path
          required: true
          schema:
            type: string
        - name: name
          in: path
          required: true
          schema:
            type: string
        - name: months
          in: query
          schema:
            type: integer
            default: 12
      responses:
        '200':
          description: Health score history

  /scan:
    post:
      summary: Scan package.json/requirements.txt
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ScanRequest'
      responses:
        '200':
          description: Scan results
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ScanResult'

components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key

  schemas:
    PackageHealth:
      type: object
      properties:
        package:
          type: string
        ecosystem:
          type: string
        health_score:
          type: number
          minimum: 0
          maximum: 100
        risk_level:
          type: string
          enum: [LOW, MEDIUM, HIGH, CRITICAL]
        abandonment_risk:
          type: object
          properties:
            probability:
              type: number
            time_horizon_months:
              type: integer
            risk_factors:
              type: array
              items:
                type: string
        components:
          type: object
          properties:
            maintainer_health:
              type: number
            community_health:
              type: number
            security_health:
              type: number
            evolution_health:
              type: number
        confidence:
          type: object
          properties:
            score:
              type: number
            level:
              type: string
        signals:
          type: object
          properties:
            days_since_last_commit:
              type: integer
            active_maintainers:
              type: integer
            open_issues:
              type: integer
            weekly_downloads:
              type: integer
            has_vulnerabilities:
              type: boolean
        last_updated:
          type: string
          format: date-time

    ScanRequest:
      type: object
      properties:
        type:
          type: string
          enum: [package.json, requirements.txt, Cargo.toml]
        content:
          type: string

    ScanResult:
      type: object
      properties:
        total_packages:
          type: integer
        risky_packages:
          type: integer
        packages:
          type: array
          items:
            $ref: '#/components/schemas/PackageHealth'
```

### 3.2 API Implementation

#### Lambda Handler Structure
```
functions/
├── api/
│   ├── get_package.py        # GET /packages/{ecosystem}/{name}
│   ├── get_history.py        # GET /packages/{ecosystem}/{name}/history
│   ├── post_scan.py          # POST /scan
│   ├── get_usage.py          # GET /usage
│   └── middleware/
│       ├── auth.py           # API key validation
│       ├── rate_limit.py     # Rate limiting by tier
│       └── logging.py        # Request logging
├── collectors/
│   ├── npm_collector.py
│   ├── github_collector.py
│   └── depsdev_enricher.py
├── scoring/
│   ├── health_score.py
│   ├── abandonment_risk.py
│   └── confidence.py
└── shared/
    ├── dynamo.py             # DynamoDB helpers
    ├── github_client.py      # GitHub API client
    └── models.py             # Data models
```

### 3.3 API Key Management

```python
# api_key_manager.py

import hashlib
import secrets
from datetime import datetime

def generate_api_key() -> tuple[str, str]:
    """Generate a new API key and its hash"""
    api_key = f"dh_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    return api_key, key_hash


def validate_api_key(api_key: str) -> dict | None:
    """Validate API key and return user info"""
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    # Look up in DynamoDB
    response = dynamo.get_item(
        TableName='api_keys',
        Key={'key_hash': key_hash}
    )

    if 'Item' not in response:
        return None

    item = response['Item']
    return {
        "user_id": item['user_id'],
        "tier": item['tier'],
        "rate_limit": TIER_LIMITS[item['tier']],
        "usage_this_month": item['usage_count'],
    }


TIER_LIMITS = {
    "free": {"requests_per_month": 1000, "requests_per_minute": 10},
    "starter": {"requests_per_month": 10000, "requests_per_minute": 60},
    "pro": {"requests_per_month": 50000, "requests_per_minute": 120},
    "business": {"requests_per_month": 200000, "requests_per_minute": 300},
}
```

### 3.4 Rate Limiting

```python
# rate_limiter.py

import time
from functools import wraps

def rate_limit(func):
    """Rate limiting decorator using DynamoDB atomic counters"""
    @wraps(func)
    def wrapper(event, context):
        api_key = event['headers'].get('X-API-Key')
        user = validate_api_key(api_key)

        if not user:
            return {"statusCode": 401, "body": "Invalid API key"}

        # Check monthly limit
        if user['usage_this_month'] >= user['rate_limit']['requests_per_month']:
            return {
                "statusCode": 429,
                "body": "Monthly rate limit exceeded",
                "headers": {"X-RateLimit-Reset": get_month_end_timestamp()}
            }

        # Check per-minute limit (using sliding window in Redis/DynamoDB)
        minute_key = f"{user['user_id']}:{int(time.time() / 60)}"
        minute_count = increment_counter(minute_key, ttl=120)

        if minute_count > user['rate_limit']['requests_per_minute']:
            return {
                "statusCode": 429,
                "body": "Rate limit exceeded. Please slow down.",
                "headers": {"Retry-After": "60"}
            }

        # Increment monthly counter
        increment_monthly_usage(user['user_id'])

        # Execute the actual function
        return func(event, context)

    return wrapper
```

### 3.5 CLI Tool

```
CLI: npx dephealth

Commands:
├── dephealth check <package>     # Check single package
├── dephealth scan                # Scan package.json in current dir
├── dephealth scan --file <path>  # Scan specific file
├── dephealth login               # Configure API key
├── dephealth usage               # Show API usage
└── dephealth --help              # Help
```

```typescript
// cli/src/index.ts
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';

const program = new Command();

program
  .name('dephealth')
  .description('Check the health of your dependencies')
  .version('1.0.0');

program
  .command('check <package>')
  .description('Check health score for a package')
  .option('-e, --ecosystem <eco>', 'Package ecosystem', 'npm')
  .action(async (packageName, options) => {
    const spinner = ora('Checking package health...').start();

    try {
      const result = await api.getPackageHealth(packageName, options.ecosystem);
      spinner.stop();

      console.log();
      console.log(chalk.bold(packageName));
      console.log();

      const scoreColor = result.health_score >= 80 ? 'green'
        : result.health_score >= 60 ? 'yellow'
        : result.health_score >= 40 ? 'orange'
        : 'red';

      console.log(`Health Score: ${chalk[scoreColor].bold(`${result.health_score}/100`)}`);
      console.log(`Risk Level: ${chalk[scoreColor](result.risk_level)}`);
      console.log();
      console.log('Signals:');
      console.log(`  • Last commit: ${result.signals.days_since_last_commit} days ago`);
      console.log(`  • Active maintainers: ${result.signals.active_maintainers}`);
      console.log(`  • Open issues: ${result.signals.open_issues}`);
      console.log(`  • Weekly downloads: ${formatNumber(result.signals.weekly_downloads)}`);

      if (result.abandonment_risk.probability > 30) {
        console.log();
        console.log(chalk.yellow(`⚠️  ${result.abandonment_risk.probability}% abandonment risk in next 12 months`));
        console.log('   Risk factors:');
        result.abandonment_risk.risk_factors.forEach(factor => {
          console.log(`   • ${factor}`);
        });
      }
    } catch (error) {
      spinner.fail('Failed to check package');
      console.error(error.message);
      process.exit(1);
    }
  });

program
  .command('scan')
  .description('Scan dependencies in current directory')
  .option('-f, --file <path>', 'Path to package.json')
  .action(async (options) => {
    // Implementation...
  });
```

### 3.6 Stripe Billing Setup

```
Tasks:
├── 3.6.1 Create Stripe account
├── 3.6.2 Configure products and prices:
│   ├── Free: $0/month (1,000 API calls)
│   ├── Starter: $29/month (10,000 API calls)
│   ├── Pro: $99/month (50,000 API calls)
│   └── Business: $299/month (200,000 API calls)
├── 3.6.3 Set up Stripe Checkout for subscriptions
├── 3.6.4 Implement webhook handlers:
│   ├── checkout.session.completed
│   ├── customer.subscription.updated
│   ├── customer.subscription.deleted
│   └── invoice.payment_failed
├── 3.6.5 Build billing portal integration
└── 3.6.6 Create upgrade prompts in API responses
```

---

## Project Structure

```
dephealth/
├── infrastructure/           # AWS CDK
│   ├── lib/
│   │   ├── api-stack.ts
│   │   ├── data-pipeline-stack.ts
│   │   └── storage-stack.ts
│   └── cdk.json
├── functions/                # Lambda functions
│   ├── api/
│   ├── collectors/
│   ├── scoring/
│   └── shared/
├── cli/                      # CLI package
│   ├── src/
│   ├── package.json
│   └── tsconfig.json
├── tests/
│   ├── unit/
│   ├── integration/
│   └── backtest/
├── docs/
│   ├── api.md
│   └── methodology.md
└── README.md
```

---

## Weekly Milestones

### Week 3
- [ ] AWS infrastructure deployed (CDK)
- [ ] DynamoDB tables created
- [ ] S3 buckets configured
- [ ] GitHub tokens set up (5 accounts)
- [ ] npm collector Lambda working

### Week 4
- [ ] GitHub collector Lambda working
- [ ] deps.dev enricher Lambda working
- [ ] BigQuery project configured
- [ ] Historical data backfill started
- [ ] 10K packages in database

### Week 5
- [ ] Health score algorithm implemented
- [ ] Abandonment risk model implemented
- [ ] Confidence scoring implemented
- [ ] Unit tests passing

### Week 6
- [ ] Backtest framework built
- [ ] 30 package backtest completed
- [ ] Accuracy ≥75% achieved
- [ ] Model weights tuned

### Week 7
- [ ] API Gateway configured
- [ ] API endpoints deployed
- [ ] API key management working
- [ ] Rate limiting implemented
- [ ] API documentation published

### Week 8
- [ ] CLI tool published to npm
- [ ] Stripe billing integrated
- [ ] Pricing tiers configured
- [ ] End-to-end testing complete
- [ ] Ready for soft launch

---

## Success Criteria for Phase 1

| Metric | Target |
|--------|--------|
| Packages indexed | 10,000 npm packages |
| Historical data | 24 months of history |
| Scoring accuracy | ≥75% on backtest |
| API response time | <500ms p95 |
| API uptime | 99.5% |
| CLI published | Yes |
| Documentation complete | Yes |

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| GitHub rate limits hit | Medium | High | 5 token rotation, aggressive caching |
| BigQuery costs exceed budget | Low | Medium | Query optimization, partition filters |
| Scoring accuracy <70% | Medium | High | Iterate on model, add more signals |
| AWS costs spike | Low | Medium | Cost alerts, reserved capacity |
| Data collection takes too long | Medium | Medium | Parallelize, prioritize top packages |

---

## Decision Points

Before proceeding to Phase 2:
1. **Accuracy checkpoint:** Is backtest accuracy ≥75%?
2. **Cost checkpoint:** Are AWS costs sustainable (<$100/month)?
3. **Data quality checkpoint:** Do we have complete data for 10K packages?

---

*Plan created: January 7, 2026*
