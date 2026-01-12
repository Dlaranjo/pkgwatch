# Phase 1: Lean MVP - Revised Implementation Plan

**Created:** January 7, 2026
**Updated:** January 7, 2026 (incorporated review feedback)
**Duration:** 7 weeks
**Goal:** Working API for npm packages with validated scoring accuracy

---

## Executive Summary

This is a streamlined Phase 1 plan that incorporates feedback from two rounds of technical review. Key changes:

| Dimension | Original | Lean MVP |
|-----------|----------|----------|
| Packages | 10,000 | 2,500 |
| History | 24 months | 6 months (via deps.dev) |
| Refresh | Daily all | Tiered (daily/weekly) |
| CLI | Yes | No (Phase 2) |
| Data source | GitHub-heavy | deps.dev-primary |
| Timeline | 6-8 weeks | 7 weeks |
| BigQuery | Required | Not needed (deps.dev sufficient) |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     DATA COLLECTION                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐               │
│  │ deps.dev │    │   npm    │    │  GitHub  │               │
│  │  (FREE)  │    │   API    │    │   API    │               │
│  │ PRIMARY  │    │          │    │ (5K/hr)  │               │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘               │
│       │               │               │                      │
│       └───────────────┴───────────────┘                      │
│                       │                                      │
│              ┌────────▼────────┐                             │
│              │  EventBridge    │                             │
│              │  (Scheduler)    │                             │
│              └────────┬────────┘                             │
│                       │                                      │
│              ┌────────▼────────┐                             │
│              │      SQS        │                             │
│              │  (Job Queue)    │                             │
│              └────────┬────────┘                             │
│                       │                                      │
│              ┌────────▼────────┐                             │
│              │    Lambda       │                             │
│              │  (Collectors)   │                             │
│              └────────┬────────┘                             │
│                       │                                      │
│         ┌─────────────┴─────────────┐                        │
│         ▼                           ▼                        │
│   ┌──────────┐               ┌──────────┐                    │
│   │ DynamoDB │               │    S3    │                    │
│   │ (Scores) │               │  (Raw)   │                    │
│   └──────────┘               └──────────┘                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                        API LAYER                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│              ┌──────────────────┐                            │
│              │   API Gateway    │                            │
│              │     (REST)       │                            │
│              └────────┬─────────┘                            │
│                       │                                      │
│              ┌────────▼─────────┐                            │
│              │     Lambda       │                            │
│              │   (Handlers)     │                            │
│              └────────┬─────────┘                            │
│                       │                                      │
│              ┌────────▼─────────┐                            │
│              │    DynamoDB      │                            │
│              └──────────────────┘                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Week 1-2: Data Foundation

### 1.1 AWS Infrastructure Setup

**Day 1-2: Base Infrastructure**

```
infrastructure/
├── lib/
│   ├── storage-stack.ts      # DynamoDB + S3
│   ├── api-stack.ts          # API Gateway + Lambda
│   └── pipeline-stack.ts     # EventBridge + SQS + Collectors
├── bin/
│   └── app.ts
└── cdk.json
```

**DynamoDB Tables**

```typescript
// packages table
// PK: ecosystem#name, SK: "LATEST" or version
// GSI: risk-level-index (risk_level -> last_updated) for querying risky packages
{
  pk: "npm#lodash",              // ecosystem#name
  sk: "LATEST",                  // or version number
  health_score: 82,
  risk_level: "LOW",
  components: {...},
  signals: {...},
  confidence: {...},
  last_updated: "2026-01-07T...",
  tier: 1                        // For refresh prioritization (1=daily, 2=3-day, 3=weekly)
}

// api_keys table
// PK: user_id, SK: key_hash
// GSI: key-hash-index (key_hash as PK) for O(1) key validation lookups
{
  pk: "user_123",
  sk: "a1b2c3d4...",             // SHA-256 hash of API key
  key_hash: "a1b2c3d4...",       // Duplicated for GSI (GSI needs its own PK)
  tier: "starter",
  requests_this_month: 1523,
  created_at: "2026-01-01T..."
}

// CDK Definition for api_keys table with GSI:
// const apiKeysTable = new dynamodb.Table(this, 'ApiKeys', {
//   partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
//   sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
// });
// apiKeysTable.addGlobalSecondaryIndex({
//   indexName: 'key-hash-index',
//   partitionKey: { name: 'key_hash', type: dynamodb.AttributeType.STRING },
// });
```

**S3 Buckets**
```
dephealth-raw-data/       # Raw API responses (for debugging)
```

**Secrets Manager**
```
dephealth/github-token    # GitHub PAT for API access
dephealth/stripe-secret   # Stripe secret key
dephealth/stripe-webhook  # Stripe webhook signing secret
```

### 1.2 deps.dev Integration (Primary Data Source)

deps.dev is the MVP's secret weapon - **no rate limits**, rich data.

```python
# collectors/depsdev_collector.py

import httpx
import asyncio
from urllib.parse import quote
from typing import Optional

DEPSDEV_API = "https://api.deps.dev/v3"

def encode_package_name(name: str) -> str:
    """
    URL-encode package names for deps.dev API.

    Scoped packages like @babel/core must be encoded:
    @babel/core -> %40babel%2Fcore
    """
    return quote(name, safe='')


def encode_repo_url(url: str) -> str:
    """
    Encode repository URL for deps.dev projects endpoint.

    github.com/lodash/lodash -> github.com%2Flodash%2Flodash
    """
    return quote(url, safe='')


async def retry_with_backoff(func, *args, max_retries=3, base_delay=1.0):
    """
    Retry async function with exponential backoff.
    """
    for attempt in range(max_retries):
        try:
            return await func(*args)
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            if attempt == max_retries - 1:
                raise
            delay = base_delay * (2 ** attempt)
            await asyncio.sleep(delay)


async def get_package_info(name: str, ecosystem: str = "npm") -> dict:
    """
    Fetch comprehensive package data from deps.dev.

    Returns:
    - Version info
    - Dependencies (direct + transitive count)
    - Dependents count (who uses this)
    - Security advisories
    - License
    - OpenSSF Scorecard
    - GitHub repo link
    """
    encoded_name = encode_package_name(name)

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Get package versions
        pkg_resp = await retry_with_backoff(
            client.get,
            f"{DEPSDEV_API}/systems/{ecosystem}/packages/{encoded_name}"
        )
        pkg_resp.raise_for_status()
        pkg_data = pkg_resp.json()

        # Get latest version details
        latest_version = pkg_data.get("defaultVersion", "")
        encoded_version = quote(latest_version, safe='')
        version_resp = await retry_with_backoff(
            client.get,
            f"{DEPSDEV_API}/systems/{ecosystem}/packages/{encoded_name}/versions/{encoded_version}"
        )
        version_resp.raise_for_status()
        version_data = version_resp.json()

        # Get project info (includes OpenSSF score)
        project_url = version_data.get("links", {}).get("repo", "")
        if project_url:
            encoded_project = encode_repo_url(project_url)
            try:
                project_resp = await retry_with_backoff(
                    client.get,
                    f"{DEPSDEV_API}/projects/{encoded_project}"
                )
                project_resp.raise_for_status()
                project_data = project_resp.json()
            except httpx.HTTPStatusError:
                project_data = {}  # Project not found, continue without
        else:
            project_data = {}

        return {
            "name": name,
            "ecosystem": ecosystem,
            "latest_version": latest_version,
            "published_at": version_data.get("publishedAt"),
            "licenses": version_data.get("licenses", []),
            "dependencies_direct": len(version_data.get("dependencies", [])),
            "advisories": version_data.get("advisories", []),
            "repository_url": project_url,
            "openssf_score": project_data.get("scorecard", {}).get("overallScore"),
            "openssf_checks": project_data.get("scorecard", {}).get("checks", []),
            "stars": project_data.get("stars"),
            "forks": project_data.get("forks"),
        }


async def get_dependents_count(name: str, ecosystem: str = "npm") -> int:
    """Get count of packages that depend on this one."""
    encoded_name = encode_package_name(name)

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await retry_with_backoff(
            client.get,
            f"{DEPSDEV_API}/systems/{ecosystem}/packages/{encoded_name}/dependents"
        )
        resp.raise_for_status()
        data = resp.json()
        return len(data.get("dependents", []))
```

### 1.3 npm Metadata Collector

```python
# collectors/npm_collector.py

import httpx

async def get_npm_metadata(name: str) -> dict:
    """
    Fetch npm-specific metadata.

    Rate limit: ~1000/hour (undocumented but safe)
    """
    async with httpx.AsyncClient() as client:
        # Package metadata
        resp = await client.get(f"https://registry.npmjs.org/{name}")
        data = resp.json()

        latest = data.get("dist-tags", {}).get("latest", "")
        time_data = data.get("time", {})

        # Download stats (separate API)
        downloads_resp = await client.get(
            f"https://api.npmjs.org/downloads/point/last-week/{name}"
        )
        downloads = downloads_resp.json().get("downloads", 0)

        return {
            "name": name,
            "latest_version": latest,
            "created_at": time_data.get("created"),
            "last_published": time_data.get(latest) or time_data.get("modified"),
            "maintainers": [m.get("name") for m in data.get("maintainers", [])],
            "is_deprecated": "deprecated" in data.get("versions", {}).get(latest, {}),
            "weekly_downloads": downloads,
            "repository_url": data.get("repository", {}).get("url", ""),
        }
```

### 1.4 GitHub Metrics Collector (Conservative)

```python
# collectors/github_collector.py

import httpx
import asyncio
from datetime import datetime, timedelta
from typing import Optional
import logging

GITHUB_API = "https://api.github.com"
logger = logging.getLogger(__name__)

class GitHubCollector:
    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self._rate_limit_remaining = 5000
        self._rate_limit_reset = None

    async def _request_with_retry(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: dict = None,
        max_retries: int = 3
    ) -> Optional[dict]:
        """Make request with exponential backoff retry."""
        for attempt in range(max_retries):
            try:
                resp = await client.get(url, params=params, headers=self.headers)

                # Track rate limits
                self._rate_limit_remaining = int(resp.headers.get("X-RateLimit-Remaining", 5000))
                self._rate_limit_reset = resp.headers.get("X-RateLimit-Reset")

                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 404:
                    return None  # Repo not found
                elif resp.status_code == 403 and self._rate_limit_remaining == 0:
                    # Rate limited - wait until reset
                    wait_time = max(0, int(self._rate_limit_reset) - int(datetime.now().timestamp()))
                    logger.warning(f"Rate limited. Waiting {wait_time}s")
                    await asyncio.sleep(min(wait_time, 60))  # Cap at 60s
                elif resp.status_code == 409:
                    # Empty repository (no commits)
                    return []
                else:
                    resp.raise_for_status()

            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                if attempt == max_retries - 1:
                    logger.error(f"Failed after {max_retries} retries: {url}")
                    raise
                delay = 2 ** attempt
                await asyncio.sleep(delay)

        return None

    async def get_repo_metrics(self, owner: str, repo: str) -> dict:
        """
        Fetch essential GitHub metrics.

        Optimized to use minimal API calls (~3-4 per repo).
        Rate limit: 5,000/hour with token.
        Includes retry logic with exponential backoff.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            # 1. Repo metadata (1 call - gets stars, forks, issues, updated_at)
            repo_data = await self._request_with_retry(
                client,
                f"{GITHUB_API}/repos/{owner}/{repo}"
            )

            if repo_data is None:
                return {"error": "repository_not_found", "owner": owner, "repo": repo}

            # 2. Recent commits (1 call - last 90 days)
            since = (datetime.now() - timedelta(days=90)).isoformat()
            commits = await self._request_with_retry(
                client,
                f"{GITHUB_API}/repos/{owner}/{repo}/commits",
                params={"since": since, "per_page": 100}
            ) or []

            # 3. Contributors (1 call)
            contributors = await self._request_with_retry(
                client,
                f"{GITHUB_API}/repos/{owner}/{repo}/contributors",
                params={"per_page": 100}
            ) or []

            # Calculate metrics
            unique_committers_90d = len(set(
                c.get("author", {}).get("login")
                for c in commits
                if isinstance(c, dict) and c.get("author")
            ))

            # Days since last commit
            days_since_commit = 999
            if commits and isinstance(commits, list) and len(commits) > 0:
                last_commit_date = commits[0].get("commit", {}).get("author", {}).get("date")
                if last_commit_date:
                    try:
                        last_commit = datetime.fromisoformat(last_commit_date.replace("Z", "+00:00"))
                        days_since_commit = (datetime.now(last_commit.tzinfo) - last_commit).days
                    except ValueError:
                        pass

            return {
                "owner": owner,
                "repo": repo,
                "stars": repo_data.get("stargazers_count", 0),
                "forks": repo_data.get("forks_count", 0),
                "open_issues": repo_data.get("open_issues_count", 0),
                "updated_at": repo_data.get("updated_at"),
                "pushed_at": repo_data.get("pushed_at"),
                "days_since_last_commit": days_since_commit,
                "commits_90d": len(commits) if isinstance(commits, list) else 0,
                "active_contributors_90d": unique_committers_90d,
                "total_contributors": len(contributors) if isinstance(contributors, list) else 0,
                "archived": repo_data.get("archived", False),
            }

    @property
    def rate_limit_remaining(self) -> int:
        return self._rate_limit_remaining
```

### 1.5 Package Selection (2,500 packages)

```python
# scripts/select_packages.py

"""
Select top 2,500 npm packages for MVP.

Criteria:
- Has GitHub repository
- >1,000 weekly downloads
- Not deprecated
- Mix of package ages
"""

TOP_PACKAGES_URL = "https://raw.githubusercontent.com/anvaka/npmrank/master/data/npm-rank.json"

async def get_top_packages(limit: int = 2500) -> list[str]:
    """Fetch top npm packages by PageRank score."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(TOP_PACKAGES_URL)
        all_packages = resp.json()

        # Filter and limit
        selected = []
        for pkg in all_packages[:limit * 2]:  # Get more, filter down
            name = pkg.get("name")
            if name and not name.startswith("@types/"):  # Skip type packages
                selected.append(name)
                if len(selected) >= limit:
                    break

        return selected
```

### 1.6 Data Pipeline (EventBridge + SQS + Lambda)

**Refresh Schedule**

| Tier | Packages | Frequency | GitHub API Budget |
|------|----------|-----------|-------------------|
| Tier 1 | Top 100 | Daily | 400 calls/day |
| Tier 2 | Top 500 | Every 3 days | 533 calls/day |
| Tier 3 | All 2,500 | Weekly | 1,428 calls/day |
| **Total** | | | **~2,400 calls/day** |

With 5,000 requests/hour, this is very comfortable.

**Tier Promotion Logic**

Packages can be promoted to higher tiers based on events:

```python
# collectors/tier_manager.py

def check_tier_promotion(package_data: dict, current_tier: int) -> int:
    """
    Promote packages to higher refresh tiers based on:
    - New security advisories (CVE) -> Tier 1
    - High request volume -> Tier 1
    - Risk level change to CRITICAL/HIGH -> Tier 1
    """
    new_tier = current_tier

    # New CVE = immediate Tier 1
    advisories = package_data.get("advisories", [])
    if any(a.get("severity") in ["CRITICAL", "HIGH"] for a in advisories):
        new_tier = 1

    # Risk level degraded to CRITICAL = Tier 1
    if package_data.get("risk_level") == "CRITICAL":
        new_tier = 1

    # High API request volume (popular package) = Tier 1
    if package_data.get("api_requests_24h", 0) > 100:
        new_tier = 1

    return new_tier
```

```typescript
// infrastructure/lib/pipeline-stack.ts

// Daily refresh trigger
new events.Rule(this, 'DailyRefresh', {
  schedule: events.Schedule.cron({ hour: '2', minute: '0' }),
  targets: [new targets.LambdaFunction(refreshDispatcher)],
});

// SQS queue for package processing
const packageQueue = new sqs.Queue(this, 'PackageQueue', {
  visibilityTimeout: Duration.minutes(5),
  deadLetterQueue: {
    queue: dlq,
    maxReceiveCount: 3,
  },
});
```

---

## Week 3-4: Scoring Engine

### 2.1 Health Score Algorithm (Continuous Functions)

```python
# scoring/health_score.py

import math
from datetime import datetime
from typing import Optional

def calculate_health_score(data: dict) -> dict:
    """
    Calculate overall health score (0-100).

    Components (revised weights based on research):
    - Maintainer Health: 30%
    - User-Centric: 30% (NEW - most predictive per research)
    - Evolution: 25%
    - Community: 15%
    """
    maintainer = _maintainer_health(data)
    user_centric = _user_centric_health(data)
    evolution = _evolution_health(data)
    community = _community_health(data)

    raw_score = (
        maintainer * 0.30 +
        user_centric * 0.30 +
        evolution * 0.25 +
        community * 0.15
    )

    health_score = round(raw_score * 100, 1)
    confidence = _calculate_confidence(data)

    return {
        "health_score": health_score,
        "risk_level": _get_risk_level(health_score),
        "components": {
            "maintainer_health": round(maintainer * 100, 1),
            "user_centric": round(user_centric * 100, 1),
            "evolution_health": round(evolution * 100, 1),
            "community_health": round(community * 100, 1),
        },
        "confidence": confidence,
    }


def _maintainer_health(data: dict) -> float:
    """
    Maintainer activity signals.
    Uses smooth exponential decay, not step functions.
    """
    # Recency score (exponential decay, half-life = 90 days)
    days = data.get("days_since_last_commit", 365)
    recency = math.exp(-0.693 * days / 90)  # 0.693 = ln(2)

    # Bus factor score (sigmoid centered at 2 maintainers)
    maintainers = data.get("active_contributors_90d", 1)
    bus_factor = 1 / (1 + math.exp(-(maintainers - 2)))

    # Combine
    return recency * 0.6 + bus_factor * 0.4


def _user_centric_health(data: dict) -> float:
    """
    User adoption signals - MOST PREDICTIVE per research.
    Uses continuous log-scale functions instead of step functions.
    """
    # Download score: log-scaled continuous function
    # log10(1M) = 6, log10(10M) = 7, we normalize to 0-1
    downloads = data.get("weekly_downloads", 0)
    download_score = min(math.log10(downloads + 1) / 7, 1.0)  # 10M+ = 1.0

    # Dependents: log-scaled (ecosystem position)
    dependents = data.get("dependents_count", 0)
    dependent_score = min(math.log10(dependents + 1) / 4, 1.0)  # 10K+ = 1.0

    # Stars: log-scaled community interest proxy
    stars = data.get("stars", 0)
    star_score = min(math.log10(stars + 1) / 5, 1.0)  # 100K+ = 1.0

    return download_score * 0.5 + dependent_score * 0.3 + star_score * 0.2


def _evolution_health(data: dict) -> float:
    """
    Project evolution signals.
    Uses continuous exponential decay functions.
    """
    # Release recency: exponential decay with 180-day half-life
    last_published = data.get("last_published")
    if last_published:
        try:
            published_date = datetime.fromisoformat(last_published.replace("Z", "+00:00"))
            days_since_release = (datetime.now(published_date.tzinfo) - published_date).days
            release_score = math.exp(-0.693 * days_since_release / 180)
        except:
            release_score = 0.5
    else:
        release_score = 0.5

    # Commit activity: log-scaled continuous function
    # Avoids step function discontinuities
    commits_90d = data.get("commits_90d", 0)
    # log10(50) ~= 1.7, normalize so 50+ commits = ~1.0
    activity_score = min(math.log10(commits_90d + 1) / 1.7, 1.0)

    return release_score * 0.5 + activity_score * 0.5


def _community_health(data: dict) -> float:
    """
    Community engagement signals.
    Uses continuous functions.
    """
    # OpenSSF Scorecard (if available) - already 0-10 scale
    openssf = data.get("openssf_score")
    if openssf is not None:
        openssf_score = openssf / 10.0
    else:
        openssf_score = 0.5  # Neutral if not available

    # Contributors: log-scaled continuous
    contributors = data.get("total_contributors", 1)
    # log10(50) ~= 1.7, normalize so 50+ contributors = ~1.0
    contributor_score = min(math.log10(contributors + 1) / 1.7, 1.0)

    # Security: sigmoid decay based on advisory count and severity
    advisories = data.get("advisories", [])
    critical = sum(1 for a in advisories if a.get("severity") == "CRITICAL")
    high = sum(1 for a in advisories if a.get("severity") == "HIGH")
    medium = sum(1 for a in advisories if a.get("severity") == "MEDIUM")

    # Weighted vulnerability score (higher = worse)
    vuln_score = critical * 3 + high * 2 + medium * 1
    # Sigmoid decay: 0 vulns = 1.0, 5+ weighted vulns = ~0.2
    security_score = 1 / (1 + math.exp((vuln_score - 2) / 1.5))

    return openssf_score * 0.4 + contributor_score * 0.3 + security_score * 0.3


def _calculate_confidence(data: dict) -> dict:
    """
    How confident are we in this score?

    Returns INSUFFICIENT_DATA for packages < 90 days old.
    """
    # Data completeness
    required_fields = [
        "days_since_last_commit",
        "weekly_downloads",
        "active_contributors_90d",
        "last_published",
    ]
    present = sum(1 for f in required_fields if data.get(f) is not None)
    completeness = present / len(required_fields)

    # Package age (cold start penalty)
    created = data.get("created_at")
    age_days = None
    age_score = 0.5

    if created:
        try:
            created_date = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age_days = (datetime.now(created_date.tzinfo) - created_date).days

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
        except:
            age_score = 0.5

    # Data freshness penalty
    last_updated = data.get("last_updated")
    freshness_score = 1.0
    if last_updated:
        try:
            updated_date = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
            hours_since_update = (datetime.now(updated_date.tzinfo) - updated_date).total_seconds() / 3600
            if hours_since_update > 168:  # > 1 week old
                freshness_score = 0.7
            elif hours_since_update > 48:
                freshness_score = 0.9
        except:
            pass

    confidence_score = completeness * 0.5 + age_score * 0.3 + freshness_score * 0.2

    if confidence_score >= 0.8:
        level = "HIGH"
    elif confidence_score >= 0.5:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": round(confidence_score * 100, 1),
        "level": level,
    }


def _get_risk_level(score: float) -> str:
    if score >= 80:
        return "LOW"
    elif score >= 60:
        return "MEDIUM"
    elif score >= 40:
        return "HIGH"
    else:
        return "CRITICAL"
```

### 2.2 Abandonment Risk (Simplified)

```python
# scoring/abandonment_risk.py

import math

def calculate_abandonment_risk(data: dict, months: int = 12) -> dict:
    """
    Predict abandonment probability.

    Simplified model using continuous risk factors.
    """
    # Risk signals (0-1 scale, higher = riskier)
    days = data.get("days_since_last_commit", 365)
    inactivity_risk = 1 - math.exp(-days / 180)

    maintainers = data.get("active_contributors_90d", 1)
    bus_factor_risk = math.exp(-maintainers / 2)

    downloads = data.get("weekly_downloads", 0)
    if downloads < 100:
        adoption_risk = 0.8
    elif downloads < 1000:
        adoption_risk = 0.5
    else:
        adoption_risk = 0.2

    # Weighted combination
    risk_score = (
        inactivity_risk * 0.4 +
        bus_factor_risk * 0.35 +
        adoption_risk * 0.25
    )

    # Adjust for time horizon
    time_factor = min(months / 12, 2.0)
    adjusted_risk = min(risk_score * time_factor, 0.95)

    # Identify specific risk factors
    factors = []
    if days > 180:
        factors.append(f"No commits in {days} days")
    if maintainers <= 1:
        factors.append("Single maintainer (bus factor = 1)")
    if downloads < 1000:
        factors.append("Low adoption (<1K weekly downloads)")
    if data.get("archived"):
        factors.append("Repository is archived")
        adjusted_risk = 0.95

    return {
        "probability": round(adjusted_risk * 100, 1),
        "time_horizon_months": months,
        "risk_factors": factors,
    }
```

### 2.3 Backtest Validation (100+ packages)

```python
# tests/backtest.py

"""
Backtest dataset: 100+ packages with known outcomes.

Categories:
- 30 confirmed abandoned (various modes: deprecated, sabotaged, stale, archived)
- 20 at-risk (single maintainer, low activity, funding issues)
- 50 healthy controls (mix of popularity levels and project types)

Stratified by:
- Package age (1-10+ years)
- Download volume (1K to 10M+)
- Abandonment mode (if applicable)
"""

BACKTEST_PACKAGES = {
    # ============================================
    # ABANDONED (30 packages)
    # ============================================

    # Officially deprecated
    "request": {"status": "abandoned", "reason": "Officially deprecated Feb 2020"},
    "moment": {"status": "abandoned", "reason": "Maintenance mode Sep 2020"},
    "node-uuid": {"status": "abandoned", "reason": "Deprecated in favor of uuid"},
    "querystring": {"status": "abandoned", "reason": "Deprecated, use URLSearchParams"},
    "hoek": {"status": "abandoned", "reason": "Deprecated"},
    "boom": {"status": "abandoned", "reason": "Deprecated in favor of @hapi/boom"},
    "joi": {"status": "abandoned", "reason": "Moved to @hapi/joi, then deprecated"},
    "node-fetch": {"status": "abandoned", "reason": "Maintenance mode, native fetch"},
    "cheerio-httpcli": {"status": "abandoned", "reason": "Unmaintained"},
    "bower": {"status": "abandoned", "reason": "Deprecated in favor of npm"},

    # Sabotaged/compromised
    "colors": {"status": "abandoned", "reason": "Sabotaged Jan 2022"},
    "faker": {"status": "abandoned", "reason": "Sabotaged Jan 2022"},
    "event-stream": {"status": "abandoned", "reason": "Compromised Sep 2018"},
    "left-pad": {"status": "abandoned", "reason": "Removed Mar 2016"},
    "ua-parser-js": {"status": "abandoned", "reason": "Compromised Oct 2021 (recovered)"},

    # Silently stale (no deprecation announcement)
    "underscore.string": {"status": "abandoned", "reason": "Stale, last commit 2019"},
    "q": {"status": "abandoned", "reason": "Stale, promises native now"},
    "async": {"status": "abandoned", "reason": "Minimal maintenance, async/await native"},
    "hawk": {"status": "abandoned", "reason": "Unmaintained since 2016"},
    "cryptiles": {"status": "abandoned", "reason": "Unmaintained"},
    "sntp": {"status": "abandoned", "reason": "Unmaintained"},
    "optimist": {"status": "abandoned", "reason": "Deprecated in favor of yargs"},
    "coffee-script": {"status": "abandoned", "reason": "Stale"},
    "node-sass": {"status": "abandoned", "reason": "Deprecated for dart-sass"},
    "nomnom": {"status": "abandoned", "reason": "Unmaintained"},

    # Archived repositories
    "gulp-util": {"status": "abandoned", "reason": "Archived, deprecated"},
    "babel-core": {"status": "abandoned", "reason": "Moved to @babel/core"},
    "babel-preset-es2015": {"status": "abandoned", "reason": "Deprecated"},
    "react-addons-test-utils": {"status": "abandoned", "reason": "Deprecated"},
    "react-dom-factories": {"status": "abandoned", "reason": "Archived"},

    # ============================================
    # AT-RISK (20 packages)
    # ============================================

    # Single maintainer / bus factor issues
    "core-js": {"status": "at_risk", "reason": "Solo maintainer, funding crisis"},
    "debug": {"status": "at_risk", "reason": "Single primary maintainer"},
    "qs": {"status": "at_risk", "reason": "Infrequent updates, bus factor 1-2"},
    "mime": {"status": "at_risk", "reason": "Low activity"},
    "ms": {"status": "at_risk", "reason": "Very stable but minimal maintenance"},
    "bytes": {"status": "at_risk", "reason": "Low activity, single purpose"},
    "statuses": {"status": "at_risk", "reason": "Low activity"},
    "destroy": {"status": "at_risk", "reason": "Single purpose, stable"},
    "depd": {"status": "at_risk", "reason": "Minimal maintenance"},
    "vary": {"status": "at_risk", "reason": "Minimal maintenance"},

    # Declining activity
    "underscore": {"status": "at_risk", "reason": "Minimal updates, superseded by lodash"},
    "bluebird": {"status": "at_risk", "reason": "Native promises, declining usage"},
    "request-promise": {"status": "at_risk", "reason": "Depends on deprecated request"},
    "moment-timezone": {"status": "at_risk", "reason": "Moment is in maintenance mode"},
    "validator": {"status": "at_risk", "reason": "Slow maintenance cadence"},
    "body-parser": {"status": "at_risk", "reason": "Built into Express now"},
    "cookie-parser": {"status": "at_risk", "reason": "Minimal updates needed"},
    "morgan": {"status": "at_risk", "reason": "Minimal updates"},
    "serve-static": {"status": "at_risk", "reason": "Minimal updates"},
    "on-finished": {"status": "at_risk", "reason": "Minimal maintenance"},

    # ============================================
    # HEALTHY (50 packages)
    # ============================================

    # Corporate-backed (10)
    "react": {"status": "healthy", "reason": "Meta backed"},
    "typescript": {"status": "healthy", "reason": "Microsoft backed"},
    "angular": {"status": "healthy", "reason": "Google backed"},
    "vue": {"status": "healthy", "reason": "Full-time team, sponsors"},
    "next": {"status": "healthy", "reason": "Vercel backed"},
    "prisma": {"status": "healthy", "reason": "Company backed"},
    "tailwindcss": {"status": "healthy", "reason": "Tailwind Labs backed"},
    "turbo": {"status": "healthy", "reason": "Vercel backed"},
    "playwright": {"status": "healthy", "reason": "Microsoft backed"},
    "puppeteer": {"status": "healthy", "reason": "Google backed"},

    # Foundation-supported (10)
    "express": {"status": "healthy", "reason": "OpenJS Foundation"},
    "eslint": {"status": "healthy", "reason": "OpenJS Foundation"},
    "webpack": {"status": "healthy", "reason": "OpenJS Foundation, sponsors"},
    "node": {"status": "healthy", "reason": "OpenJS Foundation"},
    "jquery": {"status": "healthy", "reason": "OpenJS Foundation"},
    "mocha": {"status": "healthy", "reason": "OpenJS Foundation"},
    "electron": {"status": "healthy", "reason": "OpenJS Foundation"},
    "nodejs": {"status": "healthy", "reason": "Foundation supported"},
    "deno": {"status": "healthy", "reason": "Company backed"},
    "bun": {"status": "healthy", "reason": "Oven backed"},

    # Very active community (15)
    "lodash": {"status": "healthy", "reason": "Stable, maintained"},
    "axios": {"status": "healthy", "reason": "Very active"},
    "jest": {"status": "healthy", "reason": "Meta backed, active"},
    "prettier": {"status": "healthy", "reason": "Active community"},
    "vite": {"status": "healthy", "reason": "Very active"},
    "esbuild": {"status": "healthy", "reason": "Active development"},
    "zod": {"status": "healthy", "reason": "Very active"},
    "trpc": {"status": "healthy", "reason": "Active development"},
    "fastify": {"status": "healthy", "reason": "Active community"},
    "hono": {"status": "healthy", "reason": "Very active"},
    "drizzle-orm": {"status": "healthy", "reason": "Active development"},
    "pnpm": {"status": "healthy", "reason": "Very active"},
    "vitest": {"status": "healthy", "reason": "Active development"},
    "nest": {"status": "healthy", "reason": "Active team"},
    "remix": {"status": "healthy", "reason": "Shopify backed"},

    # Stable utilities (15)
    "chalk": {"status": "healthy", "reason": "Active, widely used"},
    "commander": {"status": "healthy", "reason": "Active development"},
    "yargs": {"status": "healthy", "reason": "Active development"},
    "dotenv": {"status": "healthy", "reason": "Active, stable"},
    "uuid": {"status": "healthy", "reason": "Active development"},
    "date-fns": {"status": "healthy", "reason": "Very active, modern alternative"},
    "dayjs": {"status": "healthy", "reason": "Active development"},
    "got": {"status": "healthy", "reason": "Active development"},
    "cheerio": {"status": "healthy", "reason": "Active development"},
    "sharp": {"status": "healthy", "reason": "Active development"},
    "bcrypt": {"status": "healthy", "reason": "Stable, maintained"},
    "jsonwebtoken": {"status": "healthy", "reason": "Maintained"},
    "ora": {"status": "healthy", "reason": "Active development"},
    "inquirer": {"status": "healthy", "reason": "Active development"},
    "socket.io": {"status": "healthy", "reason": "Active development"},
}


def run_backtest() -> dict:
    """
    Run backtest and calculate accuracy metrics.

    Success criteria:
    - Accuracy >= 70%
    - Abandoned packages score < 50
    - Healthy packages score >= 60
    """
    results = []

    for package_name, expected in BACKTEST_PACKAGES.items():
        # Fetch current data and score
        data = collect_package_data(package_name)
        score_result = calculate_health_score(data)

        health_score = score_result["health_score"]

        # Classify based on score
        if health_score < 50:
            predicted = "abandoned"
        elif health_score < 65:
            predicted = "at_risk"
        else:
            predicted = "healthy"

        # Check if prediction matches
        actual = expected["status"]

        # For accuracy, group at_risk with abandoned
        predicted_binary = predicted in ["abandoned", "at_risk"]
        actual_binary = actual in ["abandoned", "at_risk"]
        correct = predicted_binary == actual_binary

        results.append({
            "package": package_name,
            "expected": actual,
            "predicted": predicted,
            "score": health_score,
            "correct": correct,
        })

    # Calculate metrics
    correct_count = sum(1 for r in results if r["correct"])
    accuracy = correct_count / len(results)

    abandoned_scores = [r["score"] for r in results if r["expected"] == "abandoned"]
    healthy_scores = [r["score"] for r in results if r["expected"] == "healthy"]

    return {
        "accuracy": round(accuracy * 100, 1),
        "total_packages": len(results),
        "correct_predictions": correct_count,
        "avg_abandoned_score": sum(abandoned_scores) / len(abandoned_scores) if abandoned_scores else 0,
        "avg_healthy_score": sum(healthy_scores) / len(healthy_scores) if healthy_scores else 0,
        "details": results,
    }
```

---

## Week 5-6: API Layer

### 3.1 API Endpoints

```yaml
# openapi.yaml (simplified)
openapi: 3.0.3
info:
  title: PkgWatch API
  version: 1.0.0

servers:
  - url: https://api.dephealth.laranjo.dev/v1

paths:
  /health:
    get:
      summary: API health check
      security: []
      responses:
        '200':
          description: API is healthy

  /packages/{ecosystem}/{name}:
    get:
      summary: Get package health score
      parameters:
        - name: ecosystem
          in: path
          required: true
          schema:
            type: string
            enum: [npm]
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
        '404':
          description: Package not found

  /scan:
    post:
      summary: Scan a package.json file
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                content:
                  type: string
                  description: Raw package.json content
      responses:
        '200':
          description: Scan results

  /usage:
    get:
      summary: Get API usage for current key
      responses:
        '200':
          description: Usage statistics

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
        risk_level:
          type: string
          enum: [LOW, MEDIUM, HIGH, CRITICAL]
        abandonment_risk:
          type: object
        components:
          type: object
        signals:
          type: object
        confidence:
          type: object
        last_updated:
          type: string
          format: date-time
```

### 3.2 Lambda Handlers

```python
# api/get_package.py

import json
from shared.dynamo import get_package
from shared.auth import validate_api_key, increment_usage

def handler(event, context):
    # Auth
    api_key = event.get("headers", {}).get("x-api-key")
    user = validate_api_key(api_key)

    if not user:
        return {
            "statusCode": 401,
            "body": json.dumps({
                "error": {
                    "code": "invalid_api_key",
                    "message": "Invalid or missing API key"
                }
            })
        }

    # Rate limit check
    if user["requests_this_month"] >= user["monthly_limit"]:
        # Calculate seconds until month reset (first of next month)
        from datetime import datetime
        import calendar
        now = datetime.now()
        days_in_month = calendar.monthrange(now.year, now.month)[1]
        seconds_until_reset = (days_in_month - now.day) * 86400 + (24 - now.hour) * 3600

        return {
            "statusCode": 429,
            "headers": {
                "Content-Type": "application/json",
                "Retry-After": str(seconds_until_reset),
                "X-RateLimit-Limit": str(user["monthly_limit"]),
                "X-RateLimit-Remaining": "0",
            },
            "body": json.dumps({
                "error": {
                    "code": "rate_limit_exceeded",
                    "message": f"Monthly limit of {user['monthly_limit']} requests exceeded",
                    "retry_after_seconds": seconds_until_reset,
                    "upgrade_url": "https://dephealth.laranjo.dev/pricing"
                }
            })
        }

    # Get package
    ecosystem = event["pathParameters"]["ecosystem"]
    name = event["pathParameters"]["name"]

    package_data = get_package(ecosystem, name)

    if not package_data:
        return {
            "statusCode": 404,
            "body": json.dumps({
                "error": {
                    "code": "package_not_found",
                    "message": f"Package '{name}' not found in {ecosystem}"
                }
            })
        }

    # Increment usage
    increment_usage(user["user_id"], user["key_hash"])

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "X-RateLimit-Limit": str(user["monthly_limit"]),
            "X-RateLimit-Remaining": str(user["monthly_limit"] - user["requests_this_month"] - 1),
        },
        "body": json.dumps(package_data)
    }
```

### 3.3 API Key Management

```python
# shared/auth.py

import hashlib
import secrets
import boto3
from datetime import datetime

dynamodb = boto3.resource("dynamodb")
api_keys_table = dynamodb.Table("dephealth-api-keys")

TIER_LIMITS = {
    "free": 5000,      # Generous free tier
    "starter": 25000,
    "pro": 100000,
    "business": 500000,
}

def generate_api_key(user_id: str, tier: str = "free") -> str:
    """Generate a new API key for a user."""
    api_key = f"dh_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    api_keys_table.put_item(Item={
        "pk": user_id,
        "sk": key_hash,
        "tier": tier,
        "requests_this_month": 0,
        "created_at": datetime.now().isoformat(),
    })

    return api_key


def validate_api_key(api_key: str) -> dict | None:
    """Validate API key and return user info."""
    if not api_key or not api_key.startswith("dh_"):
        return None

    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    # Query by key hash (using GSI)
    response = api_keys_table.query(
        IndexName="key-hash-index",
        KeyConditionExpression="sk = :hash",
        ExpressionAttributeValues={":hash": key_hash}
    )

    if not response.get("Items"):
        return None

    item = response["Items"][0]

    return {
        "user_id": item["pk"],
        "key_hash": item["sk"],  # Include for increment_usage
        "tier": item["tier"],
        "monthly_limit": TIER_LIMITS[item["tier"]],
        "requests_this_month": item.get("requests_this_month", 0),
    }


def increment_usage(user_id: str, key_hash: str):
    """Increment monthly usage counter."""
    # This uses atomic counter in DynamoDB
    # Note: Key must include both pk (user_id) and sk (key_hash) for composite key
    api_keys_table.update_item(
        Key={"pk": user_id, "sk": key_hash},
        UpdateExpression="ADD requests_this_month :inc",
        ExpressionAttributeValues={":inc": 1}
    )
```

### 3.4 Stripe Integration (Simple)

```python
# api/stripe_webhook.py

import json
import stripe
import os

stripe.api_key = os.environ["STRIPE_SECRET_KEY"]
webhook_secret = os.environ["STRIPE_WEBHOOK_SECRET"]

def handler(event, context):
    payload = event["body"]
    sig_header = event["headers"].get("stripe-signature")

    try:
        stripe_event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except Exception as e:
        return {"statusCode": 400, "body": f"Webhook error: {e}"}

    if stripe_event["type"] == "checkout.session.completed":
        session = stripe_event["data"]["object"]
        handle_successful_payment(session)

    elif stripe_event["type"] == "customer.subscription.deleted":
        subscription = stripe_event["data"]["object"]
        handle_cancellation(subscription)

    return {"statusCode": 200, "body": "OK"}


def handle_successful_payment(session):
    """Upgrade user to paid tier."""
    customer_email = session.get("customer_email")
    # Look up user by email, upgrade tier
    # ...


def handle_cancellation(subscription):
    """Downgrade user to free tier."""
    customer_id = subscription.get("customer")
    # Look up user, downgrade to free
    # ...
```

---

## Week 7: Polish & Launch

### Final Checklist

```
Infrastructure:
[ ] DynamoDB tables created with GSIs
    - packages: risk-level-index
    - api_keys: key-hash-index
[ ] API Gateway configured
[ ] Lambda functions deployed
[ ] S3 bucket for raw data
[ ] Secrets Manager for tokens (github-token, stripe-secret, stripe-webhook)
[ ] CloudWatch alarms configured:
    - Lambda error rate > 1%
    - API Gateway 5xx > 10/minute
    - DLQ message count > 0
    - DynamoDB throttling > 0
[ ] DynamoDB Point-in-Time Recovery enabled

Data:
[ ] 2,500 packages collected
[ ] deps.dev data integrated
[ ] GitHub metrics collected (with retry logic)
[ ] Scores calculated for all packages
[ ] Backtest accuracy >= 70% on 100 packages
[ ] Tier promotion logic working

API:
[ ] GET /health working
[ ] GET /packages/{ecosystem}/{name} working
[ ] POST /scan working
[ ] API key auth working (with GSI lookup)
[ ] Rate limiting working (with Retry-After header)
[ ] Error responses standardized (with error codes)

Billing:
[ ] Stripe products created
[ ] Checkout flow working
[ ] Webhook handlers working (with signature verification)
[ ] Free tier configured (5,000 requests/month)

Docs:
[ ] API documentation (basic)
[ ] Getting started guide
[ ] Authentication guide
[ ] Rate limiting explained
```

---

## Project Structure

```
dephealth/
├── infrastructure/
│   ├── lib/
│   │   ├── storage-stack.ts
│   │   ├── api-stack.ts
│   │   └── pipeline-stack.ts
│   ├── bin/app.ts
│   └── cdk.json
├── functions/
│   ├── api/
│   │   ├── get_package.py
│   │   ├── post_scan.py
│   │   ├── get_usage.py
│   │   └── stripe_webhook.py
│   ├── collectors/
│   │   ├── depsdev_collector.py
│   │   ├── npm_collector.py
│   │   ├── github_collector.py
│   │   └── refresh_dispatcher.py
│   ├── scoring/
│   │   ├── health_score.py
│   │   ├── abandonment_risk.py
│   │   └── score_package.py
│   └── shared/
│       ├── dynamo.py
│       ├── auth.py
│       └── errors.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── backtest.py
├── scripts/
│   ├── select_packages.py
│   └── initial_load.py
└── docs/
    ├── api.md
    └── getting-started.md
```

---

## Success Criteria

| Metric | Target |
|--------|--------|
| Packages indexed | 2,500 |
| Backtest accuracy (100 packages) | >= 70% |
| API response time (p95) | < 500ms |
| API uptime | 99% |
| Timeline | 7 weeks |
| Launch | End of Week 7 |

---

## Budget Summary

| Item | One-Time | Monthly |
|------|----------|---------|
| Domain | $12 | - |
| AWS (Lambda, DynamoDB, API Gateway, S3) | - | $40-80 |
| Secrets Manager (3 secrets) | - | $2 |
| CloudWatch Logs | - | $5-10 |
| **Total** | **~$12** | **~$50-90** |

**Note:** BigQuery is NOT required - deps.dev provides sufficient data for MVP.

AWS credits ($200) cover first 3-4 months easily.

---

## Post-Launch Roadmap

**Week 8-9:**
- Monitor usage and errors
- Gather user feedback
- Expand to 5,000 packages if demand

**Week 10-12:**
- Build CLI tool
- Add more packages (10K)
- Implement historical trends

**Month 3+:**
- PyPI support
- GitHub Action
- Team features

---

*Lean Plan Created: January 7, 2026*
*Last Updated: January 7, 2026 (incorporated review feedback - v2)*
