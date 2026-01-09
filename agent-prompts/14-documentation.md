# Agent Prompt: Documentation Completeness

## Context

You are working on DepHealth, a dependency health intelligence platform. The documentation needs significant improvement to support developers and enterprise adoption.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 14: Documentation Review)

## Your Mission

Create comprehensive documentation including OpenAPI spec, component READMEs, contributing guide, and environment variable documentation.

## Current Documentation Gaps

| Document | Status | Priority |
|----------|--------|----------|
| OpenAPI Specification | Missing | Critical |
| `packages/api-client/README.md` | Missing | High |
| `infrastructure/README.md` | Missing | High |
| `functions/README.md` | Missing | High |
| `CONTRIBUTING.md` | Missing | High |
| `CHANGELOG.md` | Missing | Medium |
| `.env.example` | Missing | Medium |
| Architecture Decision Records | Missing | Low |

## Critical Documentation to Create

### 1. OpenAPI Specification (CRITICAL)

**Create:** `docs/openapi.yaml`

See API Design prompt (02) for full specification. This is the most critical missing documentation.

### 2. API Client README (HIGH)

**Create:** `packages/api-client/README.md`

```markdown
# @dephealth/api-client

TypeScript client library for the DepHealth API.

## Installation

```bash
npm install @dephealth/api-client
```

## Usage

```typescript
import { DepHealthClient, ApiClientError } from '@dephealth/api-client';

// Initialize client
const client = new DepHealthClient('dh_your_api_key');

// Get package health
const result = await client.getPackage('lodash');
console.log(result.health_score);  // 85.2
console.log(result.risk_level);    // "LOW"

// Scan package.json dependencies
const scan = await client.scan({
  dependencies: {
    lodash: '^4.17.21',
    express: '^4.18.0',
  }
});
console.log(scan.total);          // 2
console.log(scan.critical);       // 0

// Get usage statistics
const usage = await client.getUsage();
console.log(usage.requests_this_month);
console.log(usage.monthly_limit);
```

## Error Handling

```typescript
try {
  const result = await client.getPackage('nonexistent-package-xyz');
} catch (error) {
  if (error instanceof ApiClientError) {
    console.log(error.code);    // 'package_not_found'
    console.log(error.message); // 'Package not found'
    console.log(error.status);  // 404
  }
}
```

## Configuration

```typescript
const client = new DepHealthClient(apiKey, {
  baseUrl: 'https://api.dephealth.laranjo.dev/v1',  // Default
  timeout: 30000,  // 30 seconds default
  maxRetries: 3,   // Automatic retry on failure
});
```

## Types

```typescript
interface PackageHealth {
  package: string;
  ecosystem: string;
  health_score: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  abandonment_risk: {
    probability: number;
    time_horizon_months: number;
  };
  components: {
    maintainer_health: number;
    user_centric: number;
    evolution: number;
    community: number;
    security: number;
  };
}

interface ScanResult {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  packages: PackageHealth[];
  not_found: string[];
}

interface UsageInfo {
  tier: string;
  requests_this_month: number;
  monthly_limit: number;
  reset_date: string;
}
```

## Rate Limiting

The client automatically handles rate limit headers. Check remaining requests:

```typescript
// After any API call, check rate limit headers
console.log(client.lastRateLimitInfo);
// { limit: 5000, remaining: 4999, reset: 1704067200 }
```

## License

MIT
```

### 3. Infrastructure README (HIGH)

**Create:** `infrastructure/README.md`

```markdown
# DepHealth Infrastructure

AWS CDK infrastructure for the DepHealth platform.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AWS Cloud                                │
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │     WAF      │───▶│ API Gateway  │───▶│     Lambda       │  │
│  │              │    │    (REST)    │    │   Functions      │  │
│  └──────────────┘    └──────────────┘    └────────┬─────────┘  │
│                                                    │            │
│                                                    ▼            │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │   Secrets    │───▶│   DynamoDB   │◀───│      SQS         │  │
│  │   Manager    │    │              │    │   + EventBridge  │  │
│  └──────────────┘    └──────────────┘    └──────────────────┘  │
│                             │                                   │
│                             ▼                                   │
│                      ┌──────────────┐                          │
│                      │      S3      │                          │
│                      │  (Raw Data)  │                          │
│                      └──────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

## Stacks

| Stack | Purpose | Key Resources |
|-------|---------|---------------|
| `StorageStack` | Data storage | DynamoDB tables, S3 bucket |
| `ApiStack` | API layer | API Gateway, Lambda functions, WAF |
| `PipelineStack` | Data collection | SQS queues, EventBridge rules, Collector Lambdas |

## Prerequisites

- Node.js 18+
- AWS CLI configured with appropriate credentials
- AWS CDK CLI (`npm install -g aws-cdk`)

## Environment Variables

Create `.env` file (see `.env.example`):

```bash
# Required
CDK_ENV=production  # or 'development'

# Stripe (for billing)
STRIPE_PRICE_STARTER=price_xxx
STRIPE_PRICE_PRO=price_xxx
STRIPE_PRICE_BUSINESS=price_xxx
```

## Deployment

```bash
# Install dependencies
npm install

# Bootstrap CDK (first time only)
npx cdk bootstrap

# Preview changes
npx cdk diff

# Deploy all stacks
npx cdk deploy --all

# Deploy specific stack
npx cdk deploy DepHealthApiStack
```

## DynamoDB Tables

### dephealth-packages

| Attribute | Type | Description |
|-----------|------|-------------|
| `pk` | String | `{ecosystem}#{name}` (e.g., `npm#lodash`) |
| `sk` | String | Always `LATEST` |
| `health_score` | Number | 0-100 score |
| `risk_level` | String | CRITICAL/HIGH/MEDIUM/LOW |
| `last_updated` | String | ISO timestamp |

**GSIs:**
- `risk-level-index` (risk_level → last_updated)
- `tier-index` (tier → last_updated)

### dephealth-api-keys

| Attribute | Type | Description |
|-----------|------|-------------|
| `pk` | String | `user_{email_hash}` |
| `sk` | String | `{key_hash}` or `PENDING` |
| `email` | String | User email |
| `tier` | String | free/starter/pro/business |
| `requests_this_month` | Number | Usage counter |

**GSIs:**
- `key-hash-index` (key_hash)
- `email-index` (email)
- `verification-token-index` (verification_token)
- `stripe-customer-index` (stripe_customer_id)

## Lambda Functions

| Function | Trigger | Purpose |
|----------|---------|---------|
| GetPackageHandler | API Gateway | GET /packages/{ecosystem}/{name} |
| ScanHandler | API Gateway | POST /scan |
| SignupHandler | API Gateway | POST /signup |
| VerifyEmailHandler | API Gateway | GET /verify |
| MagicLinkHandler | API Gateway | POST /auth/magic-link |
| AuthCallbackHandler | API Gateway | GET /auth/callback |
| RefreshDispatcher | EventBridge | Triggers package refresh |
| PackageCollector | SQS | Collects package data |
| ScoreCalculator | DynamoDB Streams | Calculates health scores |
| DLQProcessor | EventBridge | Handles failed collections |

## Secrets

Stored in AWS Secrets Manager:

| Secret | Purpose |
|--------|---------|
| `dephealth/session-secret` | Session token signing |
| `dephealth/stripe-api-key` | Stripe API access |
| `dephealth/stripe-webhook-secret` | Stripe webhook verification |

## Useful Commands

```bash
# Synthesize CloudFormation template
npx cdk synth

# View stack outputs
npx cdk outputs DepHealthApiStack

# Destroy stacks (careful!)
npx cdk destroy --all

# View logs
aws logs tail /aws/lambda/dephealth-GetPackageHandler --follow
```

## Cost Estimation

| Service | Monthly Cost (Low Traffic) |
|---------|---------------------------|
| Lambda | $5-15 |
| API Gateway | $3-10 |
| DynamoDB | $1-5 |
| WAF | $6 |
| S3 | $0.50 |
| Secrets Manager | $1.60 |
| CloudWatch | $5-10 |
| **Total** | **~$25-50** |

## License

MIT
```

### 4. Functions README (HIGH)

**Create:** `functions/README.md`

```markdown
# DepHealth Lambda Functions

Python Lambda functions for the DepHealth API and data pipeline.

## Structure

```
functions/
├── api/                    # API endpoint handlers
│   ├── get_package.py      # GET /packages/{ecosystem}/{name}
│   ├── post_scan.py        # POST /scan
│   ├── signup.py           # POST /signup
│   ├── verify_email.py     # GET /verify
│   ├── magic_link.py       # POST /auth/magic-link
│   ├── auth_callback.py    # GET /auth/callback
│   ├── auth_me.py          # GET /auth/me
│   ├── get_api_keys.py     # GET /api-keys
│   ├── create_api_key.py   # POST /api-keys
│   ├── revoke_api_key.py   # DELETE /api-keys/{id}
│   ├── get_usage.py        # GET /usage
│   ├── stripe_webhook.py   # POST /webhooks/stripe
│   └── health.py           # GET /health
│
├── collectors/             # Data collection pipeline
│   ├── package_collector.py    # Main orchestrator
│   ├── refresh_dispatcher.py   # Schedule trigger
│   ├── dlq_processor.py        # Dead letter queue
│   ├── github_collector.py     # GitHub API integration
│   ├── npm_collector.py        # npm registry integration
│   ├── depsdev_collector.py    # deps.dev API integration
│   └── bundlephobia_collector.py
│
├── scoring/                # Scoring algorithms
│   ├── health_score.py     # Health score calculation
│   ├── abandonment_risk.py # Risk prediction
│   └── score_package.py    # DynamoDB Streams handler
│
└── shared/                 # Shared utilities
    ├── auth.py             # Authentication utilities
    ├── errors.py           # Exception classes
    ├── response_utils.py   # Response formatting
    ├── dynamo.py           # DynamoDB utilities
    └── types.py            # Type definitions
```

## Local Development

### Prerequisites

- Python 3.12+
- AWS credentials configured

### Setup

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=functions --cov-report=html

# Run specific test file
pytest tests/test_scoring.py -v

# Run specific test
pytest tests/test_scoring.py::TestHealthScore::test_healthy_package -v
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PACKAGES_TABLE` | DynamoDB packages table name | `dephealth-packages` |
| `API_KEYS_TABLE` | DynamoDB API keys table name | `dephealth-api-keys` |
| `RAW_DATA_BUCKET` | S3 bucket for raw data | `dephealth-raw-data` |
| `PACKAGE_QUEUE_URL` | SQS queue URL | - |
| `DLQ_URL` | Dead letter queue URL | - |
| `SESSION_SECRET_ARN` | Secrets Manager ARN | - |
| `GITHUB_TOKEN` | GitHub API token (optional) | - |
| `ALLOW_DEV_CORS` | Enable dev CORS origins | `false` |

## API Handlers

### Authentication

Most endpoints require authentication via:
- `X-API-Key` header for API access
- Session cookie for dashboard access

### Error Response Format

```json
{
  "error": {
    "code": "error_code",
    "message": "Human readable message",
    "details": {}
  }
}
```

### Common Error Codes

| Code | Status | Description |
|------|--------|-------------|
| `invalid_api_key` | 401 | Missing or invalid API key |
| `rate_limit_exceeded` | 429 | Monthly limit exceeded |
| `package_not_found` | 404 | Package not in database |
| `invalid_ecosystem` | 400 | Unsupported ecosystem |
| `internal_error` | 500 | Server error |

## Scoring Algorithms

### Health Score (0-100)

Weighted composite of 5 components:
- Maintainer Health (25%): Commit recency, bus factor
- User-Centric (30%): Downloads, dependents, stars
- Evolution (20%): Release recency, activity
- Community (10%): Contributor count
- Security (15%): OpenSSF score, vulnerabilities

### Abandonment Risk (0-100%)

Predicts probability of abandonment within time horizon:
- Inactivity factor (35%)
- Bus factor (30%)
- Adoption factor (20%)
- Release cadence (15%)

See `landing-page/src/pages/methodology.astro` for detailed documentation.

## Adding a New API Endpoint

1. Create handler in `functions/api/`:
```python
import json
import logging
from shared.response_utils import success_response, error_response
from shared.auth import validate_api_key

logger = logging.getLogger(__name__)

def handler(event, context):
    # Validate request
    # Process logic
    # Return response
    return success_response({"data": "value"})
```

2. Add Lambda function in `infrastructure/lib/api-stack.ts`
3. Add API Gateway route
4. Add tests in `tests/`

## License

MIT
```

### 5. Contributing Guide (HIGH)

**Create:** `CONTRIBUTING.md`

```markdown
# Contributing to DepHealth

Thank you for your interest in contributing to DepHealth!

## Development Setup

### Prerequisites

- Node.js 18+
- Python 3.12+
- AWS CLI configured (for integration tests)
- Git

### Clone and Install

```bash
# Clone the repository
git clone https://github.com/dephealth/dephealth.git
cd dephealth

# Install Node.js dependencies
npm install

# Install Python dependencies
cd functions
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Running Tests

```bash
# Python tests
cd functions
pytest tests/ -v

# CLI tests
cd cli
npm test

# Action tests
cd action
npm test

# Infrastructure tests
cd infrastructure
npm test
```

## Code Style

### Python

- Follow PEP 8
- Use type hints for function signatures
- Maximum line length: 100 characters
- Use docstrings for public functions

```python
def calculate_score(data: dict, weights: dict = None) -> float:
    """
    Calculate health score from package data.

    Args:
        data: Package metrics dictionary
        weights: Optional custom weights

    Returns:
        Health score from 0 to 100
    """
    ...
```

### TypeScript

- Use strict mode
- Prefer `const` over `let`
- Use explicit return types for public functions

```typescript
function formatScore(score: number): string {
  return score.toFixed(1);
}
```

## Pull Request Process

1. **Fork** the repository
2. **Create a branch** for your feature: `git checkout -b feature/my-feature`
3. **Make your changes** with clear, focused commits
4. **Write/update tests** for your changes
5. **Ensure all tests pass**: `npm test` and `pytest`
6. **Submit a pull request** with a clear description

### PR Title Format

Use conventional commits:
- `feat: Add new scoring signal for PR velocity`
- `fix: Handle timeout in GitHub collector`
- `docs: Update API documentation`
- `refactor: Extract shared retry logic`
- `test: Add integration tests for auth flow`

### PR Description Template

```markdown
## Summary
Brief description of changes

## Changes
- Change 1
- Change 2

## Testing
How was this tested?

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
```

## Commit Messages

Follow conventional commits:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Example:
```
feat(scoring): Add issue response time signal

Adds a new signal to the community health component that measures
average time to first response on issues.

Closes #123
```

## Issue Reporting

### Bug Reports

Include:
- Steps to reproduce
- Expected vs actual behavior
- Environment (OS, Node version, Python version)
- Error messages/logs

### Feature Requests

Include:
- Use case description
- Proposed solution
- Alternatives considered

## Code Review

All submissions require review. We use GitHub pull requests for this.

Reviewers will check:
- Code quality and style
- Test coverage
- Documentation
- Performance implications
- Security considerations

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
```

### 6. Environment Example (MEDIUM)

**Create:** `.env.example`

```bash
# DepHealth Environment Variables
# Copy this file to .env and fill in values

# =============================================================================
# AWS Configuration
# =============================================================================

# AWS region for deployment
AWS_REGION=us-east-1

# =============================================================================
# DynamoDB Tables
# =============================================================================

# Package health data table
PACKAGES_TABLE=dephealth-packages

# API keys and user data table
API_KEYS_TABLE=dephealth-api-keys

# =============================================================================
# S3 Storage
# =============================================================================

# Bucket for raw collected data
RAW_DATA_BUCKET=dephealth-raw-data

# =============================================================================
# SQS Queues
# =============================================================================

# Main package collection queue
PACKAGE_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789/dephealth-package-queue

# Dead letter queue for failed collections
DLQ_URL=https://sqs.us-east-1.amazonaws.com/123456789/dephealth-package-dlq

# =============================================================================
# Secrets (AWS Secrets Manager ARNs)
# =============================================================================

# Session signing secret
SESSION_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789:secret:dephealth/session-secret

# Stripe API key secret
STRIPE_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789:secret:dephealth/stripe-api-key

# Stripe webhook secret
STRIPE_WEBHOOK_SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789:secret:dephealth/stripe-webhook-secret

# =============================================================================
# External APIs (Optional)
# =============================================================================

# GitHub personal access token for higher rate limits
# Without this, uses unauthenticated API (60 req/hour)
# With token: 5000 req/hour
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

# =============================================================================
# Development Settings
# =============================================================================

# Enable additional CORS origins for local development
# Set to "true" to allow localhost:3000, localhost:4321
ALLOW_DEV_CORS=false

# =============================================================================
# Stripe Configuration (for infrastructure deployment)
# =============================================================================

# CDK deployment environment
CDK_ENV=development

# Stripe price IDs for subscription tiers
STRIPE_PRICE_STARTER=price_xxxxxxxxxx
STRIPE_PRICE_PRO=price_xxxxxxxxxx
STRIPE_PRICE_BUSINESS=price_xxxxxxxxxx

# =============================================================================
# CLI Configuration (for @dephealth/cli)
# =============================================================================

# API key for CLI (can also use DEPHEALTH_API_KEY)
# DEPHEALTH_API_KEY=dh_xxxxxxxxxx
```

### 7. Changelog (MEDIUM)

**Create:** `CHANGELOG.md`

```markdown
# Changelog

All notable changes to DepHealth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Product review document with comprehensive analysis
- Agent prompts for parallel development

### Changed
- Increased timing normalization from 0.5s to 1.5s for better enumeration protection
- Added TTL to PENDING signup records

### Fixed
- Moto compatibility issue with DynamoDB conditional expressions

## [1.0.0] - 2026-01-07

### Added
- Initial release of DepHealth
- Health score calculation (v2 algorithm)
- Abandonment risk prediction
- REST API with rate limiting
- CLI tool (@dephealth/cli)
- GitHub Action (dephealth/action)
- Passwordless authentication (magic links)
- Stripe billing integration
- Tiered pricing (Free, Starter, Pro, Business)

### Security
- API key hashing with SHA-256
- Timing normalization for email enumeration prevention
- WAF protection with AWS managed rules
- Session tokens with HMAC signing

---

## Version History

### Scoring Algorithm Versions

| Version | Date | Changes |
|---------|------|---------|
| v2.0 | 2026-01-01 | Revised weights, added security component |
| v1.0 | 2025-12-01 | Initial algorithm |

See [Methodology](/methodology) for detailed scoring documentation.
```

## Files to Create

| File | Priority |
|------|----------|
| `docs/openapi.yaml` | Critical |
| `packages/api-client/README.md` | High |
| `infrastructure/README.md` | High |
| `functions/README.md` | High |
| `CONTRIBUTING.md` | High |
| `.env.example` | Medium |
| `CHANGELOG.md` | Medium |
| `landing-page/README.md` | Low |
| `docs/adr/` | Low |

## Success Criteria

1. OpenAPI specification validates with swagger-cli
2. README exists for all major directories
3. CONTRIBUTING.md with clear guidelines
4. .env.example documents all variables
5. CHANGELOG tracking versions
6. Documentation matches actual implementation

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 14 for full documentation analysis.
