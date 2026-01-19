# PkgWatch - Dependency Health Intelligence

Predict which npm and Python packages are at risk of abandonment, maintenance decline, or security issues — BEFORE problems occur.

**Live:**
- API: https://api.pkgwatch.laranjo.dev/v1/
- Website: https://pkgwatch.laranjo.dev
- Docs: https://pkgwatch.laranjo.dev/docs
- Methodology: https://pkgwatch.laranjo.dev/methodology

## Features

- **Health Scores (0-100)** — Quantify package health across 5 dimensions
- **Abandonment Risk** — Predict probability of abandonment over 12 months
- **True Bus Factor** — Analyze actual commit distribution, not just contributor count
- **Security Assessment** — OpenSSF Scorecard integration + vulnerability tracking
- **CI/CD Integration** — CLI tool and GitHub Action for automated checks

## Quick Start

### CLI

```bash
# Install globally
npm install -g @pkgwatch/cli

# Set your API key
export PKGWATCH_API_KEY=pw_your_key_here

# Check a single package
pkgwatch check lodash

# Scan your project's dependencies
pkgwatch scan

# Fail CI on HIGH/CRITICAL risk packages
pkgwatch scan --fail-on HIGH
```

### GitHub Action

```yaml
- uses: Dlaranjo/pkgwatch/action@v1
  with:
    api-key: ${{ secrets.PKGWATCH_API_KEY }}
    fail-on: HIGH
```

### API

```bash
# Get health score for npm package
curl -H "X-API-Key: pw_your_key" \
  https://api.pkgwatch.laranjo.dev/v1/packages/npm/lodash

# Get health score for Python package
curl -H "X-API-Key: pw_your_key" \
  https://api.pkgwatch.laranjo.dev/v1/packages/pypi/requests

# Scan multiple packages
curl -X POST -H "X-API-Key: pw_your_key" \
  -H "Content-Type: application/json" \
  -d '{"dependencies": {"lodash": "^4.17.21", "express": "^4.18.0"}}' \
  https://api.pkgwatch.laranjo.dev/v1/scan
```

Get your API key at [pkgwatch.laranjo.dev](https://pkgwatch.laranjo.dev)

## Scoring Methodology

Health scores (0-100) are calculated from 5 weighted components:

| Component | Weight | Signals |
|-----------|--------|---------|
| **User-Centric** | 30% | Downloads, dependents, stars |
| **Maintainer Health** | 25% | Commit recency, true bus factor |
| **Evolution** | 20% | Release recency, commit activity |
| **Security** | 15% | OpenSSF score, vulnerabilities, security policy |
| **Community** | 10% | Contributor diversity |

**Risk Levels:** LOW (80-100), MEDIUM (60-79), HIGH (40-59), CRITICAL (0-39)

**Key features:**
- **Maturity factor** — Stable packages like lodash aren't penalized for low activity
- **True bus factor** — Minimum contributors needed for 50% of commits
- **Continuous functions** — Log-scale, exponential decay, and sigmoid functions for smooth, gaming-resistant scores

See [/methodology](https://pkgwatch.laranjo.dev/methodology) for full details.

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/packages/{ecosystem}/{name}` | GET | API Key | Get package health score |
| `/scan` | POST | API Key | Scan multiple packages |
| `/usage` | GET | API Key | Get API usage statistics |

**Demo mode:** Try the API without an API key (20 requests/hour per IP).

## Rate Limits

| Tier | Price | Requests/Month |
|------|-------|----------------|
| Free | $0 | 5,000 |
| Starter | $9/mo | 25,000 |
| Pro | $29/mo | 100,000 |
| Business | $99/mo | 500,000 |

## Project Structure

```
pkgwatch/
├── functions/               # Python Lambda functions
│   ├── api/                 # API endpoint handlers
│   ├── admin/               # Admin functions (data status, seeding)
│   ├── collectors/          # Data collection (deps.dev, npm, GitHub)
│   ├── discovery/           # Package discovery (graph expander, npms.io)
│   ├── scoring/             # Health scoring algorithms
│   └── shared/              # Auth, DynamoDB helpers
├── cli/                     # @pkgwatch/cli - Command line tool
├── action/                  # @pkgwatch/action - GitHub Action
├── packages/
│   └── api-client/          # @pkgwatch/api-client - Shared TypeScript client
├── docs/                    # API documentation (OpenAPI spec)
├── landing-page/            # Astro website
│   └── terraform/           # S3 + CloudFront infrastructure
├── infrastructure/          # AWS CDK (API infrastructure)
│   └── lib/
│       ├── storage-stack.ts     # DynamoDB + S3
│       ├── api-stack.ts         # API Gateway + Lambda + WAF
│       ├── pipeline-stack.ts    # EventBridge + SQS + Collectors
│       └── budget-stack.ts      # AWS Budget alerts
├── scripts/                 # Utility scripts
└── tests/                   # Python tests (pytest)
```

## Tech Stack

- **Backend:** Python 3.12, AWS Lambda, DynamoDB, API Gateway
- **CLI/Action:** TypeScript, Commander.js
- **Website:** Astro, Tailwind CSS
- **Infrastructure:** AWS CDK, Terraform (landing page)
- **Data Sources:** deps.dev, npm registry, PyPI registry, GitHub API

## Development

### Prerequisites

- Node.js 20+
- Python 3.12+
- AWS CLI configured
- AWS CDK CLI (`npm install -g aws-cdk`)

### Run Tests

```bash
# Python tests (from repo root)
pip install -r tests/requirements.txt
PYTHONPATH=functions:. pytest tests/ -v --cov=functions

# CLI tests
cd cli
npm test
```

### Deploy Infrastructure

```bash
cd infrastructure
npm install
cdk bootstrap  # First time only
cdk deploy --all
```

### Set Secrets

```bash
# GitHub token for API access
aws secretsmanager put-secret-value \
  --secret-id pkgwatch/github-token \
  --secret-string 'ghp_your_token_here'

# Stripe secrets (for payments)
aws secretsmanager put-secret-value \
  --secret-id pkgwatch/stripe-secret \
  --secret-string '{"key":"sk_live_..."}'
```

### Deploy Landing Page

```bash
cd landing-page
npm run build
./deploy.sh
```

## Data Sources

| Source | Rate Limit | Data |
|--------|------------|------|
| deps.dev | Unlimited | Dependencies, advisories, OpenSSF |
| npm registry | ~1000/hr | Downloads, maintainers, deprecation |
| PyPI registry | ~500/hr | Downloads, maintainers, classifiers |
| GitHub API | 5000/hr | Commits, contributors, stars |

## Data Refresh

| Tier | Packages | Frequency |
|------|----------|-----------|
| Tier 1 | Top 100 | Daily |
| Tier 2 | Top 500 | Every 3 days |
| Tier 3 | All 2,500 | Weekly |

## License

Proprietary - All rights reserved
