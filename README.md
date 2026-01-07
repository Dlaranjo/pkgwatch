# DepHealth - Dependency Health Intelligence API

Predict which open-source packages are at risk of abandonment, maintenance decline, or becoming problematic - BEFORE issues occur.

**Live Now:**
- API: https://api.dephealth.laranjo.dev/v1/
- Landing Page: https://dephealth.laranjo.dev
- Documentation: https://dephealth.laranjo.dev/docs

## Project Structure

```
dephealth/
├── functions/               # Lambda functions (Python)
│   ├── api/                 # API handlers
│   │   ├── health.py           # GET /health
│   │   ├── get_package.py      # GET /packages/{ecosystem}/{name}
│   │   ├── post_scan.py        # POST /scan
│   │   ├── get_usage.py        # GET /usage
│   │   └── stripe_webhook.py   # POST /webhooks/stripe
│   ├── collectors/          # Data collection
│   │   ├── depsdev_collector.py    # deps.dev API (primary)
│   │   ├── npm_collector.py        # npm registry API
│   │   ├── github_collector.py     # GitHub API (rate limited)
│   │   ├── refresh_dispatcher.py   # EventBridge -> SQS
│   │   └── package_collector.py    # SQS consumer
│   ├── scoring/             # Health scoring
│   │   ├── health_score.py         # Main scoring algorithm
│   │   ├── abandonment_risk.py     # Abandonment prediction
│   │   └── score_package.py        # Score calculation Lambda
│   └── shared/              # Shared utilities
│       ├── auth.py              # API key auth
│       ├── dynamo.py            # DynamoDB helpers
│       └── errors.py            # Error responses
├── landing-page/            # Astro landing page
│   ├── src/                 # Astro source files
│   ├── terraform/           # S3 + CloudFront infrastructure
│   └── deploy.sh            # Deployment script
├── infrastructure/          # AWS CDK (API infrastructure)
│   ├── lib/
│   │   ├── storage-stack.ts    # DynamoDB + S3
│   │   ├── api-stack.ts        # API Gateway + Lambda
│   │   └── pipeline-stack.ts   # EventBridge + SQS + Collectors
│   ├── bin/app.ts
│   └── cdk.json
├── scripts/                 # Utility scripts
│   ├── select_packages.py       # Select top 2,500 packages
│   └── initial_load.py          # Bootstrap data load
├── tests/                   # Tests
│   ├── unit/
│   └── integration/
└── docs/                    # Documentation
```

## Quick Start

### Prerequisites

- Node.js 18+
- Python 3.12+
- AWS CLI configured
- AWS CDK CLI (`npm install -g aws-cdk`)

### Deploy Infrastructure

```bash
cd infrastructure
npm install
cdk bootstrap  # First time only
cdk deploy --all
```

### Set Secrets

After deployment, set the secrets in AWS Secrets Manager:

```bash
# GitHub token for API access (plain token string)
aws secretsmanager put-secret-value \
  --secret-id dephealth/github-token \
  --secret-string 'ghp_your_token_here'

# Stripe secrets (for payments)
aws secretsmanager put-secret-value \
  --secret-id dephealth/stripe-secret \
  --secret-string '{"key":"sk_live_..."}'

aws secretsmanager put-secret-value \
  --secret-id dephealth/stripe-webhook \
  --secret-string '{"secret":"whsec_..."}'
```

### Load Initial Data

```bash
cd scripts
pip install -r requirements.txt

# Select top packages
python select_packages.py --limit 2500 --output packages.json

# Load into DynamoDB (requires GitHub token)
export GITHUB_TOKEN=ghp_your_token_here
python initial_load.py --packages packages.json --table dephealth-packages
```

### Deploy Landing Page

```bash
cd landing-page

# First time: Initialize Terraform
cd terraform
terraform init
terraform apply
cd ..

# Deploy (builds and uploads to S3, invalidates CloudFront)
./deploy.sh
```

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/packages/{ecosystem}/{name}` | GET | API Key | Get package health score |
| `/scan` | POST | API Key | Scan package.json |
| `/usage` | GET | API Key | Get API usage stats |
| `/webhooks/stripe` | POST | Stripe Sig | Handle billing events |

## API Usage

```bash
# Get health score for lodash
curl -H "X-API-Key: dh_your_key" \
  https://api.dephealth.laranjo.dev/v1/packages/npm/lodash

# Scan a package.json
curl -X POST -H "X-API-Key: dh_your_key" \
  -H "Content-Type: application/json" \
  -d '{"content": "{\"dependencies\": {\"lodash\": \"^4.17.21\"}}"}' \
  https://api.dephealth.laranjo.dev/v1/scan
```

## Scoring Algorithm

The health score (0-100) is calculated from four components:

| Component | Weight | Signals |
|-----------|--------|---------|
| Maintainer Health | 30% | Days since commit, active contributors |
| User-Centric | 30% | Downloads, dependents, stars |
| Evolution | 25% | Release recency, commit activity |
| Community | 15% | OpenSSF score, contributors, security |

All scoring uses continuous functions (log-scale, exponential decay, sigmoid) instead of step functions for smoother, more accurate results.

## Data Sources

| Source | Rate Limit | Data Provided |
|--------|------------|---------------|
| deps.dev | Unlimited | Versions, dependencies, advisories, OpenSSF |
| npm registry | ~1000/hr | Downloads, maintainers, deprecation |
| GitHub API | 5000/hr | Commits, contributors, stars, forks |

## Refresh Strategy

| Tier | Packages | Frequency | GitHub Calls/Day |
|------|----------|-----------|------------------|
| Tier 1 | Top 100 | Daily | ~400 |
| Tier 2 | Top 500 | Every 3 days | ~533 |
| Tier 3 | All 2,500 | Weekly | ~1,428 |
| **Total** | | | **~2,400** |

## Rate Limits

| Tier | Price | Monthly Requests |
|------|-------|-----------------|
| Free | $0 | 5,000 |
| Starter | $29 | 25,000 |
| Pro | $99 | 100,000 |
| Business | $299 | 500,000 |

## Development

### Run Tests

```bash
cd functions
pip install -r requirements.txt pytest pytest-asyncio
pytest tests/
```

### Local Testing

```bash
# Test collectors locally
cd functions/collectors
python -c "
import asyncio
from depsdev_collector import get_package_info
print(asyncio.run(get_package_info('lodash')))
"
```

## License

Proprietary - All rights reserved
