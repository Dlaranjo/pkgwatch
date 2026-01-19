# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PkgWatch is a dependency health intelligence platform that predicts npm and Python package abandonment, maintenance decline, and security issues. It provides health scores (0-100) and abandonment risk predictions via REST API, CLI tool, and GitHub Action.

## Build and Test Commands

### Python (Lambda functions)
```bash
# Run all tests with coverage (from repo root)
PYTHONPATH=functions:. pytest tests/ -v --cov=functions --cov-report=term-missing

# Run specific test file
PYTHONPATH=functions:. pytest tests/test_scoring.py -v

# Run specific test
PYTHONPATH=functions:. pytest tests/test_scoring.py::TestHealthScore::test_healthy_package -v

# Run excluding integration tests
PYTHONPATH=functions:. pytest tests/ -v --ignore=tests/integration
```

### TypeScript (CLI, Action, API Client)
```bash
# Build all workspaces
npm run build

# Run CLI tests
cd cli && npm test

# Run Action tests
cd action && npm test

# Run api-client tests
cd packages/api-client && npm test
```

### Infrastructure (CDK)
```bash
cd infrastructure
npm run synth     # Synthesize CloudFormation templates
npm run diff      # Show changes vs deployed stack
npm run deploy    # Deploy all stacks
```

### Web
```bash
cd web
npm run dev       # Development server
npm run build     # Production build
```

## Architecture

### Monorepo Structure
- **functions/** - Python Lambda functions (API handlers, data collectors, scoring algorithms)
- **packages/api-client/** - Shared TypeScript API client used by CLI and Action
- **cli/** - @pkgwatch/cli npm package (Commander.js)
- **action/** - @pkgwatch/action GitHub Action
- **infrastructure/** - AWS CDK stacks (TypeScript)
- **web/** - Astro + Tailwind marketing site and dashboard
- **docs/** - API documentation (OpenAPI spec)
- **tests/** - Python pytest tests (moto for AWS mocking)

### AWS Infrastructure (4 CDK Stacks)
1. **storage-stack.ts** - DynamoDB tables (packages, api-keys, billing-events), S3 buckets
2. **api-stack.ts** - API Gateway, Lambda functions, WAF, custom domain
3. **pipeline-stack.ts** - EventBridge schedules, SQS queues, data collectors
4. **budget-stack.ts** - AWS Budget alerts for cost monitoring

### Data Flow
1. **Collectors** (EventBridge scheduled) fetch from deps.dev, npm registry, PyPI registry, GitHub API
2. Data stored in DynamoDB with raw JSON in S3
3. **DynamoDB Streams** trigger scoring Lambda on data changes
4. **API Gateway** serves scored data to clients

### Lambda Function Organization
- `functions/api/` - API endpoint handlers (get_package, post_scan, auth, billing, etc.)
- `functions/admin/` - Admin functions (data_status_metrics, seed_packages)
- `functions/collectors/` - Data collection pipeline (npm, PyPI, deps.dev, GitHub)
- `functions/discovery/` - Package discovery (graph_expander, npmsio_audit, publish_top_packages)
- `functions/scoring/` - Health score and abandonment risk algorithms
- `functions/shared/` - Auth, DynamoDB helpers, response utilities, error classes

### Authentication
- API Key auth via `X-API-Key` header (stored in api-keys DynamoDB table)
- Session cookie auth for dashboard (magic link flow)
- Demo mode: 20 req/hr per IP without API key

## Key Patterns

### Python Lambda Handler Pattern
```python
from shared.response_utils import success_response, error_response
from shared.auth import validate_api_key

def handler(event, context):
    # Auth check, business logic, return success_response() or error_response()
```

### Adding New API Endpoint
1. Create handler in `functions/api/`
2. Add Lambda function in `infrastructure/lib/api-stack.ts`
3. Add API Gateway route
4. Add tests in `tests/`

### Test Fixtures
Tests use moto for AWS service mocking. See `tests/conftest.py` for shared fixtures (mock DynamoDB tables, S3 buckets).

## CI/CD

GitHub Actions workflow (`.github/workflows/ci.yml`):
- Runs pytest with 80% coverage requirement
- CDK synth validation
- Landing page build
- Auto-deploys to AWS on main branch push

## Environment Variables

Lambda functions expect:
- `PACKAGES_TABLE`, `API_KEYS_TABLE`, `USERS_TABLE` - DynamoDB table names
- `RAW_DATA_BUCKET` - S3 bucket for raw API responses
- `PACKAGE_QUEUE_URL`, `DLQ_URL` - SQS queue URLs
- `GITHUB_TOKEN_SECRET_ARN`, `SESSION_SECRET_ARN` - Secrets Manager ARNs

## User Management / Testing

### User Data Model
Users are stored in the `pkgwatch-api-keys` DynamoDB table with these record types:
- **API Key records**: `pk=user_xxx`, `sk=<key_hash>` - Contains tier, email, stripe fields, key_suffix
- **USER_META records**: `pk=user_xxx`, `sk=USER_META` - Aggregated usage counters, key_count

Each user can have multiple API keys. The `tier` field is stored on each API key record (kept in sync by webhook handlers).

### Resetting Users for Testing
To wipe all users and start fresh:

```bash
# 1. Delete all user records from pkgwatch-api-keys
aws dynamodb scan --table-name pkgwatch-api-keys \
  --filter-expression "begins_with(pk, :u) OR pk = :t" \
  --expression-attribute-values '{":u":{"S":"user_"},":t":{"S":"test-user-cli"}}' \
  --projection-expression "pk, sk" --output json | \
  jq -c '.Items[]' | while read item; do
    aws dynamodb delete-item --table-name pkgwatch-api-keys --key "$item"
  done

# 2. Clear billing events (Stripe webhook audit trail)
aws dynamodb scan --table-name pkgwatch-billing-events \
  --projection-expression "pk, sk" --output json | \
  jq -c '.Items[]' | while read item; do
    aws dynamodb delete-item --table-name pkgwatch-billing-events --key "$item"
  done
```

### Downgrading a User to Free Tier
To downgrade a specific user (e.g., for testing payment flow):

```bash
# 1. Find user's API key records
aws dynamodb query --table-name pkgwatch-api-keys \
  --key-condition-expression "pk = :pk" \
  --expression-attribute-values '{":pk":{"S":"user_xxx"}}' \
  --output json | jq '.Items[] | {sk: .sk.S, tier: .tier.S}'

# 2. Update EACH API key record (not USER_META) to remove Stripe fields
aws dynamodb update-item --table-name pkgwatch-api-keys \
  --key '{"pk":{"S":"user_xxx"},"sk":{"S":"<key_hash>"}}' \
  --update-expression 'SET tier = :tier, monthly_limit = :limit REMOVE stripe_customer_id, stripe_subscription_id' \
  --expression-attribute-values '{":tier":{"S":"free"},":limit":{"N":"5000"}}'

# 3. Cancel Stripe subscription (if active)
STRIPE_KEY=$(aws secretsmanager get-secret-value --secret-id pkgwatch/stripe-secret --query SecretString --output text | jq -r '.key')
curl -X DELETE "https://api.stripe.com/v1/subscriptions/<sub_id>" -u "$STRIPE_KEY:"
```

**Important**: Users may have multiple API key records. You must update ALL of them to avoid inconsistency. The `stripe_subscription_id` field triggers checkout to return 409, so it must be removed for users to go through the payment flow again.
