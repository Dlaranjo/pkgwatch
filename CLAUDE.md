# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PkgWatch is a dependency health intelligence platform that predicts npm package abandonment, maintenance decline, and security issues. It provides health scores (0-100) and abandonment risk predictions via REST API, CLI tool, and GitHub Action.

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

### Landing Page
```bash
cd landing-page
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
- **landing-page/** - Astro + Tailwind static site
- **tests/** - Python pytest tests (moto for AWS mocking)

### AWS Infrastructure (3 CDK Stacks)
1. **storage-stack.ts** - DynamoDB tables (packages, api-keys, users), S3 bucket
2. **api-stack.ts** - API Gateway, Lambda functions, WAF, custom domain
3. **pipeline-stack.ts** - EventBridge schedules, SQS queues, data collectors

### Data Flow
1. **Collectors** (EventBridge scheduled) fetch from deps.dev, npm registry, GitHub API
2. Data stored in DynamoDB with raw JSON in S3
3. **DynamoDB Streams** trigger scoring Lambda on data changes
4. **API Gateway** serves scored data to clients

### Lambda Function Organization
- `functions/api/` - API endpoint handlers (get_package, post_scan, auth, etc.)
- `functions/collectors/` - Data collection pipeline (npm, deps.dev, GitHub)
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
