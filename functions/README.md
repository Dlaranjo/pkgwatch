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
│   ├── reset_usage.py      # Monthly usage reset (EventBridge)
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
