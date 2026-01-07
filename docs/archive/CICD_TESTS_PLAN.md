# CI/CD and Tests Plan (Revised)

## Revision Notes

This plan was simplified based on Opus agent review. Key changes:
- Removed codecov, multiple workflows, staging environment
- Consolidated to single workflow with 2 test files
- Fixed technical issues (respx, freezegun, terraform init, CDK approval)
- Focus on minimum viable CI that catches real bugs

---

## Phase 1: Python Tests (Do Now)

### Test Dependencies

Add to `tests/requirements.txt`:
```
pytest>=8.0.0
pytest-cov>=4.1.0
moto[dynamodb]>=5.0.0
respx>=0.21.0
freezegun>=1.3.0
```

### Test Files

```
tests/
├── conftest.py           # AWS credentials fixture
├── test_scoring.py       # health_score.py + abandonment_risk.py
└── test_auth.py          # shared/auth.py (security-critical)
```

### tests/conftest.py

```python
import os
import pytest
import boto3
from moto import mock_aws

@pytest.fixture(autouse=True)
def aws_credentials():
    """Set fake AWS credentials for all tests."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

@pytest.fixture
def mock_dynamodb():
    """Provide mocked DynamoDB with tables."""
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

        # API keys table with GSI
        dynamodb.create_table(
            TableName="dephealth-api-keys",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "key_hash", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "key-hash-index",
                    "KeySchema": [{"AttributeName": "key_hash", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        yield dynamodb
```

### tests/test_scoring.py (~15 tests)

Key tests to write:
1. `calculate_health_score()` with complete data
2. `calculate_health_score()` with missing data (defaults)
3. `_maintainer_health()` recent vs stale commits
4. `_user_centric_health()` high vs low downloads
5. `_get_risk_level()` boundary values (79/80, 59/60, 39/40)
6. `calculate_abandonment_risk()` healthy package
7. `calculate_abandonment_risk()` archived package
8. `calculate_abandonment_risk()` deprecated package
9. Time-dependent tests with `@freeze_time`

### tests/test_auth.py (~5 tests)

Key tests to write:
1. `validate_api_key()` with valid key
2. `validate_api_key()` with invalid key
3. `validate_api_key()` with missing key
4. `increment_usage()` updates counter
5. Rate limit enforcement

---

## Phase 2: GitHub Actions (Do Now)

### .github/workflows/ci.yml

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  test-and-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Python tests
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          cache: 'pip'
          cache-dependency-path: |
            functions/requirements.txt
            tests/requirements.txt

      - name: Install Python dependencies
        run: |
          pip install -r functions/requirements.txt
          pip install -r tests/requirements.txt

      - name: Run tests
        run: pytest tests/ -v --tb=short
        env:
          PYTHONPATH: ${{ github.workspace }}

      # CDK synth
      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: infrastructure/package-lock.json

      - name: CDK Synth
        working-directory: infrastructure
        run: |
          npm ci
          npm run synth

      # Landing page build
      - name: Build landing page
        working-directory: landing-page
        run: |
          npm ci
          npm run build

  deploy:
    needs: test-and-build
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    runs-on: ubuntu-latest
    concurrency:
      group: deploy-production
      cancel-in-progress: false
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      # CDK Deploy
      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: infrastructure/package-lock.json

      - name: CDK Deploy
        working-directory: infrastructure
        run: |
          npm ci
          npx cdk deploy --all --require-approval never

      # Landing page deploy
      - name: Deploy landing page
        working-directory: landing-page
        run: |
          npm ci
          npm run build
          aws s3 sync dist/ s3://dephealth-landing-page \
            --delete \
            --cache-control "max-age=86400" \
            --exclude ".DS_Store"
          aws cloudfront create-invalidation \
            --distribution-id ${{ vars.CLOUDFRONT_DISTRIBUTION_ID }} \
            --paths "/*"
```

### GitHub Repository Settings

1. **Add secret:** `AWS_ACCESS_KEY_ID`
2. **Add secret:** `AWS_SECRET_ACCESS_KEY`
3. **Add variable:** `CLOUDFRONT_DISTRIBUTION_ID` (get from `terraform output`)
4. **Branch protection on main:**
   - Require status check: `test-and-build`
   - No force push
   - No deletion

---

## Phase 3: Optional (Later)

Only add these when you have a specific need:

| Item | When to Add |
|------|-------------|
| Ruff linting | When codebase grows or you get tired of style inconsistencies |
| More test coverage | When a bug slips through that tests would have caught |
| Dependabot | When you want automated dependency updates |
| OIDC credentials | When you hire another developer or want better security |
| Staging environment | When you have paying customers |

---

## Implementation Checklist

- [ ] Create `tests/requirements.txt`
- [ ] Create `tests/conftest.py`
- [ ] Create `tests/test_scoring.py` (15 tests)
- [ ] Create `tests/test_auth.py` (5 tests)
- [ ] Create `.github/workflows/ci.yml`
- [ ] Get CloudFront distribution ID: `cd landing-page/terraform && terraform output`
- [ ] Add GitHub secrets and variables
- [ ] Enable branch protection
- [ ] Verify workflow runs

---

## Summary

**Total effort:** ~3 hours
**Files to create:** 5 (4 test files + 1 workflow)
**Tests to write:** ~20

This catches the most likely bugs (scoring algorithm errors) and validates infrastructure compiles. Everything else can wait until needed.
