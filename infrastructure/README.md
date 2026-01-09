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
| ResetUsageHandler | EventBridge | Monthly usage counter reset |
| RefreshDispatcher | EventBridge | Triggers package refresh |
| PackageCollector | SQS | Collects package data |
| ScoreCalculator | DynamoDB Streams | Calculates health scores |
| DLQProcessor | EventBridge | Handles failed collections |

## Secrets

Stored in AWS Secrets Manager:

| Secret | Purpose |
|--------|---------|
| `dephealth/session-secret` | Session token signing |
| `dephealth/stripe-secret` | Stripe API access |
| `dephealth/stripe-webhook` | Stripe webhook verification |

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
