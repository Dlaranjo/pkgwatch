# PkgWatch Infrastructure

AWS CDK infrastructure for the PkgWatch platform.

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
| `StorageStack` | Data storage | DynamoDB tables, S3 buckets |
| `ApiStack` | API layer | API Gateway, Lambda functions, WAF |
| `PipelineStack` | Data collection | SQS queues, EventBridge rules, Collector Lambdas |
| `BudgetStack` | Cost monitoring | AWS Budget alerts |

## Prerequisites

- Node.js 20+
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
npx cdk deploy PkgWatchApiStack
```

## DynamoDB Tables

### pkgwatch-packages

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

### pkgwatch-api-keys

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
- `magic-token-index` (magic_token)
- `data-status-index` (data_status)

### pkgwatch-billing-events

| Attribute | Type | Description |
|-----------|------|-------------|
| `pk` | String | Event ID (e.g., `evt_xxx`) |
| `sk` | String | Timestamp |
| `event_type` | String | Stripe event type |
| `customer_id` | String | Stripe customer ID |
| `processed_at` | String | ISO timestamp |

## S3 Buckets

| Bucket | Purpose |
|--------|---------|
| `pkgwatch-raw-data` | Raw API responses from collectors |
| `pkgwatch-artifacts` | Build artifacts and deployments |
| `pkgwatch-logs` | Access logs and audit trails |

## Lambda Functions

### API Handlers
| Function | Trigger | Purpose |
|----------|---------|---------|
| GetPackageHandler | API Gateway | GET /packages/{ecosystem}/{name} |
| ScanHandler | API Gateway | POST /scan |
| SignupHandler | API Gateway | POST /signup |
| VerifyEmailHandler | API Gateway | GET /verify |
| MagicLinkHandler | API Gateway | POST /auth/magic-link |
| AuthCallbackHandler | API Gateway | GET /auth/callback |
| LogoutHandler | API Gateway | POST /auth/logout |
| AuthMeHandler | API Gateway | GET /auth/me |
| GetApiKeysHandler | API Gateway | GET /api-keys |
| CreateApiKeyHandler | API Gateway | POST /api-keys |
| RevokeApiKeyHandler | API Gateway | DELETE /api-keys/{id} |
| GetPendingKeyHandler | API Gateway | GET /api-keys/pending |
| GetUsageHandler | API Gateway | GET /usage |
| RequestPackageHandler | API Gateway | POST /packages/request |
| CreateCheckoutHandler | API Gateway | POST /checkout/create |
| CreateBillingPortalHandler | API Gateway | POST /billing-portal/create |
| UpgradePreviewHandler | API Gateway | GET /upgrade/preview |
| UpgradeConfirmHandler | API Gateway | POST /upgrade/confirm |
| StripeWebhookHandler | API Gateway | POST /webhooks/stripe |
| HealthHandler | API Gateway | GET /health |

### Background Functions
| Function | Trigger | Purpose |
|----------|---------|---------|
| ResetUsageHandler | EventBridge | Monthly usage counter reset |
| RefreshDispatcher | EventBridge | Triggers package refresh |
| RetryDispatcher | EventBridge | Retries failed collections |
| PackageCollector | SQS | Collects package data |
| ScoreCalculator | DynamoDB Streams | Calculates health scores |
| StreamsDLQProcessor | DynamoDB Streams | Handles streams DLQ |
| DLQProcessor | EventBridge | Handles failed collections |
| DataStatusMetrics | EventBridge | Reports data completeness |
| PipelineHealth | EventBridge | Monitors pipeline health |

### Discovery Functions
| Function | Trigger | Purpose |
|----------|---------|---------|
| GraphExpanderDispatcher | EventBridge | Dispatches dependency graph expansion |
| GraphExpanderWorker | SQS | Expands dependency graphs |
| NpmsioAudit | EventBridge | Audits packages via npms.io |
| PublishTopPackages | EventBridge | Publishes top packages list |

## Secrets

Stored in AWS Secrets Manager:

| Secret | Purpose |
|--------|---------|
| `pkgwatch/session-secret` | Session token signing |
| `pkgwatch/stripe-secret` | Stripe API access |
| `pkgwatch/stripe-webhook` | Stripe webhook verification |
| `pkgwatch/github-token` | GitHub API authentication |

## Useful Commands

```bash
# Synthesize CloudFormation template
npx cdk synth

# View stack outputs
npx cdk outputs PkgWatchApiStack

# Destroy stacks (careful!)
npx cdk destroy --all

# View logs
aws logs tail /aws/lambda/pkgwatch-GetPackageHandler --follow
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

Proprietary - All rights reserved
