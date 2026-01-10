# Rebrand Plan: DepHealth → PkgWatch

## Overview

| Current | New |
|---------|-----|
| DepHealth | PkgWatch |
| dephealth | pkgwatch |
| DEPHEALTH | PKGWATCH |
| dephealth.laranjo.dev | pkgwatch.laranjo.dev |
| api.dephealth.laranjo.dev | api.pkgwatch.laranjo.dev |
| @dephealth/* | @pkgwatch/* |
| DepHealthClient | PkgWatchClient |
| DEPHEALTH_API_KEY | PKGWATCH_API_KEY |
| ~/.dephealth/ | ~/.pkgwatch/ |
| `dh_` (API key prefix) | `pw_` |

---

## ✅ DECISION: API Key Prefix → `pw_`

**Current:** API keys use the `dh_` prefix (e.g., `dh_abc123def456`)

**Decision:** Change to `pw_` prefix (e.g., `pw_abc123def456`)

This is a clean rebrand since there are no production users.

**Files affected by this decision:**
- `functions/shared/auth.py` - Lines 54, 88, 97: prefix generation and validation
- `functions/api/create_api_key.py` - Line 103: key generation
- `docs/openapi.yaml` - Line 341: example `dh_abc123def456`
- `.env.example` - Line 85: example key
- 33+ test files with `dh_` assertions

---

## Pre-Flight Checklist (Complete Before Starting)

### Required Accounts & Access
- [ ] npm account with ability to create `@pkgwatch` organization
- [ ] AWS account access (for CDK deployment)
- [ ] Cloudflare/DNS provider access (for DNS records)
- [ ] GitHub repository access

### Resources to Create BEFORE Code Changes
- [ ] Create npm organization: `npm org create pkgwatch`
- [ ] Verify npm scope available: `npm view @pkgwatch/cli` (should 404)
- [ ] Create Terraform state bucket: `aws s3 mb s3://pkgwatch-terraform-state --region us-east-1`
- [ ] Create Terraform locks table:
  ```bash
  aws dynamodb create-table \
    --table-name pkgwatch-terraform-locks \
    --attribute-definitions AttributeName=LockID,AttributeType=S \
    --key-schema AttributeName=LockID,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST \
    --region us-east-1
  ```
- [ ] Create AWS Secrets Manager entries (can be placeholder values initially):
  - `pkgwatch/github-token`
  - `pkgwatch/stripe-secret`
  - `pkgwatch/stripe-webhook`
  - `pkgwatch/session-secret`

### Backups (Safety)
- [ ] Export current Terraform state: `terraform state pull > terraform.tfstate.backup`
- [ ] Document current CloudFront distribution IDs
- [ ] Backup all Secrets Manager values

---

## Phase 1: Pre-Rebrand Setup (Do First)

### 1.1 Domain & DNS Setup
- [ ] Create DNS records for `pkgwatch.laranjo.dev`
- [ ] Create DNS records for `api.pkgwatch.laranjo.dev`
- [ ] Create DNS records for `app.pkgwatch.laranjo.dev` (if used)
- [ ] Set up SSL certificates for new subdomains

### 1.2 npm Scope Registration
- [ ] Create npm organization `@pkgwatch`
- [ ] Verify npm scope availability: `npm view @pkgwatch/cli` (should 404)

### 1.3 GitHub Organization (Optional)
- [ ] Create GitHub org `pkgwatch` (optional - can stay in personal repo)
- [ ] Or rename repo from `dephealth` to `pkgwatch`

### 1.4 SES Domain Identity
- [ ] Add SES identity for `pkgwatch.laranjo.dev`
- [ ] Configure DKIM DNS records
- [ ] Verify domain in SES console

---

## Phase 2: Infrastructure Changes (CDK)

### 2.1 File: `infrastructure/bin/app.ts`

| Line | Current | New |
|------|---------|-----|
| 16 | `DepHealthStorage` | `PkgWatchStorage` |
| 18 | `DepHealth storage resources` | `PkgWatch storage resources` |
| 23 | `ALERT_EMAIL` reference | (no change needed) |
| 31 | `DepHealthPipeline` | `PkgWatchPipeline` |
| 33 | `DepHealth data collection pipeline` | `PkgWatch data collection pipeline` |
| 41 | `DepHealthApi` | `PkgWatchApi` |
| 43 | `DepHealth REST API` | `PkgWatch REST API` |
| 51 | `Project: "DepHealth"` | `Project: "PkgWatch"` |

### 2.2 File: `infrastructure/lib/storage-stack.ts`

| Line | Current | New | Impact |
|------|---------|-----|--------|
| 19 | `dephealth-access-logs-${account}` | `pkgwatch-access-logs-${account}` | New bucket (logs can be lost) |
| 39 | `dephealth-packages` | `pkgwatch-packages` | **DATA MIGRATION REQUIRED** |
| 79 | `dephealth-api-keys` | `pkgwatch-api-keys` | **DATA MIGRATION REQUIRED** |
| 146 | `dephealth-raw-data-${account}` | `pkgwatch-raw-data-${account}` | New bucket (7-day lifecycle) |
| 168 | `exportName: "DepHealthPackagesTable"` | `exportName: "PkgWatchPackagesTable"` | CloudFormation export |
| 174 | `exportName: "DepHealthApiKeysTable"` | `exportName: "PkgWatchApiKeysTable"` | CloudFormation export |
| 180 | `exportName: "DepHealthRawDataBucket"` | `exportName: "PkgWatchRawDataBucket"` | CloudFormation export |

### 2.3 File: `infrastructure/lib/pipeline-stack.ts`

| Line | Current | New |
|------|---------|-----|
| 41 | `dephealth/github-token` | `pkgwatch/github-token` |
| 53 | `dephealth-package-dlq` | `pkgwatch-package-dlq` |
| 61 | `dephealth-package-queue` | `pkgwatch-package-queue` |
| 130 | `dephealth-refresh-dispatcher` | `pkgwatch-refresh-dispatcher` |
| 145 | `dephealth-package-collector` | `pkgwatch-package-collector` |
| 176 | `dephealth-score-calculator` | `pkgwatch-score-calculator` |
| 190 | `dephealth-streams-dlq` | `pkgwatch-streams-dlq` |
| 229 | `dephealth-daily-refresh` | `pkgwatch-daily-refresh` |
| 244 | `dephealth-three-day-refresh` | `pkgwatch-three-day-refresh` |
| 261 | `dephealth-weekly-refresh` | `pkgwatch-weekly-refresh` |
| 284 | `dephealth-dlq-processor` | `pkgwatch-dlq-processor` |
| 304 | `dephealth-dlq-processor` (rule) | `pkgwatch-dlq-processor` |
| 316-317 | `dephealth-alerts` | `pkgwatch-alerts` |
| 210 | `dephealth-streams-dlq-messages` (alarm) | `pkgwatch-streams-dlq-messages` |
| 329 | `dephealth-dlq-messages` (alarm) | `pkgwatch-dlq-messages` |
| 353 | `dephealth-dispatcher-errors` (alarm) | `pkgwatch-dispatcher-errors` |
| 376 | `dephealth-collector-errors` (alarm) | `pkgwatch-collector-errors` |
| 393 | `dephealth-score-calculator-errors` (alarm) | `pkgwatch-score-calculator-errors` |
| 409 | `dephealth-dynamo-throttling` (alarm) | `pkgwatch-dynamo-throttling` |
| 430 | `dephealth-apikeys-throttling` (alarm) | `pkgwatch-apikeys-throttling` |
| 454 | `dephealth-dispatcher-not-running` (alarm) | `pkgwatch-dispatcher-not-running` |
| 470 | `DepHealth-Operations` | `PkgWatch-Operations` |
| 549-561 | Export names | `PkgWatch*` |

### 2.4 File: `infrastructure/lib/api-stack.ts`

| Line | Current | New |
|------|---------|-----|
| 56 | `dephealth/stripe-secret` | `pkgwatch/stripe-secret` |
| 65 | `dephealth/stripe-webhook` | `pkgwatch/stripe-webhook` |
| 119 | `dephealth-api-health` | `pkgwatch-api-health` |
| 128 | `dephealth-api-get-package` | `pkgwatch-api-get-package` |
| 147 | `dephealth-api-scan` | `pkgwatch-api-scan` |
| 162 | `dephealth-api-get-usage` | `pkgwatch-api-get-usage` |
| 176 | `dephealth-api-stripe-webhook` | `pkgwatch-api-stripe-webhook` |
| 197 | `dephealth-api-reset-usage` | `pkgwatch-api-reset-usage` |
| 208 | `dephealth-monthly-usage-reset` | `pkgwatch-monthly-usage-reset` |
| 227 | `dephealth/session-secret` | `pkgwatch/session-secret` |
| 243 | `https://dephealth.laranjo.dev` | `https://pkgwatch.laranjo.dev` |
| 245-246 | `noreply@dephealth.laranjo.dev` | `noreply@pkgwatch.laranjo.dev` |
| 253-360 | All Lambda function names | `pkgwatch-api-*` |
| 264 | `DepHealthEmailIdentity` | `PkgWatchEmailIdentity` |
| 265 | `dephealth.laranjo.dev` (SES identity) | `pkgwatch.laranjo.dev` |
| 280 | SES ARN domain | `pkgwatch.laranjo.dev` |
| 372 | `DepHealthApi` | `PkgWatchApi` |
| 373 | `DepHealth API` | `PkgWatch API` |
| 374 | `Dependency Health Intelligence API` | `Package Watch API` |
| 401-408 | CORS origins | `pkgwatch.laranjo.dev`, `app.pkgwatch.laranjo.dev` |
| 667 | `dephealth-api-waf` | `pkgwatch-api-waf` |
| 672 | `DepHealthApiWaf` | `PkgWatchApiWaf` |
| 784 | `dephealth-api-${name}-errors` (template) | `pkgwatch-api-${name}-errors` |
| 801 | `dephealth-api-${name}-duration` (template) | `pkgwatch-api-${name}-duration` |
| 817 | `dephealth-api-${name}-throttles` (template) | `pkgwatch-api-${name}-throttles` |
| 862 | `dephealth-api-5xx-errors` (alarm) | `pkgwatch-api-5xx-errors` |
| 876 | `dephealth-api-4xx-errors` (alarm) | `pkgwatch-api-4xx-errors` |
| 897 | `dephealth-api-latency-p95` (alarm) | `pkgwatch-api-latency-p95` |
| 916 | `DepHealth-API-Latency` | `PkgWatch-API-Latency` |
| 938-950 | Export names | `PkgWatch*` |

### 2.5 File: `infrastructure/package.json`

| Field | Current | New |
|-------|---------|-----|
| name | `dephealth-infrastructure` | `pkgwatch-infrastructure` |

---

## Phase 3: Python Backend Changes

### 3.1 Environment Variable Defaults (All files in `functions/`)

Replace all occurrences of default table/bucket names:
- `dephealth-packages` → `pkgwatch-packages`
- `dephealth-api-keys` → `pkgwatch-api-keys`
- `dephealth-raw-data` → `pkgwatch-raw-data`

Files to update:
- `functions/api/signup.py`
- `functions/api/magic_link.py`
- `functions/api/auth_callback.py`
- `functions/api/auth_me.py`
- `functions/api/create_api_key.py`
- `functions/api/get_api_keys.py`
- `functions/api/get_package.py`
- `functions/api/post_scan.py`
- `functions/api/revoke_api_key.py`
- `functions/api/reset_usage.py`
- `functions/api/stripe_webhook.py`
- `functions/api/verify_email.py`
- `functions/shared/auth.py`
- `functions/shared/dynamo.py`
- `functions/collectors/package_collector.py`
- `functions/collectors/refresh_dispatcher.py`
- `functions/collectors/dlq_processor.py`
- `functions/scoring/score_package.py`

### 3.1.1 Additional Files (Docstrings & Comments)

| File | Line | Current | New |
|------|------|---------|-----|
| `functions/collectors/depsdev_collector.py` | 2 | `"Primary data source for DepHealth."` | `"Primary data source for PkgWatch."` |
| `functions/shared/constants.py` | 2 | `"Shared constants for DepHealth."` | `"Shared constants for PkgWatch."` |
| `functions/shared/README.md` | 57-58 | `/home/user/dephealth/tests/...` | `/home/user/pkgwatch/tests/...` |

### 3.1.2 Scripts Directory

| File | Line | Current | New |
|------|------|---------|-----|
| `scripts/initial_load.py` | 227 | `default="dephealth-packages"` | `default="pkgwatch-packages"` |

### 3.2 URLs and Domain References

| File | Current | New |
|------|---------|-----|
| `functions/api/signup.py` | `noreply@dephealth.laranjo.dev` | `noreply@pkgwatch.laranjo.dev` |
| `functions/api/signup.py` | `https://dephealth.laranjo.dev` | `https://pkgwatch.laranjo.dev` |
| `functions/api/signup.py` | `DepHealth` in email subject/body | `PkgWatch` |
| `functions/api/magic_link.py` | Same pattern | Same changes |
| `functions/api/get_package.py` | CORS origins | `pkgwatch.laranjo.dev` |
| `functions/api/get_package.py` | Pricing URL | `pkgwatch.laranjo.dev/pricing` |
| `functions/shared/response_utils.py` | CORS origins | `pkgwatch.laranjo.dev` |
| `functions/shared/errors.py` | Pricing URL | `pkgwatch.laranjo.dev/pricing` |
| `functions/shared/rate_limit_utils.py` | Pricing URL | `pkgwatch.laranjo.dev/pricing` |

### 3.3 CloudWatch Namespace

| File | Current | New |
|------|---------|-----|
| `functions/shared/metrics.py` | `DepHealth` | `PkgWatch` |

### 3.4 Documentation

| File | Changes |
|------|---------|
| `functions/README.md` | Title, description, table names |
| `functions/shared/README.md` | Path examples |

---

## Phase 4: CLI Changes

### 4.1 File: `cli/package.json`

| Field | Current | New |
|-------|---------|-----|
| name | `@dephealth/cli` | `@pkgwatch/cli` |
| description | Contains "DepHealth" | Contains "PkgWatch" |
| bin | `"dephealth": "./dist/index.js"` | `"pkgwatch": "./dist/index.js"` |
| author | `DepHealth` | `PkgWatch` |
| repository | `github.com/dephealth/cli` | Update accordingly |
| dependencies | `@dephealth/api-client` | `@pkgwatch/api-client` |

### 4.2 File: `cli/src/config.ts`

| Line | Current | New |
|------|---------|-----|
| 5, 58 | `DEPHEALTH_API_KEY` | `PKGWATCH_API_KEY` |
| 13 | `~/.dephealth/` | `~/.pkgwatch/` |
| 80 | Error message path | `~/.pkgwatch/config.json` |

### 4.3 File: `cli/src/index.ts`

| Item | Current | New |
|------|---------|-----|
| Program name | `.name("dephealth")` | `.name("pkgwatch")` |
| All URLs | `dephealth.laranjo.dev` | `pkgwatch.laranjo.dev` |
| Env var references | `DEPHEALTH_API_KEY` | `PKGWATCH_API_KEY` |
| Doctor output | `"DepHealth Doctor"` | `"PkgWatch Doctor"` |
| SARIF driver | `dephealth` | `pkgwatch` |

### 4.4 File: `cli/src/api.ts`

| Line | Current | New |
|------|---------|-----|
| 4 | Comment | Update |
| 25 | Import from `@dephealth/api-client` | `@pkgwatch/api-client` |
| 8 | Re-export `DepHealthClient` | `PkgWatchClient` |

### 4.5 File: `cli/README.md`

- Update all package name references
- Update all command examples
- Update environment variable name
- Update URLs

### 4.6 File: `cli/package.json` - Additional Fields

| Line | Field | Current | New |
|------|-------|---------|-----|
| 53 | homepage | `https://dephealth.laranjo.dev` | `https://pkgwatch.laranjo.dev` |

### 4.7 File: `cli/src/config.ts` - Additional Lines

| Line | Current | New |
|------|---------|-----|
| 2 | Comment: `Configuration management for DepHealth CLI.` | `Configuration management for PkgWatch CLI.` |
| 6 | Comment: `~/.dephealth/config.json` | `~/.pkgwatch/config.json` |

### 4.8 File: `cli/src/index.ts` - Additional Lines

| Line | Current | New |
|------|---------|-----|
| 3 | Comment: `DepHealth CLI` | `PkgWatch CLI` |
| 6-9 | Comments: `dephealth check`, etc. | `pkgwatch check`, etc. |
| 348, 352, 588, 592, 644, 648 | `github.com/Dlaranjo/dephealth/issues` | Update to new repo URL |
| 718 | `Enter your DepHealth API key` | `Enter your PkgWatch API key` |
| 806-812 | Help examples with `dephealth` | Help examples with `pkgwatch` |

### 4.9 Test Files: `cli/src/__tests__/*.ts`

| File | Lines | Current | New |
|------|-------|---------|-----|
| `config.test.ts` | 7 | `dephealth-test-${Date.now()}` | `pkgwatch-test-${Date.now()}` |
| `config.test.ts` | 28, 33, 43 | `process.env.DEPHEALTH_API_KEY` | `process.env.PKGWATCH_API_KEY` |
| `config.test.ts` | 62 | `".dephealth"` | `".pkgwatch"` |

---

## Phase 5: GitHub Action Changes

### 5.1 File: `action/package.json`

| Field | Current | New |
|-------|---------|-----|
| name | `@dephealth/action` | `@pkgwatch/action` |
| dependencies | `@dephealth/api-client` | `@pkgwatch/api-client` |

### 5.2 File: `action/action.yml`

| Field | Current | New |
|-------|---------|-----|
| name | `DepHealth Scan` | `PkgWatch Scan` |
| author | `DepHealth` | `PkgWatch` |
| description | References to DepHealth | PkgWatch |
| inputs.api-key.description | `DepHealth API key` | `PkgWatch API key` |

### 5.3 File: `action/src/*.ts`

- Update all `DepHealthClient` references to `PkgWatchClient`
- Update all URLs to `pkgwatch.laranjo.dev`
- Update import from `@dephealth/api-client` to `@pkgwatch/api-client`

### 5.4 File: `action/README.md`

- Update action name in all examples
- Update `DEPHEALTH_API_KEY` to `PKGWATCH_API_KEY`
- Update all URLs

### 5.5 File: `action/LICENSE`

- Update copyright holder name

### 5.6 File: `action/src/index.ts` - Detailed

| Line | Current | New |
|------|---------|-----|
| 138, 143, 168, 172 | `dephealth.laranjo.dev/dashboard` | `pkgwatch.laranjo.dev/dashboard` |
| 148 | `dephealth.laranjo.dev/pricing` | `pkgwatch.laranjo.dev/pricing` |
| 153, 158 | `DepHealth API`, `status.dephealth.laranjo.dev` | `PkgWatch API`, `status.pkgwatch.laranjo.dev` |

### 5.7 File: `action/src/scanner.ts`

| Line | Current | New |
|------|---------|-----|
| 4 | `import { DepHealthClient }` | `import { PkgWatchClient }` |
| 48 | `new DepHealthClient(apiKey)` | `new PkgWatchClient(apiKey)` |

### 5.8 File: `action/src/summary.ts`

| Line | Current | New |
|------|---------|-----|
| 38 | `DepHealth Scan Results` heading | `PkgWatch Scan Results` |
| 104 | `DepHealth` link, `dephealth.laranjo.dev` | `PkgWatch`, `pkgwatch.laranjo.dev` |

### 5.9 Test Files: `action/__tests__/*.ts`

| File | Lines | Pattern |
|------|-------|---------|
| `api.test.ts` | 2, 8, 34, 60, 82, 97, 104, 106, 112, 118, 125 | `DepHealthClient` → `PkgWatchClient` |
| `api.test.ts` | 38 | `api.dephealth.laranjo.dev` → `api.pkgwatch.laranjo.dev` |
| `index.test.ts` | 533, 657 | `dephealth.laranjo.dev/dashboard` |
| `index.test.ts` | 582 | `dephealth.laranjo.dev/pricing` |
| `index.test.ts` | 631 | `status.dephealth.laranjo.dev` |
| `scanner.test.ts` | 4, 17 | `DepHealthClient` |

---

## Phase 6: API Client Changes

### 6.1 File: `packages/api-client/package.json`

| Field | Current | New |
|-------|---------|-----|
| name | `@dephealth/api-client` | `@pkgwatch/api-client` |
| keywords | `dephealth` | `pkgwatch` |

### 6.2 File: `packages/api-client/src/index.ts`

| Item | Current | New |
|------|---------|-----|
| Class name | `DepHealthClient` | `PkgWatchClient` |
| Default base URL | `api.dephealth.laranjo.dev` | `api.pkgwatch.laranjo.dev` |
| Error messages | `DepHealth API` | `PkgWatch API` |

### 6.3 File: `packages/api-client/README.md`

- Update all references

### 6.4 File: `packages/api-client/package.json` - Additional Fields

| Line | Field | Current | New |
|------|-------|---------|-----|
| 4 | description | `Shared API client for DepHealth services` | `Shared API client for PkgWatch services` |

### 6.5 File: `packages/api-client/src/index.ts` - Additional Lines

| Line | Current | New |
|------|---------|-----|
| 2 | Comment: `DepHealth API Client` | `PkgWatch API Client` |

### 6.6 Test Files: `packages/api-client/src/__tests__/*.ts`

| File | Lines | Pattern |
|------|-------|---------|
| `client.test.ts` | 3, 13, 16, 22, 28, 34, 40, 49, 58, 67, 76, 85, 92, 94 | `DepHealthClient` → `PkgWatchClient` |
| `retry.test.ts` | 2, 8, 19, 708 | `DepHealthClient` → `PkgWatchClient` |

---

## Phase 7: Landing Page Changes

### 7.1 Configuration Files

| File | Changes |
|------|---------|
| `landing-page/astro.config.mjs` | `site: 'https://pkgwatch.laranjo.dev'` |
| `landing-page/deploy.sh` | Bucket name, domain |
| `landing-page/public/robots.txt` | Sitemap URL |
| `landing-page/public/sitemap.xml` | All URLs |

### 7.2 Terraform Infrastructure

| File | Changes |
|------|---------|
| `landing-page/terraform/main.tf` | Domain, bucket names, tags, OAC names |
| `landing-page/terraform/backend.tf` | State bucket name, lock table name |

### 7.3 Astro Pages

All files in `landing-page/src/pages/*.astro`:
- Page titles: `| DepHealth` → `| PkgWatch`
- Body copy: `DepHealth` → `PkgWatch`
- API URLs: `api.dephealth.laranjo.dev` → `api.pkgwatch.laranjo.dev`
- Email addresses: `*@dephealth.laranjo.dev` → `*@pkgwatch.laranjo.dev`
- CLI examples: `@dephealth/cli` → `@pkgwatch/cli`
- GitHub Action examples: Update references

### 7.4 Astro Components

All files in `landing-page/src/components/*.astro`:
- Navbar logo text
- Footer copyright
- CTA examples
- Terminal examples

### 7.5 Astro Layout

`landing-page/src/layouts/Layout.astro`:
- OG meta tags
- CSP headers (img-src, connect-src)
- Site name

**Detailed changes:**

| Line | Current | New |
|------|---------|-----|
| 14 | `https://dephealth.laranjo.dev/og-image.png` | `https://pkgwatch.laranjo.dev/og-image.png` |
| 37 | `og:site_name content="DepHealth"` | `og:site_name content="PkgWatch"` |
| 55 | CSP `img-src ... https://dephealth.laranjo.dev` | `img-src ... https://pkgwatch.laranjo.dev` |
| 56 | CSP `connect-src ... https://api.dephealth.laranjo.dev` | `connect-src ... https://api.pkgwatch.laranjo.dev` |
| 70, 77 | Plausible `data-domain="dephealth.laranjo.dev"` | `data-domain="pkgwatch.laranjo.dev"` |

**Note:** Plausible Analytics requires updating the site domain in the Plausible dashboard, or creating a new site for `pkgwatch.laranjo.dev`.

### 7.6 Assets

| File | Action |
|------|--------|
| `landing-page/public/og-image.svg` | Update text and URL |
| `landing-page/public/favicon.svg` | Replace with new brand (optional) |

---

## Phase 8: Documentation & Config

### 8.1 Root Files

| File | Line | Current | New |
|------|------|---------|-----|
| `package.json` (root) | 2 | `"name": "dephealth-monorepo"` | `"name": "pkgwatch-monorepo"` |
| `package.json` (root) | 5 | Description with "DepHealth" | Description with "PkgWatch" |
| `README.md` | Multiple | Project name, URLs, badges | Update all |

### 8.2 API Documentation

| File | Line | Current | New |
|------|------|---------|-----|
| `docs/openapi.yaml` | 3 | `title: DepHealth API` | `title: PkgWatch API` |
| `docs/openapi.yaml` | 6 | `description: ...DepHealth...` | `description: ...PkgWatch...` |
| `docs/openapi.yaml` | 26 | `url: https://api.dephealth.laranjo.dev/v1` | `url: https://api.pkgwatch.laranjo.dev/v1` |
| `docs/openapi.yaml` | 85-86 | URLs in descriptions | Update to pkgwatch |
| `docs/openapi.yaml` | 341 | `example: "dh_abc123def456"` | `example: "pw_abc123def456"` |
| `docs/openapi.yaml` | 899, 906 | Error URLs | Update to pkgwatch |
| `docs/api-versioning.md` | Multiple | `dephealth.laranjo.dev`, `docs.dephealth.laranjo.dev` | Update all |

### 8.3 Other Documentation

| File | Changes |
|------|---------|
| `CONTRIBUTING.md` | Repository URLs |
| `CHANGELOG.md` | Project name references |
| `.env.example` | All env var names, default values, example API key |
| `docs/*.md` | All references |

### 8.4 Archive Documentation (Historical - DO NOT UPDATE)

The following files contain historical references and should NOT be updated (preserves project history):
- `docs/archive/CICD_TESTS_PLAN.md`
- `docs/archive/RESTRUCTURE_PLAN.md`
- `docs/archive/PHASE_1_LEAN_PLAN.md`
- `docs/archive/IMPLEMENTATION_PLAN.md`

### 8.3 Research Documentation

`/research/DEVELOPMENT_FRONTS.md`:
- Project name
- Table names in examples
- URLs

---

## Phase 9: Test Files

### 9.1 Python Tests - Detailed

| File | Occurrences | Key Patterns |
|------|-------------|--------------|
| `tests/conftest.py` | 5 | Line 2 docstring, table names at 77, 123, 164, 189 |
| `tests/test_api_contracts.py` | 54+ | URLs, table names, branding |
| `tests/test_get_package.py` | 24+ | Table names, URLs |
| `tests/test_security.py` | 64+ | Table names, URLs, assertions |
| `tests/test_edge_cases.py` | 42+ | Table names, error messages |
| `tests/test_auth_handlers.py` | 30+ | SES email at lines 24, 370 |
| `tests/test_concurrency.py` | 22+ | Table names |
| `tests/test_post_scan.py` | 18+ | Table names |
| `tests/test_collectors.py` | 40+ | CloudWatch namespace at line 2420 |
| `tests/test_dynamo_helpers.py` | 3 | Table names |
| `tests/test_dlq_processor.py` | 9 | Table names |
| `tests/test_error_handling.py` | 52+ | Assertions at lines 1282-1283 checking table names not leaked |
| `tests/test_stripe_webhook.py` | 22+ | Table names |
| `tests/test_reset_usage.py` | 28+ | Table names |
| `tests/test_api_keys.py` | 24+ | Table names, key prefix `dh_` |
| `tests/test_get_usage.py` | 6 | Table names |
| `tests/integration/test_integration_flows.py` | 60+ | URLs at line 118, SES mock at 106 |

**Critical test assertions to update:**
- `tests/test_collectors.py:2420` - Asserts CloudWatch namespace is `"DepHealth"`
- `tests/test_error_handling.py:1282-1283` - Asserts `dephealth-packages` not in error messages
- `tests/test_auth_handlers.py:24,370` - SES email identity verification mocks
- `tests/integration/test_integration_flows.py:118` - Test URL `test.dephealth.example.com`

### 9.2 TypeScript Tests

See sections 4.9, 5.9, and 6.6 for detailed TypeScript test file changes.

### 9.3 API Key Prefix in Tests

Update all test files that:
- Generate mock API keys with `dh_` prefix → `pw_`
- Assert API key format validation
- Use example keys in test data

---

## Phase 10: CI/CD

### 10.1 GitHub Workflows

| File | Changes |
|------|---------|
| `.github/workflows/ci.yml` | Secret names, S3 bucket references |
| `cli/.github/workflows/ci.yml` | npm package version check |
| `action/.github/workflows/ci.yml` | Secret names |

### 10.2 GitHub Repository Secrets

Update in GitHub Settings → Secrets:

| Current Secret | New Secret |
|----------------|------------|
| `DEPHEALTH_API_KEY` | `PKGWATCH_API_KEY` |
| Other secrets as needed | ... |

### 10.3 Hardcoded CloudFront Distribution ID

**Issue:** `.github/workflows/ci.yml` line 134 has hardcoded distribution ID `E3A2X106W5KELX`

**Fix options:**
1. After deploying new infrastructure, update with new CloudFront distribution ID
2. Or make dynamic:
```yaml
- name: Get CloudFront Distribution ID
  id: cf
  run: |
    DIST_ID=$(terraform -chdir=landing-page/terraform output -raw cloudfront_distribution_id)
    echo "distribution_id=$DIST_ID" >> $GITHUB_OUTPUT

- name: Invalidate CloudFront
  run: |
    aws cloudfront create-invalidation \
      --distribution-id ${{ steps.cf.outputs.distribution_id }} \
      --paths "/*"
```

---

## Execution Order

### Step 1: Setup (Before Code Changes) - Allow 24-48 hours

```bash
# 1. Set up DNS records for new subdomains (in Cloudflare or DNS provider)
#    - pkgwatch.laranjo.dev → CloudFront
#    - api.pkgwatch.laranjo.dev → API Gateway

# 2. Verify DNS propagation (may take 24-48 hours for full propagation)
dig pkgwatch.laranjo.dev
nslookup api.pkgwatch.laranjo.dev

# 3. Register @pkgwatch npm scope
npm org create pkgwatch

# 4. Set up SES domain identity for pkgwatch.laranjo.dev
#    - Add DKIM DNS records
#    - SES verification can take 24-72 hours in sandbox mode

# 5. Create Terraform state resources (see Pre-Flight Checklist)

# 6. Create Secrets Manager entries with values from old secrets
```

### Step 2: Code Changes (Single Commit)
```bash
# Run global search and replace
# Order: api-client → cli → action → infrastructure → functions → landing-page → docs

# Search patterns:
# - "dephealth" → "pkgwatch" (lowercase)
# - "DepHealth" → "PkgWatch" (PascalCase)
# - "DEPHEALTH" → "PKGWATCH" (uppercase)
# - "dephealth.laranjo.dev" → "pkgwatch.laranjo.dev"
# - "dh_" → "pw_" (API key prefix)

# Verification command (should only return REBRAND_PLAN.md and archive docs):
grep -ri "dephealth" --include="*.py" --include="*.ts" --include="*.json" \
  --include="*.md" --include="*.astro" --include="*.tf" \
  --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=archive
```

### Step 3: Infrastructure Deployment
```bash
# IMPORTANT: Since no users/data exist, this is a FRESH deployment
# Old resources will remain (can be manually deleted later)

cd infrastructure
npm run build
npx cdk deploy --all

# The secrets should already exist from Pre-Flight (populated with values)
```

### Step 4: Landing Page Deployment
```bash
cd landing-page/terraform

# Option A: Fresh deployment (recommended - abandons old state)
terraform init -reconfigure
terraform apply

# Option B: Migrate state (if you need to preserve state history)
# terraform state pull > terraform.tfstate.backup  # Already done in pre-flight
# terraform init -migrate-state

# Deploy site
cd ..
npm run build
./deploy.sh

# Update CloudFront distribution ID in CI/CD workflow
# Get new ID: aws cloudfront list-distributions --query "DistributionList.Items[0].Id"
```

### Step 5: Publish npm Packages
```bash
# Build and publish in order:
cd packages/api-client
npm publish --access public

cd ../cli
npm publish --access public

cd ../action
npm publish --access public
```

### Step 6: Verification
- [ ] Visit https://pkgwatch.laranjo.dev - landing page works
- [ ] Visit https://api.pkgwatch.laranjo.dev/v1/health - API responds
- [ ] Run `npx @pkgwatch/cli doctor` - CLI works
- [ ] Test email sending (signup flow)
- [ ] Verify CloudWatch dashboards/alarms exist
- [ ] Test GitHub Action in a test repo

---

## Rollback Plan

Since there's no production data or users, rollback is simple:

1. Revert git commits
2. Redeploy old infrastructure (if deployed)
3. Unpublish npm packages (within 72 hours of publish)

---

## Post-Rebrand Cleanup

- [ ] Delete old DNS records for dephealth.laranjo.dev (after verification)
- [ ] Update any external links (social media, etc.)
- [ ] Archive old documentation

---

## Files Changed Summary

| Category | Files | Estimated Changes |
|----------|-------|-------------------|
| Infrastructure | 5 | ~110 |
| Python Backend | 20 | ~54 |
| CLI | 6 | ~80 |
| GitHub Action | 6 | ~60 |
| API Client | 3 | ~20 |
| Landing Page | 25 | ~91 |
| Documentation | 10 | ~100 |
| Tests | 25 | ~200 |
| Config/CI | 5 | ~30 |
| **Total** | **~105** | **~745** |

---

## Verification Checklist

### Pre-Deployment
- [ ] npm org `@pkgwatch` created and accessible
- [ ] DNS records propagated (verify with `dig`)
- [ ] SES domain identity verified
- [ ] Terraform state bucket created
- [ ] Terraform locks table created
- [ ] All Secrets Manager entries populated

### Infrastructure
- [ ] All Lambda functions deployed with new names
- [ ] DynamoDB tables created with new names
- [ ] S3 buckets created with new names
- [ ] SQS queues created with new names
- [ ] Secrets Manager secrets created and populated
- [ ] EventBridge rules active
- [ ] CloudWatch alarms configured
- [ ] CloudWatch Log Groups created with new names
- [ ] CloudWatch namespace is `PkgWatch`
- [ ] WAF attached to API Gateway
- [ ] SNS topic with email subscription
- [ ] SQS DLQ subscribed to SNS topic
- [ ] API Gateway custom domain configured

### API
- [ ] Health endpoint responds: `curl https://api.pkgwatch.laranjo.dev/v1/health`
- [ ] Package lookup works
- [ ] Scan endpoint works
- [ ] Auth flow works (signup → verify → login)
- [ ] Magic link email sends with correct branding
- [ ] Verification email sends with correct branding
- [ ] Rate limiting works
- [ ] CORS headers allow new domain origins
- [ ] Error messages show correct URLs (pricing, signup)

### CLI
- [ ] `npx @pkgwatch/cli --version` works
- [ ] `pkgwatch check lodash` works
- [ ] `pkgwatch scan` works
- [ ] `pkgwatch config` works
- [ ] `pkgwatch doctor` works
- [ ] Config stored in `~/.pkgwatch/`
- [ ] Environment variable `PKGWATCH_API_KEY` recognized
- [ ] SARIF output uses correct driver name (`pkgwatch`)

### GitHub Action
- [ ] Action runs in test workflow
- [ ] Outputs correct results
- [ ] Job summary renders with correct branding
- [ ] Links point to pkgwatch.laranjo.dev

### Landing Page
- [ ] All pages load
- [ ] Forms work (signup, login)
- [ ] API calls use correct endpoints
- [ ] No broken links
- [ ] SEO meta tags correct (title, description, og:site_name)
- [ ] CSP headers allow new domains
- [ ] Plausible analytics configured for new domain

### npm Packages
- [ ] `@pkgwatch/api-client` published and installable
- [ ] `@pkgwatch/cli` published and installable
- [ ] `@pkgwatch/action` published (if applicable)

### Tests
- [ ] All Python tests pass
- [ ] All TypeScript tests pass
- [ ] No assertions checking for old branding

### Code Verification
- [ ] `grep -ri "dephealth" --include="*.py" --include="*.ts"` returns only archive files
