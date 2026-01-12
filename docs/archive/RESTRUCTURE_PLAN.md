# PkgWatch Repository Restructure Plan

## Executive Summary

This plan consolidates PkgWatch from a fragmented multi-repo structure into a clean monorepo with unified infrastructure, eliminating technical debt and preparing for scale.

## Current State Analysis

### Problems Identified

1. **Fragmented Git Repositories**
   - `/work/dephealth/` - Main application (separate .git)
   - `/work/infrastructure/landing-page/astro-site/` - Landing page (separate .git)
   - Parent `/work/` has no version control

2. **Misplaced Components**
   - Landing page source inside `/infrastructure/` (should be application code)
   - Planning docs orphaned at `/work/` level

3. **Duplicate Build Artifacts**
   - `website/` folder is manual copy of `astro-site/dist/`
   - Risk of deploying stale content

4. **Mixed Infrastructure Tools**
   - CDK (TypeScript) for API, storage, pipeline
   - Terraform for landing page S3/CloudFront
   - Local Terraform state (not shareable)

5. **Empty Placeholders**
   - `/work/application/` - unused
   - `/work/operations/` - unused
   - `/work/dephealth/docs/` - empty
   - `/work/dephealth/tests/unit/` - empty
   - `/work/dephealth/tests/integration/` - empty

## Target State

### New Directory Structure

```
/work/dephealth/                        # Single git repository
├── README.md                           # Project overview
├── .gitignore                          # Unified gitignore
├── package.json                        # Root package.json for workspaces
│
├── apps/
│   └── landing-page/                   # Astro landing page (MOVED)
│       ├── src/
│       │   ├── components/
│       │   ├── layouts/
│       │   └── pages/
│       ├── public/
│       ├── package.json
│       ├── astro.config.mjs
│       └── tsconfig.json
│
├── packages/
│   ├── api/                            # Lambda API handlers
│   │   ├── src/
│   │   │   ├── health.py
│   │   │   ├── get_package.py
│   │   │   ├── get_usage.py
│   │   │   ├── post_scan.py
│   │   │   └── stripe_webhook.py
│   │   ├── tests/
│   │   └── requirements.txt
│   │
│   ├── collectors/                     # Data collection lambdas
│   │   ├── src/
│   │   │   ├── depsdev_collector.py
│   │   │   ├── npm_collector.py
│   │   │   ├── github_collector.py
│   │   │   ├── refresh_dispatcher.py
│   │   │   └── package_collector.py
│   │   ├── tests/
│   │   └── requirements.txt
│   │
│   ├── scoring/                        # Health scoring logic
│   │   ├── src/
│   │   │   ├── health_score.py
│   │   │   ├── abandonment_risk.py
│   │   │   └── score_package.py
│   │   ├── tests/
│   │   └── requirements.txt
│   │
│   └── shared/                         # Shared Python utilities
│       ├── src/
│       │   ├── auth.py
│       │   ├── dynamo.py
│       │   └── errors.py
│       └── requirements.txt
│
├── infrastructure/                     # All CDK infrastructure
│   ├── bin/
│   │   └── app.ts                      # CDK app entry
│   ├── lib/
│   │   ├── storage-stack.ts            # DynamoDB + S3
│   │   ├── api-stack.ts                # API Gateway + Lambdas
│   │   ├── pipeline-stack.ts           # EventBridge + SQS
│   │   └── landing-page-stack.ts       # S3 + CloudFront (NEW - replaces Terraform)
│   ├── package.json
│   ├── tsconfig.json
│   └── cdk.json
│
├── scripts/                            # Utility scripts
│   ├── select_packages.py
│   ├── initial_load.py
│   └── requirements.txt
│
├── docs/                               # Documentation
│   ├── architecture.md                 # System architecture
│   ├── api.md                          # API documentation
│   ├── deployment.md                   # Deployment guide
│   └── archive/                        # Historical planning docs
│       ├── IMPLEMENTATION_PLAN.md
│       ├── PHASE_1_DETAILED_PLAN.md
│       └── PHASE_1_LEAN_PLAN.md
│
└── .github/                            # GitHub configuration
    └── workflows/
        ├── deploy-api.yml              # API deployment
        └── deploy-landing-page.yml     # Landing page deployment
```

## Implementation Phases

### Phase 1: Consolidate Git Repositories (Low Risk)

**Objective:** Merge the astro-site git history into dephealth repo

**Steps:**
1. In `/work/dephealth/`:
   - Create `apps/landing-page/` directory
   - Use `git subtree add` to merge astro-site with history preserved

2. Remove standalone astro-site `.git`:
   ```bash
   rm -rf /work/infrastructure/landing-page/astro-site/.git
   ```

3. Update `.gitignore` in dephealth to include:
   ```
   apps/landing-page/node_modules/
   apps/landing-page/dist/
   apps/landing-page/.astro/
   ```

**Validation:**
- `git log apps/landing-page/` shows preserved history
- Landing page builds successfully from new location

### Phase 2: Restructure Python Packages (Medium Risk)

**Objective:** Move from flat `functions/` to organized `packages/` structure

**Steps:**
1. Create new package directories:
   ```bash
   mkdir -p packages/{api,collectors,scoring,shared}/src
   mkdir -p packages/{api,collectors,scoring}/tests
   ```

2. Move files:
   ```
   functions/api/*.py → packages/api/src/
   functions/collectors/*.py → packages/collectors/src/
   functions/scoring/*.py → packages/scoring/src/
   functions/shared/*.py → packages/shared/src/
   ```

3. Update imports in all Python files:
   - Old: `from shared.auth import ...`
   - New: `from packages.shared.src.auth import ...`

   OR use Lambda layers to keep imports simple

4. Consolidate requirements.txt:
   - Root `requirements.txt` for shared deps (boto3, etc.)
   - Package-specific for unique deps (stripe in api/)

**Validation:**
- All Python imports resolve correctly
- Lambda functions deploy and work

### Phase 3: Migrate Terraform to CDK (Medium Risk)

**Objective:** Replace Terraform landing page infrastructure with CDK

**Steps:**
1. Create `infrastructure/lib/landing-page-stack.ts`:
   ```typescript
   import * as cdk from 'aws-cdk-lib';
   import * as s3 from 'aws-cdk-lib/aws-s3';
   import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
   import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
   import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';

   export class LandingPageStack extends cdk.Stack {
     constructor(scope: Construct, id: string, props?: cdk.StackProps) {
       super(scope, id, props);

       const bucket = new s3.Bucket(this, 'WebsiteBucket', {
         bucketName: 'dephealth-landing-page',
         websiteIndexDocument: 'index.html',
         websiteErrorDocument: 'index.html',
         publicReadAccess: false,
         blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
         removalPolicy: cdk.RemovalPolicy.RETAIN,
       });

       const distribution = new cloudfront.Distribution(this, 'Distribution', {
         defaultBehavior: {
           origin: new origins.S3Origin(bucket),
           viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
         },
         defaultRootObject: 'index.html',
         errorResponses: [
           { httpStatus: 404, responseHttpStatus: 200, responsePagePath: '/index.html' },
         ],
       });

       new s3deploy.BucketDeployment(this, 'DeployWebsite', {
         sources: [s3deploy.Source.asset('../apps/landing-page/dist')],
         destinationBucket: bucket,
         distribution,
         distributionPaths: ['/*'],
       });
     }
   }
   ```

2. Add to `bin/app.ts`:
   ```typescript
   new LandingPageStack(app, 'PkgWatchLandingPage', { env });
   ```

3. Test deploy to new stack (parallel with Terraform)

4. Update DNS to point to new CloudFront

5. Tear down Terraform infrastructure:
   ```bash
   cd /work/infrastructure/landing-page
   terraform destroy
   ```

6. Remove Terraform files

**Validation:**
- Landing page accessible via new CloudFront
- SSL certificate working
- All pages load correctly

### Phase 4: Clean Up (Low Risk)

**Objective:** Remove orphaned files and empty directories

**Steps:**
1. Archive planning docs:
   ```bash
   mkdir -p docs/archive
   mv /work/IMPLEMENTATION_PLAN.md docs/archive/
   mv /work/PHASE_*.md docs/archive/
   mv /work/phase-0-validation/ docs/archive/
   ```

2. Remove empty/unused directories:
   ```bash
   rm -rf /work/application/
   rm -rf /work/operations/
   rm -rf /work/infrastructure/  # After Terraform migration complete
   ```

3. Remove duplicate build artifacts:
   ```bash
   rm -rf /work/infrastructure/landing-page/website/
   ```

4. Update root `.gitignore`

**Validation:**
- No orphaned files remain
- Git status is clean

### Phase 5: Add CI/CD (Enhancement)

**Objective:** Automate deployments via GitHub Actions

**Steps:**
1. Create `.github/workflows/deploy-api.yml`:
   ```yaml
   name: Deploy API
   on:
     push:
       branches: [main]
       paths:
         - 'packages/**'
         - 'infrastructure/**'
   jobs:
     deploy:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-node@v4
         - uses: actions/setup-python@v5
         - run: cd infrastructure && npm ci && npx cdk deploy --all --require-approval never
   ```

2. Create `.github/workflows/deploy-landing-page.yml`:
   ```yaml
   name: Deploy Landing Page
   on:
     push:
       branches: [main]
       paths:
         - 'apps/landing-page/**'
   jobs:
     deploy:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-node@v4
         - run: cd apps/landing-page && npm ci && npm run build
         - run: cd infrastructure && npm ci && npx cdk deploy PkgWatchLandingPage --require-approval never
   ```

3. Add AWS credentials as GitHub secrets

**Validation:**
- Push to main triggers deployment
- Deployment succeeds

## Risk Assessment

| Phase | Risk Level | Rollback Strategy |
|-------|------------|-------------------|
| 1. Consolidate Git | Low | Keep backup of original repos |
| 2. Restructure Python | Medium | CDK deploy will fail fast; revert commit |
| 3. Migrate Terraform→CDK | Medium | Keep Terraform running until CDK proven |
| 4. Clean Up | Low | Files archived, not deleted |
| 5. Add CI/CD | Low | Optional enhancement |

## Migration Checklist

### Pre-Migration
- [ ] Backup both git repositories
- [ ] Document current DNS configuration
- [ ] Note current CloudFront distribution ID
- [ ] Ensure all packages are loaded to DynamoDB

### Phase 1: Git Consolidation
- [ ] Create apps/landing-page directory
- [ ] Merge astro-site history
- [ ] Remove standalone .git
- [ ] Update .gitignore
- [ ] Verify landing page builds

### Phase 2: Python Restructure
- [ ] Create packages/ directory structure
- [ ] Move Python files
- [ ] Update imports
- [ ] Test locally
- [ ] Deploy and verify API works

### Phase 3: Terraform → CDK
- [ ] Create landing-page-stack.ts
- [ ] Add to app.ts
- [ ] Deploy new stack
- [ ] Verify landing page works
- [ ] Update DNS
- [ ] Terraform destroy
- [ ] Remove Terraform files

### Phase 4: Clean Up
- [ ] Archive planning docs
- [ ] Remove empty directories
- [ ] Remove website/ folder
- [ ] Update documentation
- [ ] Final git commit

### Phase 5: CI/CD
- [ ] Create GitHub Actions workflows
- [ ] Add AWS secrets to GitHub
- [ ] Test deployment pipeline
- [ ] Document deployment process

## Success Criteria

1. **Single Repository**: All code in one git repo with unified history
2. **Clean Structure**: No empty directories, no orphaned files
3. **Unified Infrastructure**: All resources managed by CDK
4. **Working Deployments**: API and landing page deploy successfully
5. **Documented**: README and docs/ reflect new structure

## Estimated Effort

| Phase | Complexity | Files Changed |
|-------|------------|---------------|
| Phase 1 | Low | ~5 |
| Phase 2 | Medium | ~20 |
| Phase 3 | Medium | ~5 new, ~3 deleted |
| Phase 4 | Low | ~10 deleted |
| Phase 5 | Low | ~3 new |

## Open Questions

1. **Lambda Layers**: Should shared Python code use Lambda layers for cleaner imports?
2. **Monorepo Tooling**: Use npm workspaces, pnpm, or turborepo for the monorepo?
3. **Python Packaging**: Use poetry or stick with requirements.txt?
4. **Environment Separation**: Add staging environment now or later?
5. **Existing Terraform State**: What about the existing S3 bucket - import into CDK or recreate?
