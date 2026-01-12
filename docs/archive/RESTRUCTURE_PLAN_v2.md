# PkgWatch Repository Restructure Plan v2
## (Refined based on Opus Agent Reviews)

## Executive Summary

The original plan was over-engineered. This revised plan achieves the same goals with **~90% less effort** and **lower risk**.

### What Changed After Review

| Original Proposal | Review Verdict | Revised Approach |
|------------------|----------------|------------------|
| `apps/` + `packages/` structure | **Rejected** - overkill for 3,200 LOC | Keep `functions/`, add `landing-page/` |
| Rename `functions/` to `packages/` | **Rejected** - worse import paths | Keep `functions/` as-is |
| npm workspaces | **Rejected** - not needed for Python | No workspaces |
| `git subtree add` | **Rejected** - too complex for 5 commits | Simple copy |
| Terraform→CDK migration | **Deferred** - fix state instead | S3 backend for Terraform |
| Lambda Layers for shared code | **Rejected** - bundling works fine | Keep bundling |
| Poetry for Python | **Rejected** - overhead not justified | Keep requirements.txt |

---

## The Problem (unchanged)

1. **Fragmented Git Repos** - Two separate `.git` directories (dephealth, astro-site)
2. **Build Artifacts in Git** - `website/` folder is duplicate of `dist/`
3. **Local Terraform State** - Not shareable across developers
4. **Empty Placeholder Directories** - Confusing

## The Solution (simplified)

### Target State

```
/work/dephealth/                  # Single git repository
├── README.md
├── .gitignore
│
├── functions/                    # UNCHANGED - Lambda code
│   ├── api/
│   ├── collectors/
│   ├── scoring/
│   └── shared/
│
├── landing-page/                 # MOVED from infrastructure/
│   ├── src/
│   ├── public/
│   ├── package.json
│   ├── astro.config.mjs
│   └── terraform/                # Moved alongside, not migrated to CDK
│       ├── main.tf
│       └── backend.tf            # NEW - S3 state backend
│
├── infrastructure/               # UNCHANGED - CDK stacks
│   ├── bin/app.ts
│   └── lib/
│       ├── storage-stack.ts
│       ├── api-stack.ts
│       └── pipeline-stack.ts
│
├── scripts/
│
└── docs/                         # Archive planning docs here
    └── archive/
```

---

## Implementation Plan

### Phase 1: Clean Up (30 minutes)

**Objective:** Remove clutter, fix .gitignore

**Steps:**

```bash
cd /home/iebt/projects/startup-experiment/work

# 1. Delete empty directories
rm -rf application/ operations/
rm -rf dephealth/docs/*
rmdir dephealth/tests/unit dephealth/tests/integration 2>/dev/null || true

# 2. Archive planning docs
mkdir -p dephealth/docs/archive
mv IMPLEMENTATION_PLAN.md dephealth/docs/archive/
mv PHASE_*.md dephealth/docs/archive/
mv phase-0-validation dephealth/docs/archive/

# 3. Add build artifacts to gitignore
echo "" >> infrastructure/landing-page/.gitignore
echo "# Build artifacts" >> infrastructure/landing-page/.gitignore
echo "website/" >> infrastructure/landing-page/.gitignore
echo "astro-site/dist/" >> infrastructure/landing-page/.gitignore
echo "astro-site/node_modules/" >> infrastructure/landing-page/.gitignore
```

**Validation:**
- No empty directories remain
- Planning docs archived
- `git status` shows clean after commit

---

### Phase 2: Consolidate Repositories (1 hour)

**Objective:** Move landing page into main repo, fix Terraform state

**Steps:**

```bash
cd /home/iebt/projects/startup-experiment/work/dephealth

# 1. Copy landing page source (NOT the built website folder)
cp -r ../infrastructure/landing-page/astro-site landing-page

# 2. Remove the separate .git from astro-site
rm -rf landing-page/.git

# 3. Create terraform directory inside landing-page
mkdir -p landing-page/terraform
cp ../infrastructure/landing-page/main.tf landing-page/terraform/
cp ../infrastructure/landing-page/deploy.sh landing-page/

# 4. Create S3 backend configuration for Terraform
cat > landing-page/terraform/backend.tf << 'EOF'
terraform {
  backend "s3" {
    bucket         = "dephealth-terraform-state"
    key            = "landing-page/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
  }
}
EOF

# 5. Update deploy.sh paths
sed -i 's|../website|./dist|g' landing-page/deploy.sh

# 6. Update .gitignore
cat >> .gitignore << 'EOF'

# Landing page
landing-page/node_modules/
landing-page/dist/
landing-page/.astro/
landing-page/terraform/.terraform/
landing-page/terraform/*.tfstate*
EOF

# 7. Commit the migration
git add .
git commit -m "Migrate landing page into main repository

- Moved astro-site source to landing-page/
- Moved Terraform config to landing-page/terraform/
- Added S3 backend for Terraform state
- Updated deploy script paths
- Previous astro-site git history available in docs if needed"
```

---

### Phase 3: Migrate Terraform State (30 minutes)

**Objective:** Move local tfstate to S3

**Prerequisites:** Create S3 bucket for state

```bash
# Create state bucket (one-time)
aws s3 mb s3://dephealth-terraform-state --region us-east-1
aws s3api put-bucket-versioning \
  --bucket dephealth-terraform-state \
  --versioning-configuration Status=Enabled

# Migrate state
cd /home/iebt/projects/startup-experiment/work/dephealth/landing-page/terraform
terraform init -migrate-state

# Verify
terraform plan  # Should show no changes
```

---

### Phase 4: Clean Up Old Structure (15 minutes)

**Objective:** Remove the now-obsolete infrastructure folder

```bash
cd /home/iebt/projects/startup-experiment/work

# Verify landing page works from new location first!
cd dephealth/landing-page
npm install
npm run build

# If successful, remove old structure
rm -rf ../infrastructure/landing-page

# If infrastructure/ is now empty, remove it
rmdir infrastructure 2>/dev/null || true
```

---

### Phase 5: Update Documentation (15 minutes)

**Objective:** Update README to reflect new structure

Update `dephealth/README.md`:

```markdown
## Project Structure

dephealth/
├── functions/           # Lambda function code (Python)
│   ├── api/             # API handlers
│   ├── collectors/      # Data collection
│   ├── scoring/         # Health scoring
│   └── shared/          # Shared utilities
├── landing-page/        # Astro landing page + Terraform
│   ├── src/             # Astro source
│   └── terraform/       # S3/CloudFront infrastructure
├── infrastructure/      # AWS CDK (API infrastructure)
├── scripts/             # Utility scripts
└── docs/                # Documentation
```

---

## Total Effort

| Phase | Time | Risk |
|-------|------|------|
| Phase 1: Clean Up | 30 min | None |
| Phase 2: Consolidate | 1 hour | Low |
| Phase 3: Terraform State | 30 min | Low |
| Phase 4: Remove Old | 15 min | None |
| Phase 5: Documentation | 15 min | None |
| **Total** | **~2.5 hours** | **Low** |

---

## What We're NOT Doing (and why)

| Rejected Idea | Why |
|---------------|-----|
| Restructure Python to `packages/` | Works fine as-is, worse imports |
| Migrate Terraform to CDK | Not worth the effort, just fix state |
| Add npm workspaces | Not needed for Python project |
| Use git subtree | Complex, only 5 commits to preserve |
| Add Lambda Layers | Bundling works, minimal duplication |
| Add turborepo | Over-engineering for 2 deployables |
| Add Poetry | requirements.txt is fine for 5 deps |

---

## Success Criteria

1. **Single Git Repository** - All code in `dephealth/`
2. **No Orphaned Files** - Empty dirs and old infra removed
3. **Shareable Terraform State** - S3 backend configured
4. **Working Deployments** - API and landing page deploy successfully
5. **Clear Documentation** - README reflects actual structure

---

## Rollback Plan

If anything goes wrong:

1. The old `infrastructure/landing-page/` is not deleted until Phase 4
2. Terraform state is versioned in S3
3. Git history preserved for all changes
4. Can revert any commit if needed

---

## Future Considerations (not now)

When/if the project grows significantly:

- **CI/CD Automation** - GitHub Actions for deployment
- **CDK for Landing Page** - If Terraform becomes burdensome
- **Lambda Layers** - If shared code exceeds 50KB
- **Monorepo Tooling** - If we add more applications
- **Tests** - Add proper test suite in `tests/` directory

For now: ship features, not infrastructure refactoring.
