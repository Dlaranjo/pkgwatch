# Changelog

All notable changes to PkgWatch will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-02-05

### Added
- OpenAPI 3.0 specification documenting all API endpoints
- Comprehensive documentation (READMEs, CONTRIBUTING.md, .env.example)
- Customer feedback mechanisms across all touchpoints (CLI, Action, dashboard)
- Data quality transparency indicators in API responses

### Changed
- Unified signup and login into single `/start` page
- Increased timing normalization from 0.5s to 1.5s for better enumeration protection
- Added TTL to PENDING signup records
- Updated favicon to eye icon matching PkgWatch branding
- Changed CLI progress bar color from emerald to blue
- Disabled API Gateway cache to reduce costs
- Bumped @pkgwatch/cli to v1.3.0

### Fixed
- Billing cycle date display in upgrade preview popup
- npm validation regex and centralized package validation
- CI health check URLs - removed /v1 prefix
- CLI documentation link anchor
- Stripe API billing period extraction
- Missing key_suffix in signup flow
- Subscription cancellation flow and billing cycle display
- Moto compatibility issue with DynamoDB conditional expressions
- Critical issues from SaaS evaluation

### Security
- Implemented data completeness backlog clearance

## [1.0.0] - 2026-01-07

### Added
- Initial release of PkgWatch
- Health score calculation (v2 algorithm)
- Abandonment risk prediction
- REST API with rate limiting
- CLI tool (@pkgwatch/cli)
- GitHub Action (pkgwatch/action)
- Passwordless authentication (magic links)
- Stripe billing integration
- Tiered pricing (Free, Starter, Pro, Business)

### Security
- API key hashing with SHA-256
- Timing normalization for email enumeration prevention
- WAF protection with AWS managed rules
- Session tokens with HMAC signing

---

## Version History

### Scoring Algorithm Versions

| Version | Date | Changes |
|---------|------|---------|
| v2.0 | 2026-01-01 | Revised weights, added security component |
| v1.0 | 2025-12-01 | Initial algorithm |

See [Methodology](/methodology) for detailed scoring documentation.
