# Changelog

All notable changes to DepHealth will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Product review document with comprehensive analysis
- Agent prompts for parallel development
- OpenAPI 3.0 specification documenting all API endpoints
- Comprehensive documentation (READMEs, CONTRIBUTING.md, .env.example)

### Changed
- Increased timing normalization from 0.5s to 1.5s for better enumeration protection
- Added TTL to PENDING signup records

### Fixed
- Moto compatibility issue with DynamoDB conditional expressions

## [1.0.0] - 2026-01-07

### Added
- Initial release of DepHealth
- Health score calculation (v2 algorithm)
- Abandonment risk prediction
- REST API with rate limiting
- CLI tool (@dephealth/cli)
- GitHub Action (dephealth/action)
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
