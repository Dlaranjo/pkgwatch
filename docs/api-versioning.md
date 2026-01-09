# API Versioning Strategy

## Current Version

**Version:** v1
**Base URL:** `https://api.dephealth.laranjo.dev/v1`
**Status:** Active (Current)

## Versioning Principles

### 1. URL-Based Versioning

We use URL path versioning (`/v1`, `/v2`, etc.) for major API versions:
- **Clear and explicit**: Version is immediately visible in the URL
- **Easy to route**: Different versions can be deployed independently
- **Simple caching**: CDNs and proxies can cache different versions separately

### 2. Backwards Compatibility

Within a major version (e.g., v1), we maintain strict backwards compatibility:
- **Additive changes only**: New fields, endpoints, or optional parameters
- **No breaking changes**: Existing integrations continue to work
- **Deprecation warnings**: Advanced notice via headers before removal in next major version

### 3. When to Introduce a New Major Version

A new major version (v2) is required for:
- Removing or renaming endpoints
- Changing response structures
- Making optional parameters required
- Modifying authentication methods
- Changing rate limit semantics

## Known API Inconsistencies (v1)

The following inconsistencies exist in v1 for historical reasons. They will be addressed in v2 to maintain backwards compatibility:

### 1. Endpoint Naming Inconsistencies

| Current Endpoint | Issue | Recommended v2 Name | Rationale |
|-----------------|-------|-------------------|-----------|
| `POST /scan` | Verb instead of noun | `POST /scans` | RESTful convention: resources should be nouns |
| `GET /verify` | Not grouped with auth | `GET /auth/verify` | Logical grouping with other auth endpoints |

**Impact**: Low - URLs work fine, but not perfectly RESTful
**Migration Path**: v2 will introduce proper naming while v1 endpoints remain available

### 2. Authentication Method Variety

Current v1 has three authentication methods:
- API Key (`X-API-Key` header) - for programmatic access
- Session Cookie (`session`) - for web application
- Webhook Signature (`Stripe-Signature`) - for Stripe webhooks

**Status**: Intentional design, not an inconsistency
**No changes planned**: Multiple auth methods serve different use cases appropriately

## Deprecation Policy

### Deprecation Process

1. **Announcement** (T-0): Deprecation announced in:
   - API changelog
   - Documentation
   - Email to affected users
   - Response header: `Deprecation: true` and `Sunset: <date>`

2. **Grace Period** (6 months minimum):
   - Deprecated endpoint continues to work
   - Documentation marked as deprecated
   - Alternative endpoint documented

3. **Removal** (T+6 months):
   - Deprecated endpoint removed in new major version
   - Old major version continues to work for existing users
   - New users must use current version

### Deprecation Headers

When an endpoint or feature is deprecated:

```
Deprecation: true
Sunset: Sat, 1 Jun 2026 00:00:00 GMT
Link: <https://docs.dephealth.laranjo.dev/migration/v1-to-v2>; rel="deprecation"
```

## Version Support Timeline

### Support Lifecycle

- **Current Version (v1)**: Full support, receives all updates
- **Previous Version (N-1)**: Security updates only for 12 months
- **Older Versions (N-2+)**: No support, endpoints may be deactivated

### Version History

| Version | Release Date | Support Status | End of Life |
|---------|-------------|----------------|-------------|
| v1      | 2026-01     | Current        | TBD         |

## Future Breaking Changes (Planned for v2)

When v2 is introduced, the following changes will be made:

### 1. Endpoint Naming

```yaml
# v1 (current)
POST /scan              # Verb-based
GET /verify            # Ungrouped auth endpoint

# v2 (planned)
POST /scans            # Noun-based, RESTful
GET /auth/verify       # Grouped with auth endpoints
```

### 2. Consistent Response Envelope

v2 will use consistent response structure:

```json
// Success responses
{
  "data": { ... },
  "meta": {
    "version": "2.0",
    "timestamp": "2026-06-01T10:00:00Z"
  }
}

// Error responses (already consistent)
{
  "error": {
    "code": "invalid_request",
    "message": "...",
    "details": { ... }
  }
}
```

### 3. Pagination Standardization

Future endpoints returning lists will use consistent pagination:

```json
{
  "data": [...],
  "pagination": {
    "total": 100,
    "page": 1,
    "per_page": 25,
    "has_next": true
  }
}
```

## Migration Guides

### v1 → v2 Migration (when available)

Migration guides will be published at:
- [https://docs.dephealth.laranjo.dev/migration/v1-to-v2](https://docs.dephealth.laranjo.dev/migration/v1-to-v2)

## Client Library Versioning

Official client libraries will follow this pattern:

```
dephealth-js@1.x.x    → supports API v1
dephealth-js@2.x.x    → supports API v2
dephealth-python@1.x  → supports API v1
```

## Version Negotiation (Future)

In future versions, we may support content negotiation via headers:

```http
Accept: application/vnd.dephealth.v2+json
```

Currently, use URL versioning exclusively.

## Contact

For questions about API versioning or migration:
- Email: [hello@laranjo.dev](mailto:hello@laranjo.dev)
- Documentation: [https://docs.dephealth.laranjo.dev](https://docs.dephealth.laranjo.dev)

---

**Last Updated:** 2026-01-09
**Document Version:** 1.0
