# Agent Prompt: API Design Improvements

## Context

You are working on DepHealth, a dependency health intelligence platform. The REST API needs improvements in consistency, documentation, and adherence to best practices.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 2: API Design Review)

## Your Mission

Improve API design consistency, create OpenAPI documentation, and consolidate duplicated code across handlers.

## Critical Issues to Fix

### 1. Create OpenAPI 3.0 Specification (HIGH PRIORITY)

**Location to create:** `docs/openapi.yaml`

**Requirements:**
- Document all endpoints with request/response schemas
- Include authentication requirements (X-API-Key header)
- Document all error codes and response formats
- Include rate limit headers documentation
- Add examples for each endpoint

**Endpoints to document:**
| Endpoint | Method | Auth Required |
|----------|--------|---------------|
| `/health` | GET | No |
| `/packages/{ecosystem}/{name}` | GET | Yes (or demo mode) |
| `/scan` | POST | Yes |
| `/usage` | GET | Yes |
| `/signup` | POST | No |
| `/verify` | GET | No |
| `/auth/magic-link` | POST | No |
| `/auth/callback` | GET | No |
| `/auth/me` | GET | Yes (session cookie) |
| `/api-keys` | GET | Yes (session cookie) |
| `/api-keys` | POST | Yes (session cookie) |
| `/api-keys/{key_id}` | DELETE | Yes (session cookie) |
| `/webhooks/stripe` | POST | Stripe signature |

### 2. Consolidate Error Response Functions (HIGH PRIORITY)

**Problem:** `_error_response` is duplicated in 6+ handlers:
- `functions/api/post_scan.py:234-240`
- `functions/api/get_package.py:316-326`
- `functions/api/signup.py:213-219`
- `functions/api/magic_link.py:190-196`
- `functions/api/verify_email.py:133-146`
- `functions/api/auth_callback.py:200-213`

**Solution:**
1. Enhance `functions/shared/response_utils.py` with a comprehensive `error_response()` function
2. Update all handlers to import and use the shared function
3. Remove local `_error_response` definitions

**Enhanced response_utils.py signature:**
```python
def error_response(
    status_code: int,
    code: str,
    message: str,
    headers: Optional[dict] = None,
    details: Optional[dict] = None,
    retry_after: Optional[int] = None,
) -> dict:
```

### 3. Add Missing Rate Limit Header (MEDIUM)

**Location:** `functions/api/get_package.py:293-307`

**Current headers:**
```python
"X-RateLimit-Limit": str(user["monthly_limit"])
"X-RateLimit-Remaining": str(remaining)
```

**Missing header:**
```python
"X-RateLimit-Reset": str(reset_timestamp)  # Unix timestamp of reset
```

**Also add to:** `functions/api/post_scan.py`

### 4. Consolidate decimal_default Function (MEDIUM)

**Problem:** `decimal_default` duplicated in:
- `functions/api/post_scan.py:23-27`
- `functions/shared/response_utils.py:17-21`

**Solution:** Remove from `post_scan.py`, import from `response_utils.py`

### 5. API Naming Consistency (LOW)

**Recommendations (document but don't change for backwards compatibility):**
- `/scan` should ideally be `/scans` (noun not verb)
- `/verify` should ideally be `/auth/verify` (grouped with auth endpoints)

**Action:** Document these as future breaking changes in API versioning strategy.

## Files to Create

| File | Purpose |
|------|---------|
| `docs/openapi.yaml` | OpenAPI 3.0 specification |
| `docs/api-versioning.md` | API versioning strategy document |

## Files to Modify

| File | Changes |
|------|---------|
| `functions/shared/response_utils.py` | Enhance error_response function |
| `functions/api/get_package.py` | Use shared error_response, add X-RateLimit-Reset |
| `functions/api/post_scan.py` | Use shared error_response, remove decimal_default |
| `functions/api/signup.py` | Use shared error_response |
| `functions/api/magic_link.py` | Use shared error_response |
| `functions/api/verify_email.py` | Use shared error_response |
| `functions/api/auth_callback.py` | Use shared error_response |
| `functions/api/create_api_key.py` | Use shared error_response |
| `functions/api/revoke_api_key.py` | Use shared error_response |
| `functions/api/get_usage.py` | Use shared error_response |
| `functions/api/auth_me.py` | Use shared error_response |

## OpenAPI Specification Template

Start with this structure for `docs/openapi.yaml`:

```yaml
openapi: 3.0.3
info:
  title: DepHealth API
  version: 1.0.0
  description: |
    Dependency Health Intelligence API for predicting npm package abandonment risk.

    ## Authentication
    Most endpoints require an API key passed via the `X-API-Key` header.

    ## Rate Limiting
    Rate limits are enforced per API key based on your subscription tier.
    See response headers for current usage.
  contact:
    email: hello@laranjo.dev
  license:
    name: MIT

servers:
  - url: https://api.dephealth.laranjo.dev/v1
    description: Production

security:
  - ApiKeyAuth: []

paths:
  /health:
    get:
      summary: Health check
      security: []  # No auth required
      responses:
        '200':
          description: API is healthy
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HealthResponse'

  /packages/{ecosystem}/{name}:
    get:
      summary: Get package health score
      parameters:
        - name: ecosystem
          in: path
          required: true
          schema:
            type: string
            enum: [npm]
        - name: name
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Package health data
          headers:
            X-RateLimit-Limit:
              schema:
                type: string
            X-RateLimit-Remaining:
              schema:
                type: string
            X-RateLimit-Reset:
              schema:
                type: string
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/PackageHealth'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '404':
          $ref: '#/components/responses/NotFound'
        '429':
          $ref: '#/components/responses/RateLimited'

  # ... continue for all endpoints

components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key

  schemas:
    HealthResponse:
      type: object
      properties:
        status:
          type: string
          example: healthy
        version:
          type: string
        timestamp:
          type: string
          format: date-time

    PackageHealth:
      type: object
      required:
        - package
        - ecosystem
        - health_score
        - risk_level
      properties:
        package:
          type: string
        ecosystem:
          type: string
        health_score:
          type: number
          minimum: 0
          maximum: 100
        risk_level:
          type: string
          enum: [CRITICAL, HIGH, MEDIUM, LOW]
        abandonment_risk:
          $ref: '#/components/schemas/AbandonmentRisk'
        # ... more properties

    Error:
      type: object
      required:
        - error
      properties:
        error:
          type: object
          required:
            - code
            - message
          properties:
            code:
              type: string
            message:
              type: string
            details:
              type: object

  responses:
    Unauthorized:
      description: Invalid or missing API key
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            error:
              code: invalid_api_key
              message: Invalid or missing API key

    NotFound:
      description: Resource not found
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'

    RateLimited:
      description: Rate limit exceeded
      headers:
        Retry-After:
          schema:
            type: integer
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
```

## Success Criteria

1. OpenAPI specification created and validates with `swagger-cli validate docs/openapi.yaml`
2. All handlers use shared `error_response()` function
3. No duplicated utility functions across handlers
4. X-RateLimit-Reset header added to rate-limited endpoints
5. All existing tests pass
6. API documentation matches actual implementation

## Testing Requirements

After making changes:
```bash
cd /home/iebt/projects/startup-experiment/work/dephealth
pytest tests/test_api_contracts.py -v
```

Validate OpenAPI spec:
```bash
npx @apidevtools/swagger-cli validate docs/openapi.yaml
```

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 2 for full API design analysis.
