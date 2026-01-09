# Agent Prompt: Security Fixes

## Context

You are working on DepHealth, a dependency health intelligence platform that predicts npm package abandonment risk. The product has undergone a comprehensive security review and several vulnerabilities have been identified that need to be fixed.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 1: Security Review)

## Your Mission

Fix all critical and high-priority security vulnerabilities identified in the product review. Focus on authentication flows, race conditions, and data protection.

## Critical Issues to Fix

### 1. Magic Link Token Table Scan (MEDIUM → Fix Required)

**Location:** `functions/api/auth_callback.py:88-93`

**Current Problem:**
```python
response = table.scan(
    FilterExpression=Attr("magic_token").eq(token),
    ProjectionExpression="pk, sk, email, magic_expires, tier",
)
```
This is O(n) and will become expensive/slow as user base grows.

**Required Fix:**
1. Add a GSI on `magic_token` field in `infrastructure/lib/storage-stack.ts`
2. Update `auth_callback.py` to use the GSI query instead of scan

**GSI Specification:**
```typescript
{
  IndexName: "magic-token-index",
  KeySchema: [{ AttributeName: "magic_token", KeyType: "HASH" }],
  Projection: { ProjectionType: "KEYS_ONLY" },
}
```

### 2. API Key Creation Race Condition (HIGH → Critical Fix)

**Location:** `functions/api/create_api_key.py:59-74`

**Current Problem:**
```python
response = table.query(KeyConditionExpression=Key("pk").eq(user_id))
active_keys = [i for i in items if i.get("sk") != "PENDING"]
if len(active_keys) >= MAX_KEYS_PER_USER:
    return _error_response(400, "max_keys_reached", ...)
# RACE WINDOW: Another request could create a key here
api_key = generate_api_key(user_id=user_id, tier=tier, email=email)
```

Two concurrent requests could both pass the check and exceed `MAX_KEYS_PER_USER`.

**Required Fix Options:**
1. **Option A (Preferred):** Use DynamoDB conditional put with a counter attribute
2. **Option B:** Use DynamoDB TransactWriteItems to atomically check count and create key
3. **Option C:** Add a distributed lock using DynamoDB

### 3. API Key Revocation Race Condition (HIGH → Critical Fix)

**Location:** `functions/api/revoke_api_key.py:79-91`

**Current Problem:**
```python
active_keys = [i for i in items if i.get("sk") != "PENDING"]
if len(active_keys) <= 1:
    return _error_response(400, "cannot_revoke_last_key", ...)
# RACE WINDOW: Another revocation could succeed here
table.delete_item(Key={"pk": user_id, "sk": target_key["sk"]})
```

**Required Fix:**
Use conditional delete with count verification, or use transactions.

### 4. Magic Link Token Reuse Vulnerability (HIGH → Critical Fix)

**Location:** `functions/api/auth_callback.py:124-129`

**Current Problem:**
```python
table.update_item(
    Key={"pk": user_id, "sk": user["sk"]},
    UpdateExpression="REMOVE magic_token, magic_expires SET last_login = :now",
    # MISSING: ConditionExpression to prevent replay
)
```

A fast attacker could potentially use the same magic link twice before it's cleared.

**Required Fix:**
Add `ConditionExpression="attribute_exists(magic_token)"` to make the token consumption atomic.

### 5. Enable TTL on API Keys Table (MEDIUM)

**Location:** `infrastructure/lib/storage-stack.ts`

**Current Problem:**
The `ttl` attribute is set in code (`signup.py:122-124`) but TTL is NOT enabled on the DynamoDB table.

**Required Fix:**
Add TTL configuration to the API keys table in CDK:
```typescript
timeToLiveAttribute: "ttl",
```

## Secondary Security Improvements

### 6. Input Validation for Package Names
Add validation in `get_package.py` and `post_scan.py` to prevent injection via malformed package names.

### 7. Rate Limit Bypass Prevention
Verify that demo mode rate limiting uses `requestContext.identity.sourceIp` (which cannot be spoofed) rather than `X-Forwarded-For` header.

## Files to Modify

| File | Changes |
|------|---------|
| `infrastructure/lib/storage-stack.ts` | Add magic-token-index GSI, enable TTL |
| `functions/api/auth_callback.py` | Use GSI query, add conditional expression |
| `functions/api/create_api_key.py` | Add atomic key creation |
| `functions/api/revoke_api_key.py` | Add atomic revocation |
| `tests/test_security.py` | Add tests for race conditions |
| `tests/test_auth_handlers.py` | Update tests for new GSI |

## Success Criteria

1. All table scans replaced with GSI queries
2. Race conditions eliminated with atomic operations
3. Magic link tokens are single-use (verified by tests)
4. TTL enabled and PENDING records auto-expire
5. All existing tests pass
6. New security tests added for race condition scenarios

## Testing Requirements

After making changes:
```bash
cd /home/iebt/projects/startup-experiment/work/dephealth
pytest tests/ -v
```

Specifically run security tests:
```bash
pytest tests/test_security.py tests/test_auth_handlers.py tests/test_concurrency.py -v
```

## CDK Deployment Note

After modifying `storage-stack.ts`, the GSI will need to be deployed:
```bash
cd infrastructure
npx cdk diff
npx cdk deploy
```

**Warning:** Adding a GSI to an existing table is a safe operation but takes time to backfill.

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 1 for full security analysis details.
