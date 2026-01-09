# Agent Prompt: Code Quality Improvements

## Context

You are working on DepHealth, a dependency health intelligence platform. The codebase needs improvements in code quality, including eliminating duplication, reducing complexity, and improving consistency.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 12: Code Quality Review)

## Your Mission

Improve code quality by eliminating duplication, reducing complexity, fixing consistency issues, and improving type coverage.

## Critical Improvements

### 1. Consolidate Error Response Functions (HIGH PRIORITY)

**Problem:** `_error_response` function duplicated in 6+ handlers.

**Files with duplication:**
- `functions/api/post_scan.py:234-240`
- `functions/api/get_package.py:316-326`
- `functions/api/signup.py:213-219`
- `functions/api/magic_link.py:190-196`
- `functions/api/verify_email.py:133-146`
- `functions/api/auth_callback.py:200-213`

**Solution:** Update `functions/shared/response_utils.py`:

```python
"""
Response utilities for Lambda handlers.

Provides consistent response formatting for success and error responses.
"""

import json
from decimal import Decimal
from typing import Optional, Any, Dict


def decimal_default(obj: Any) -> Any:
    """JSON serializer for Decimal types from DynamoDB."""
    if isinstance(obj, Decimal):
        if obj % 1 == 0:
            return int(obj)
        return float(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def success_response(
    data: Any,
    status_code: int = 200,
    headers: Optional[Dict[str, str]] = None,
) -> dict:
    """
    Create a success response.

    Args:
        data: Response body data
        status_code: HTTP status code (default 200)
        headers: Additional response headers

    Returns:
        Lambda response dict
    """
    response_headers = {"Content-Type": "application/json"}
    if headers:
        response_headers.update(headers)

    return {
        "statusCode": status_code,
        "headers": response_headers,
        "body": json.dumps(data, default=decimal_default),
    }


def error_response(
    status_code: int,
    code: str,
    message: str,
    headers: Optional[Dict[str, str]] = None,
    details: Optional[Dict[str, Any]] = None,
    retry_after: Optional[int] = None,
) -> dict:
    """
    Create an error response.

    Args:
        status_code: HTTP status code
        code: Machine-readable error code (snake_case)
        message: Human-readable error message
        headers: Additional response headers
        details: Optional additional error details
        retry_after: Optional Retry-After header value in seconds

    Returns:
        Lambda response dict
    """
    response_headers = {"Content-Type": "application/json"}
    if headers:
        response_headers.update(headers)
    if retry_after is not None:
        response_headers["Retry-After"] = str(retry_after)

    body = {
        "error": {
            "code": code,
            "message": message,
        }
    }
    if details:
        body["error"]["details"] = details

    return {
        "statusCode": status_code,
        "headers": response_headers,
        "body": json.dumps(body, default=decimal_default),
    }


def redirect_response(
    location: str,
    status_code: int = 302,
    headers: Optional[Dict[str, str]] = None,
) -> dict:
    """
    Create a redirect response.

    Args:
        location: Redirect URL
        status_code: HTTP status code (302 or 301)
        headers: Additional headers (e.g., Set-Cookie)

    Returns:
        Lambda response dict
    """
    response_headers = {"Location": location}
    if headers:
        response_headers.update(headers)

    return {
        "statusCode": status_code,
        "headers": response_headers,
        "body": "",
    }
```

**Then update all handlers to use shared function:**
```python
# In each handler file, replace local _error_response with:
from shared.response_utils import error_response, success_response

# Remove local _error_response definition
# Update calls from _error_response to error_response
```

### 2. Consolidate Retry Logic (HIGH PRIORITY)

**Problem:** `retry_with_backoff` duplicated in collectors:
- `functions/collectors/depsdev_collector.py:46-76`
- `functions/collectors/npm_collector.py:45-68`
- `functions/collectors/bundlephobia_collector.py`

**Solution:** See Error Handling prompt (09) for `shared/retry.py`.

After creating the shared module, update collectors:
```python
# In each collector, replace local retry_with_backoff with:
from shared.retry import retry_async, HTTP_RETRY_CONFIG

# Usage:
result = await retry_async(client.get, url, config=HTTP_RETRY_CONFIG)
```

### 3. Consolidate decimal_default Function (MEDIUM PRIORITY)

**Problem:** Duplicated in:
- `functions/api/post_scan.py:23-27`
- `functions/shared/response_utils.py:17-21`

**Solution:** Remove from `post_scan.py`, import from shared:
```python
# In post_scan.py, remove:
def decimal_default(obj):
    ...

# Add import:
from shared.response_utils import decimal_default
```

### 4. Refactor High-Complexity Handlers (MEDIUM PRIORITY)

**Problem:** `get_package.py` handler is 135 lines with cyclomatic complexity >10.

**Solution:** Extract into smaller functions:

```python
# functions/api/get_package.py - Refactored

import logging
from typing import Tuple, Optional
from datetime import datetime, timezone

from shared.auth import validate_api_key, check_and_increment_usage
from shared.response_utils import success_response, error_response
from shared.db import get_package_by_name

logger = logging.getLogger(__name__)

# Constants
DEMO_REQUESTS_PER_HOUR = 20


def _parse_request(event: dict) -> Tuple[str, str, dict]:
    """
    Parse and validate the incoming request.

    Returns:
        Tuple of (ecosystem, package_name, headers)

    Raises:
        ValueError: If request is invalid
    """
    path_params = event.get("pathParameters") or {}
    ecosystem = path_params.get("ecosystem", "").lower()
    name = path_params.get("name", "")

    if not ecosystem or not name:
        raise ValueError("Missing ecosystem or package name")

    if ecosystem != "npm":
        raise ValueError(f"Unsupported ecosystem: {ecosystem}")

    # URL decode the name
    from urllib.parse import unquote
    name = unquote(name)

    headers = event.get("headers") or {}

    return ecosystem, name, headers


def _get_cors_headers(origin: str = None) -> dict:
    """Get CORS headers for response."""
    return {
        "Access-Control-Allow-Origin": origin or "*",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
    }


def _authenticate_request(headers: dict) -> Tuple[Optional[dict], bool]:
    """
    Authenticate the request.

    Returns:
        Tuple of (user_dict or None, is_demo_mode)
    """
    api_key = headers.get("x-api-key") or headers.get("X-API-Key")

    if not api_key:
        return None, True  # Demo mode

    user = validate_api_key(api_key)
    if not user:
        return None, False  # Invalid key

    return user, False


def _check_demo_rate_limit(client_ip: str) -> Tuple[bool, int]:
    """
    Check demo mode rate limit.

    Returns:
        Tuple of (is_allowed, remaining_requests)
    """
    # Implementation moved from main handler
    ...


def _build_response_data(item: dict, ecosystem: str, name: str) -> dict:
    """Build the response data from DynamoDB item."""
    return {
        "package": name,
        "ecosystem": ecosystem,
        "health_score": item.get("health_score"),
        "risk_level": item.get("risk_level"),
        "abandonment_risk": item.get("abandonment_risk"),
        "components": item.get("score_components"),
        # ... more fields
    }


def handler(event: dict, context) -> dict:
    """
    Handle GET /packages/{ecosystem}/{name} requests.
    """
    cors_headers = _get_cors_headers()

    # Parse request
    try:
        ecosystem, name, headers = _parse_request(event)
    except ValueError as e:
        return error_response(400, "invalid_request", str(e), headers=cors_headers)

    # Authenticate
    user, is_demo = _authenticate_request(headers)

    if not is_demo and user is None:
        return error_response(401, "invalid_api_key", "Invalid or missing API key", headers=cors_headers)

    # Rate limiting
    if is_demo:
        client_ip = event.get("requestContext", {}).get("identity", {}).get("sourceIp", "")
        allowed, remaining = _check_demo_rate_limit(client_ip)
        if not allowed:
            return error_response(429, "demo_rate_limit_exceeded", "Demo limit exceeded", headers=cors_headers)
    else:
        allowed, usage = check_and_increment_usage(user["user_id"], user["key_hash"], user["monthly_limit"])
        if not allowed:
            return _rate_limit_response(user, cors_headers)

    # Fetch package data
    item = get_package_by_name(ecosystem, name)
    if not item:
        return error_response(404, "package_not_found", f"Package '{name}' not found", headers=cors_headers)

    # Build response
    response_data = _build_response_data(item, ecosystem, name)

    # Add rate limit headers
    response_headers = {**cors_headers}
    if not is_demo:
        response_headers["X-RateLimit-Limit"] = str(user["monthly_limit"])
        response_headers["X-RateLimit-Remaining"] = str(max(0, user["monthly_limit"] - usage))

    return success_response(response_data, headers=response_headers)
```

### 5. Replace print() with Logger (MEDIUM PRIORITY)

**Problem:** Some files use `print()` instead of logger:
- `functions/shared/auth.py:123`
- `functions/shared/dynamo.py:33`

**Solution:**
```python
# In shared/auth.py, replace:
print(f"Error validating API key: {e}")

# With:
logger.error(f"Error validating API key: {e}")

# In shared/dynamo.py, replace:
print(f"Error fetching package: {e}")

# With:
logger.error(f"Error fetching package: {e}")
```

### 6. Add Type Hints to Lambda Handlers (MEDIUM PRIORITY)

**Problem:** Lambda handlers lack parameter type hints.

**Solution:** Create types in `shared/types.py`:

```python
"""
Type definitions for Lambda handlers.
"""

from typing import TypedDict, Optional, Any, Dict, List


class APIGatewayIdentity(TypedDict, total=False):
    sourceIp: str
    userAgent: str


class APIGatewayRequestContext(TypedDict, total=False):
    requestId: str
    identity: APIGatewayIdentity
    httpMethod: str
    path: str


class APIGatewayEvent(TypedDict, total=False):
    """API Gateway Lambda proxy event."""
    httpMethod: str
    path: str
    pathParameters: Optional[Dict[str, str]]
    queryStringParameters: Optional[Dict[str, str]]
    headers: Optional[Dict[str, str]]
    body: Optional[str]
    isBase64Encoded: bool
    requestContext: APIGatewayRequestContext


class LambdaContext:
    """Lambda execution context."""
    function_name: str
    memory_limit_in_mb: int
    invoked_function_arn: str
    aws_request_id: str

    def get_remaining_time_in_millis(self) -> int: ...


class LambdaResponse(TypedDict):
    """Lambda proxy response."""
    statusCode: int
    headers: Dict[str, str]
    body: str


class SQSRecord(TypedDict):
    """SQS message record."""
    messageId: str
    receiptHandle: str
    body: str
    attributes: Dict[str, str]
    messageAttributes: Dict[str, Any]
    md5OfBody: str
    eventSource: str
    eventSourceARN: str
    awsRegion: str


class SQSEvent(TypedDict):
    """SQS Lambda event."""
    Records: List[SQSRecord]
```

**Update handlers:**
```python
from shared.types import APIGatewayEvent, LambdaContext, LambdaResponse


def handler(event: APIGatewayEvent, context: LambdaContext) -> LambdaResponse:
    """Handle API request."""
    ...
```

### 7. Standardize Constants Location (LOW PRIORITY)

**Problem:** Constants like `TIER_LIMITS` defined in multiple files.

**Solution:** Create `shared/constants.py`:

```python
"""
Shared constants for DepHealth.
"""

# Tier configuration
TIER_LIMITS = {
    "free": 5000,
    "starter": 25000,
    "pro": 100000,
    "business": 500000,
}

TIER_NAMES = list(TIER_LIMITS.keys())

# Rate limiting
MAX_KEYS_PER_USER = 5
DEMO_REQUESTS_PER_HOUR = 20

# API configuration
SUPPORTED_ECOSYSTEMS = ["npm"]

# Scoring
RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SCORE_COMPONENTS = [
    "maintainer_health",
    "user_centric",
    "evolution",
    "community",
    "security",
]

# External APIs
DEPSDEV_API = "https://api.deps.dev/v3"
NPM_REGISTRY = "https://registry.npmjs.org"
GITHUB_API = "https://api.github.com"
BUNDLEPHOBIA_API = "https://bundlephobia.com/api/size"

# Timeouts
DEFAULT_TIMEOUT = 30.0
GITHUB_TIMEOUT = 45.0

# Rate limit shards
RATE_LIMIT_SHARDS = 10
GITHUB_HOURLY_LIMIT = 4000
```

**Update all files to import from shared:**
```python
from shared.constants import TIER_LIMITS, MAX_KEYS_PER_USER
```

### 8. Add ESLint to TypeScript Projects (LOW PRIORITY)

**Problem:** No linter configured for TypeScript.

**Solution:** Add ESLint to cli, action, and infrastructure.

**Create:** `cli/.eslintrc.json`
```json
{
  "root": true,
  "env": {
    "node": true,
    "es2022": true
  },
  "extends": [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended"
  ],
  "parser": "@typescript-eslint/parser",
  "parserOptions": {
    "ecmaVersion": "latest",
    "sourceType": "module"
  },
  "rules": {
    "@typescript-eslint/no-unused-vars": ["error", { "argsIgnorePattern": "^_" }],
    "@typescript-eslint/explicit-function-return-type": "off",
    "no-console": "off"
  }
}
```

**Add to package.json:**
```json
{
  "scripts": {
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix"
  },
  "devDependencies": {
    "@typescript-eslint/eslint-plugin": "^6.0.0",
    "@typescript-eslint/parser": "^6.0.0",
    "eslint": "^8.0.0"
  }
}
```

## Files to Create

| File | Purpose |
|------|---------|
| `functions/shared/constants.py` | Centralized constants |

## Files to Modify

| File | Changes |
|------|---------|
| `functions/shared/response_utils.py` | Add error_response, redirect_response |
| `functions/shared/types.py` | Add Lambda type definitions |
| `functions/api/get_package.py` | Refactor, use shared functions |
| `functions/api/post_scan.py` | Remove duplicates, use shared |
| `functions/api/signup.py` | Use shared error_response |
| `functions/api/magic_link.py` | Use shared error_response |
| `functions/api/verify_email.py` | Use shared error_response |
| `functions/api/auth_callback.py` | Use shared error_response |
| `functions/api/stripe_webhook.py` | Use shared constants |
| `functions/shared/auth.py` | Use logger, import constants |
| `functions/shared/dynamo.py` | Use logger |
| `functions/collectors/*.py` | Use shared retry, constants |
| `cli/package.json` | Add ESLint |
| `action/package.json` | Add ESLint |

## Success Criteria

1. No duplicated `_error_response` functions
2. No duplicated `retry_with_backoff` functions
3. No duplicated `decimal_default` functions
4. All handlers under 100 lines
5. All handlers have type hints
6. No `print()` statements (use logger)
7. Constants centralized in shared module
8. ESLint configured for TypeScript
9. All tests pass

## Testing Requirements

```bash
cd /home/iebt/projects/startup-experiment/work/dephealth
pytest tests/ -v

# TypeScript lint
cd cli && npm run lint
cd ../action && npm run lint
```

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 12 for full code quality analysis.
