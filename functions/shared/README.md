# Shared Utilities

This directory contains shared utility modules for authentication, error handling, resilience, and observability.

## Core Utilities

### auth.py
Authentication and authorization utilities.

**Functions**: `validate_api_key()`, `validate_session()`, `get_user_from_session()`
**Status**: ✅ Production ready, integrated in all API handlers

### errors.py
Custom exception classes for consistent error handling.

**Classes**: `PkgWatchError`, `AuthenticationError`, `NotFoundError`, `RateLimitError`, `ValidationError`
**Status**: ✅ Production ready, integrated throughout

### response_utils.py
HTTP response formatting utilities.

**Functions**: `success_response()`, `error_response()`, `cors_headers()`
**Status**: ✅ Production ready, integrated in all API handlers

### dynamo.py
DynamoDB utility functions.

**Functions**: `get_item()`, `put_item()`, `query()`, `update_item()`
**Status**: ✅ Production ready, integrated throughout

### types.py
Type definitions and data classes.

**Status**: ✅ Production ready

## Resilience Utilities

### circuit_breaker.py
Circuit breaker pattern implementation with CLOSED/OPEN/HALF_OPEN states.

**Status**: ✅ Production ready with DynamoDB-based distributed state
**Usage**: Protects external API calls (GitHub, npm, PyPI, deps.dev)

### retry.py
Centralized retry logic with exponential backoff and jitter.

**Status**: ✅ Production ready
**Usage**: Apply to functions that don't already have internal retry logic.

### metrics.py
CloudWatch metrics utilities for error tracking.

**Status**: ✅ Production ready
**Functions**: `emit_error_metric()`, `emit_circuit_breaker_metric()`, `emit_dlq_metric()`

### logging_utils.py
Structured JSON logging for CloudWatch Logs Insights.

**Status**: ✅ Production ready
**Usage**: Call `configure_structured_logging()` at handler start, use `set_request_id()` for correlation.

## Testing

Tests are available in:
- `tests/test_circuit_breaker.py`
- `tests/test_retry.py`

Run with: `PYTHONPATH=functions:. pytest tests/ -v`

## DLQ Error Classification

The DLQ processor (`dlq_processor.py`) includes error classification logic to distinguish between transient and permanent errors, improving retry efficiency.

**Features**:
- Classifies errors as `transient`, `permanent`, or `unknown`
- Skips retries for permanent errors (404, unauthorized, etc.)
- Continues retries for transient errors (timeouts, 503, rate limits)

**Status**: ✅ Integrated and production ready
