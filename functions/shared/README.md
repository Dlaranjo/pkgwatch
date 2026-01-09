# Shared Utilities

This directory contains shared utility modules for error handling, resilience, and observability.

## Status: Available But Not Yet Integrated

These utilities have been implemented and tested, but are **not currently integrated** into the collectors to avoid nested retry logic and thread safety concerns. They are available for future proper integration.

## Available Utilities

### 🔴 circuit_breaker.py
Circuit breaker pattern implementation with CLOSED/OPEN/HALF_OPEN states.

**Status**: ⚠️ Requires async locking before production use
**Note**: Currently not thread-safe for concurrent async operations. Add `asyncio.Lock` protection before integrating.

### ✅ retry.py
Centralized retry logic with exponential backoff and jitter.

**Status**: ✅ Production ready
**Usage**: Apply to functions that don't already have internal retry logic.

### ✅ metrics.py
CloudWatch metrics utilities for error tracking.

**Status**: ✅ Production ready
**Functions**: `emit_error_metric()`, `emit_circuit_breaker_metric()`, `emit_dlq_metric()`

### ✅ logging_utils.py
Structured JSON logging for CloudWatch Logs Insights.

**Status**: ✅ Production ready, partially integrated
**Integrated In**: `health.py` endpoint
**Usage**: Call `configure_structured_logging()` at handler start, use `set_request_id()` for correlation.

## Integration Plan

### Why Not Integrated Yet?

1. **Nested Retries**: Collectors already have internal retry logic. Adding decorators creates double retry layers (up to 9 attempts).
2. **Thread Safety**: Circuit breaker needs `asyncio.Lock` for concurrent operations with `asyncio.gather()`.
3. **Import Issues**: `sys.path.insert()` pattern needs to be replaced with proper relative imports.

### Recommended Integration Approach

**Option A** (Safest): Keep existing manual retry logic, don't use decorators yet.

**Option B** (Future): Properly integrate after:
1. Adding `asyncio.Lock` to circuit breaker
2. Removing internal retry logic from collectors
3. Configuring `retryable_exceptions` to exclude `CircuitOpenError` and non-transient errors
4. Using relative imports instead of `sys.path.insert()`

## Testing

Tests are available in:
- `/home/user/dephealth/tests/test_circuit_breaker.py` (10 tests)
- `/home/user/dephealth/tests/test_retry.py` (12 tests)

**Note**: Tests require AWS region environment variable to be set.

## DLQ Error Classification

The DLQ processor (`dlq_processor.py`) includes error classification logic to distinguish between transient and permanent errors, improving retry efficiency.

**Features**:
- Classifies errors as `transient`, `permanent`, or `unknown`
- Skips retries for permanent errors (404, unauthorized, etc.)
- Continues retries for transient errors (timeouts, 503, rate limits)

**Status**: ✅ Integrated and production ready
