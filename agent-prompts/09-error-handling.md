# Agent Prompt: Error Handling and Resilience Improvements

## Context

You are working on DepHealth, a dependency health intelligence platform. The error handling needs improvements including circuit breakers, centralized retry logic, and better error classification.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 9: Error Handling Review)

## Your Mission

Implement resilience patterns including circuit breakers, centralized retry utilities, error classification, and improved observability.

## Current Error Handling

### Exception Hierarchy (`functions/shared/errors.py`)
```
APIError (base)
├── InvalidAPIKeyError (401)
├── RateLimitExceededError (429)
├── PackageNotFoundError (404)
├── InvalidEcosystemError (400)
├── InvalidRequestError (400)
└── InternalError (500)
```

### Key Files
- `functions/shared/errors.py` - Exception classes
- `functions/shared/response_utils.py` - Response formatting
- `functions/collectors/dlq_processor.py` - DLQ handling
- `functions/collectors/package_collector.py` - Data collection with retries

## Improvements to Implement

### 1. Implement Circuit Breaker Pattern (HIGH PRIORITY)

**Create:** `functions/shared/circuit_breaker.py`

```python
"""
Circuit Breaker Pattern for External Service Protection.

Prevents cascade failures by stopping requests to failing services
and allowing them time to recover.

States:
- CLOSED: Normal operation, requests allowed
- OPEN: Service failing, requests blocked
- HALF_OPEN: Testing if service recovered
"""

import time
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Callable, TypeVar, Any
from datetime import datetime, timezone, timedelta
from functools import wraps

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""
    failure_threshold: int = 5          # Failures before opening
    success_threshold: int = 2          # Successes to close from half-open
    timeout_seconds: int = 60           # Time before testing recovery
    half_open_max_calls: int = 3        # Max calls in half-open state


@dataclass
class CircuitBreakerState:
    """Current state of a circuit breaker."""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[float] = None
    half_open_calls: int = 0


class InMemoryCircuitBreaker:
    """
    In-memory circuit breaker for single Lambda instance.

    Note: State is not shared across Lambda instances.
    Use DynamoDBCircuitBreaker for distributed coordination.
    """

    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitBreakerState()

    @property
    def state(self) -> CircuitState:
        """Get current circuit state, checking for timeout."""
        if self._state.state == CircuitState.OPEN:
            if self._state.last_failure_time:
                elapsed = time.time() - self._state.last_failure_time
                if elapsed >= self.config.timeout_seconds:
                    logger.info(f"Circuit {self.name}: OPEN -> HALF_OPEN (timeout elapsed)")
                    self._state.state = CircuitState.HALF_OPEN
                    self._state.half_open_calls = 0
                    self._state.success_count = 0
        return self._state.state

    def can_execute(self) -> bool:
        """Check if a request should be allowed."""
        current_state = self.state

        if current_state == CircuitState.CLOSED:
            return True

        if current_state == CircuitState.OPEN:
            return False

        # HALF_OPEN: Allow limited requests
        if self._state.half_open_calls < self.config.half_open_max_calls:
            self._state.half_open_calls += 1
            return True

        return False

    def record_success(self) -> None:
        """Record a successful request."""
        if self._state.state == CircuitState.HALF_OPEN:
            self._state.success_count += 1
            if self._state.success_count >= self.config.success_threshold:
                logger.info(f"Circuit {self.name}: HALF_OPEN -> CLOSED (service recovered)")
                self._state.state = CircuitState.CLOSED
                self._state.failure_count = 0
        elif self._state.state == CircuitState.CLOSED:
            # Reset failure count on success
            self._state.failure_count = 0

    def record_failure(self, error: Optional[Exception] = None) -> None:
        """Record a failed request."""
        self._state.failure_count += 1
        self._state.last_failure_time = time.time()

        if self._state.state == CircuitState.HALF_OPEN:
            logger.warning(f"Circuit {self.name}: HALF_OPEN -> OPEN (service still failing)")
            self._state.state = CircuitState.OPEN
        elif self._state.state == CircuitState.CLOSED:
            if self._state.failure_count >= self.config.failure_threshold:
                logger.warning(
                    f"Circuit {self.name}: CLOSED -> OPEN "
                    f"({self._state.failure_count} failures)"
                )
                self._state.state = CircuitState.OPEN


class CircuitOpenError(Exception):
    """Raised when circuit is open and request is blocked."""

    def __init__(self, circuit_name: str, retry_after: int):
        self.circuit_name = circuit_name
        self.retry_after = retry_after
        super().__init__(f"Circuit '{circuit_name}' is open. Retry after {retry_after}s")


def circuit_breaker(breaker: InMemoryCircuitBreaker):
    """
    Decorator to wrap function calls with circuit breaker.

    Usage:
        github_circuit = InMemoryCircuitBreaker("github")

        @circuit_breaker(github_circuit)
        async def call_github_api():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            if not breaker.can_execute():
                raise CircuitOpenError(
                    breaker.name,
                    breaker.config.timeout_seconds
                )

            try:
                result = await func(*args, **kwargs)
                breaker.record_success()
                return result
            except Exception as e:
                breaker.record_failure(e)
                raise

        return wrapper
    return decorator


# Pre-configured circuit breakers for external services
GITHUB_CIRCUIT = InMemoryCircuitBreaker(
    "github",
    CircuitBreakerConfig(
        failure_threshold=5,
        timeout_seconds=120,
        success_threshold=2,
    )
)

DEPSDEV_CIRCUIT = InMemoryCircuitBreaker(
    "deps.dev",
    CircuitBreakerConfig(
        failure_threshold=10,
        timeout_seconds=60,
        success_threshold=3,
    )
)

NPM_CIRCUIT = InMemoryCircuitBreaker(
    "npm",
    CircuitBreakerConfig(
        failure_threshold=10,
        timeout_seconds=60,
        success_threshold=3,
    )
)
```

### 2. Create Centralized Retry Utility (HIGH PRIORITY)

**Create:** `functions/shared/retry.py`

```python
"""
Centralized retry logic with exponential backoff and jitter.

Features:
- Configurable retry counts and delays
- Exponential backoff with jitter (prevents thundering herd)
- Retryable exception filtering
- Structured logging for observability
"""

import asyncio
import logging
import random
from dataclasses import dataclass
from typing import Callable, TypeVar, Tuple, Type, Optional, Any
from functools import wraps

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter_factor: float = 0.3  # 0-30% jitter
    retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,)


def calculate_delay(attempt: int, config: RetryConfig) -> float:
    """Calculate delay with exponential backoff and jitter."""
    # Exponential backoff
    delay = min(
        config.base_delay * (config.exponential_base ** attempt),
        config.max_delay
    )

    # Add jitter to prevent thundering herd
    jitter = random.uniform(0, delay * config.jitter_factor)

    return delay + jitter


async def retry_async(
    func: Callable[..., T],
    *args,
    config: Optional[RetryConfig] = None,
    **kwargs
) -> T:
    """
    Execute async function with retry logic.

    Args:
        func: Async function to call
        *args: Positional arguments for func
        config: Retry configuration
        **kwargs: Keyword arguments for func

    Returns:
        Result from successful function call

    Raises:
        Last exception if all retries exhausted
    """
    config = config or RetryConfig()
    last_exception: Optional[Exception] = None

    for attempt in range(config.max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except config.retryable_exceptions as e:
            last_exception = e

            if attempt == config.max_retries:
                logger.error(
                    f"All {config.max_retries + 1} attempts failed for {func.__name__}",
                    extra={
                        "function": func.__name__,
                        "attempts": config.max_retries + 1,
                        "final_error": str(e),
                        "error_type": type(e).__name__,
                    }
                )
                raise

            delay = calculate_delay(attempt, config)

            logger.warning(
                f"Attempt {attempt + 1}/{config.max_retries + 1} failed for "
                f"{func.__name__}, retrying in {delay:.2f}s: {e}",
                extra={
                    "function": func.__name__,
                    "attempt": attempt + 1,
                    "delay_seconds": delay,
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
            )

            await asyncio.sleep(delay)

    # Should not reach here, but satisfy type checker
    raise last_exception or RuntimeError("Unexpected retry state")


def retry(config: Optional[RetryConfig] = None):
    """
    Decorator for async functions with retry logic.

    Usage:
        @retry(RetryConfig(max_retries=5))
        async def call_external_api():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            return await retry_async(func, *args, config=config, **kwargs)
        return wrapper
    return decorator


# Pre-configured retry configs for different scenarios
HTTP_RETRY_CONFIG = RetryConfig(
    max_retries=3,
    base_delay=1.0,
    max_delay=30.0,
    jitter_factor=0.3,
)

GITHUB_RETRY_CONFIG = RetryConfig(
    max_retries=3,
    base_delay=2.0,
    max_delay=60.0,
    jitter_factor=0.3,
)

DYNAMODB_RETRY_CONFIG = RetryConfig(
    max_retries=3,
    base_delay=0.1,
    max_delay=2.0,
    jitter_factor=0.2,
)
```

### 3. Add Error Classification to DLQ Processor (HIGH PRIORITY)

**Location:** `functions/collectors/dlq_processor.py`

**Add error classification:**

```python
# Add at top of file
TRANSIENT_ERROR_PATTERNS = [
    "timeout",
    "timed out",
    "connection reset",
    "connection refused",
    "503",
    "502",
    "504",
    "rate limit",
    "too many requests",
    "temporarily unavailable",
    "service unavailable",
]

PERMANENT_ERROR_PATTERNS = [
    "404",
    "not found",
    "does not exist",
    "invalid package",
    "malformed",
    "forbidden",
    "unauthorized",
]


def classify_error(error_message: str) -> str:
    """
    Classify error as transient or permanent.

    Returns:
        'transient' - Should retry
        'permanent' - Should not retry
        'unknown' - Default to transient behavior
    """
    error_lower = error_message.lower()

    for pattern in PERMANENT_ERROR_PATTERNS:
        if pattern in error_lower:
            return "permanent"

    for pattern in TRANSIENT_ERROR_PATTERNS:
        if pattern in error_lower:
            return "transient"

    return "unknown"


def should_retry(body: dict) -> bool:
    """
    Determine if message should be retried based on error and retry count.
    """
    retry_count = body.get("_retry_count", 0)
    last_error = body.get("_last_error", "")
    error_class = body.get("_error_class", "unknown")

    # Don't retry permanent errors
    if error_class == "permanent":
        logger.info(f"Skipping retry for permanent error: {last_error}")
        return False

    # Don't retry if max retries exceeded
    if retry_count >= MAX_DLQ_RETRIES:
        return False

    return True


# Update process_message to use classification
def process_message(message: dict) -> bool:
    """Process a single DLQ message."""
    body = json.loads(message["Body"])
    message_id = message["MessageId"]

    # Classify the error
    last_error = body.get("_last_error", "")
    error_class = classify_error(last_error)
    body["_error_class"] = error_class

    if not should_retry(body):
        if error_class == "permanent":
            logger.info(f"Storing permanent failure for {body.get('name')}: {last_error}")
        _store_permanent_failure(body, message_id, last_error)
        _delete_message(message)
        return True

    # Requeue for retry...
```

### 4. Add CloudWatch Metrics for Error Tracking (MEDIUM PRIORITY)

**Create:** `functions/shared/metrics.py`

```python
"""
CloudWatch metrics utilities for error tracking and observability.
"""

import os
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

cloudwatch = boto3.client("cloudwatch")

NAMESPACE = "DepHealth"


def emit_metric(
    metric_name: str,
    value: float = 1.0,
    unit: str = "Count",
    dimensions: Optional[Dict[str, str]] = None,
) -> None:
    """
    Emit a CloudWatch metric.

    Args:
        metric_name: Name of the metric
        value: Metric value (default 1.0 for counters)
        unit: CloudWatch unit (Count, Seconds, etc.)
        dimensions: Optional dimension key-value pairs
    """
    try:
        metric_data = {
            "MetricName": metric_name,
            "Value": value,
            "Unit": unit,
            "Timestamp": datetime.now(timezone.utc),
        }

        if dimensions:
            metric_data["Dimensions"] = [
                {"Name": k, "Value": v} for k, v in dimensions.items()
            ]

        cloudwatch.put_metric_data(
            Namespace=NAMESPACE,
            MetricData=[metric_data],
        )
    except ClientError as e:
        # Don't fail on metric emission errors
        logger.warning(f"Failed to emit metric {metric_name}: {e}")


def emit_error_metric(
    error_type: str,
    service: Optional[str] = None,
    handler: Optional[str] = None,
) -> None:
    """
    Emit an error metric with standard dimensions.

    Args:
        error_type: Type of error (e.g., 'rate_limit', 'timeout', 'internal')
        service: External service name (e.g., 'github', 'npm')
        handler: Lambda handler name
    """
    dimensions = {"ErrorType": error_type}

    if service:
        dimensions["Service"] = service
    if handler:
        dimensions["Handler"] = handler

    emit_metric("Errors", dimensions=dimensions)


def emit_circuit_breaker_metric(
    circuit_name: str,
    state: str,
) -> None:
    """Emit circuit breaker state change metric."""
    emit_metric(
        "CircuitBreakerStateChange",
        dimensions={
            "CircuitName": circuit_name,
            "State": state,
        }
    )


def emit_dlq_metric(
    action: str,
    package_name: Optional[str] = None,
) -> None:
    """
    Emit DLQ processing metric.

    Args:
        action: 'requeued', 'permanent_failure', 'processed'
        package_name: Name of package (optional)
    """
    dimensions = {"Action": action}
    if package_name:
        dimensions["Package"] = package_name[:50]  # Truncate for dimension limit

    emit_metric("DLQProcessing", dimensions=dimensions)
```

### 5. Add Structured Logging (MEDIUM PRIORITY)

**Create:** `functions/shared/logging_utils.py`

```python
"""
Structured logging utilities for CloudWatch Logs Insights.
"""

import json
import logging
import os
from contextvars import ContextVar
from typing import Optional, Any, Dict
import uuid

# Context variable for request correlation
request_id_var: ContextVar[str] = ContextVar("request_id", default="")


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get(""),
            "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME", ""),
        }

        # Add extra fields
        if hasattr(record, "__dict__"):
            for key, value in record.__dict__.items():
                if key not in (
                    "name", "msg", "args", "created", "filename", "funcName",
                    "levelname", "levelno", "lineno", "module", "msecs",
                    "pathname", "process", "processName", "relativeCreated",
                    "stack_info", "exc_info", "exc_text", "thread", "threadName",
                    "message", "asctime",
                ):
                    log_entry[key] = value

        # Add exception info
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


def configure_structured_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Configure structured JSON logging for Lambda.

    Call this at the start of your handler.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add structured handler
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredFormatter())
    root_logger.addHandler(handler)

    return root_logger


def set_request_id(event: dict) -> str:
    """
    Extract or generate request ID and set in context.

    Args:
        event: Lambda event

    Returns:
        Request ID string
    """
    # Try API Gateway request ID
    request_id = event.get("requestContext", {}).get("requestId")

    # Try X-Request-Id header
    if not request_id:
        headers = event.get("headers") or {}
        request_id = headers.get("x-request-id") or headers.get("X-Request-Id")

    # Generate if not present
    if not request_id:
        request_id = str(uuid.uuid4())

    request_id_var.set(request_id)
    return request_id


def log_api_request(
    logger: logging.Logger,
    method: str,
    path: str,
    status_code: int,
    latency_ms: float,
    user_id: Optional[str] = None,
) -> None:
    """Log API request with standard fields."""
    logger.info(
        f"{method} {path} -> {status_code}",
        extra={
            "http_method": method,
            "path": path,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "user_id": user_id or "anonymous",
        }
    )


def log_external_call(
    logger: logging.Logger,
    service: str,
    operation: str,
    success: bool,
    latency_ms: float,
    error: Optional[str] = None,
) -> None:
    """Log external service call."""
    level = logging.INFO if success else logging.WARNING
    logger.log(
        level,
        f"External call to {service}: {operation} -> {'success' if success else 'failed'}",
        extra={
            "service": service,
            "operation": operation,
            "success": success,
            "latency_ms": latency_ms,
            "error": error,
        }
    )
```

### 6. Update Collectors to Use New Utilities (MEDIUM PRIORITY)

**Location:** `functions/collectors/github_collector.py`

**Update to use circuit breaker and centralized retry:**

```python
# At top of file
from shared.circuit_breaker import GITHUB_CIRCUIT, circuit_breaker, CircuitOpenError
from shared.retry import retry, GITHUB_RETRY_CONFIG
from shared.metrics import emit_error_metric, emit_circuit_breaker_metric

# Update get_repo_metrics method
class GitHubCollector:
    @circuit_breaker(GITHUB_CIRCUIT)
    @retry(GITHUB_RETRY_CONFIG)
    async def get_repo_metrics(self, owner: str, repo: str) -> Optional[dict]:
        """Fetch repository metrics from GitHub API."""
        # ... existing implementation ...
```

## Files to Create

| File | Purpose |
|------|---------|
| `functions/shared/circuit_breaker.py` | Circuit breaker implementation |
| `functions/shared/retry.py` | Centralized retry utilities |
| `functions/shared/metrics.py` | CloudWatch metrics utilities |
| `functions/shared/logging_utils.py` | Structured logging utilities |

## Files to Modify

| File | Changes |
|------|---------|
| `functions/collectors/dlq_processor.py` | Add error classification |
| `functions/collectors/github_collector.py` | Use circuit breaker and retry |
| `functions/collectors/npm_collector.py` | Use circuit breaker and retry |
| `functions/collectors/depsdev_collector.py` | Use circuit breaker and retry |
| `functions/collectors/package_collector.py` | Remove duplicated retry logic |
| `functions/api/*.py` | Add structured logging |

## Success Criteria

1. Circuit breaker implemented and integrated with collectors
2. Centralized retry utility used across all collectors
3. Error classification in DLQ processor
4. CloudWatch metrics for errors and circuit breaker states
5. Structured JSON logging configured
6. Duplicated retry code removed from collectors
7. All existing tests pass
8. New tests for circuit breaker and retry logic

## Testing Requirements

```bash
cd /home/iebt/projects/startup-experiment/work/dephealth
pytest tests/ -v
```

Add new tests for:
- Circuit breaker state transitions
- Retry logic with jitter
- Error classification
- Metric emission

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 9 for full error handling analysis.
