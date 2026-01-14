"""
Circuit Breaker Pattern for External Service Protection.

Prevents cascade failures by stopping requests to failing services
and allowing them time to recover.

States:
- CLOSED: Normal operation, requests allowed
- OPEN: Service failing, requests blocked
- HALF_OPEN: Testing if service recovered

NOTE: This implementation uses asyncio.Lock for thread safety when used
with async/await and asyncio.gather() for concurrent operations.
"""

import asyncio
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
    """Current state of a circuit breaker with async lock for thread safety."""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[float] = None
    half_open_calls: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class InMemoryCircuitBreaker:
    """
    In-memory circuit breaker for single Lambda instance.

    Note: State is not shared across Lambda instances.
    Use DynamoDBCircuitBreaker for distributed coordination.

    Thread Safety: All state-modifying operations use asyncio.Lock to prevent
    race conditions when used with asyncio.gather() or concurrent coroutines.
    Use the async methods (can_execute_async, record_success_async, record_failure_async)
    for thread-safe operations in async contexts.
    """

    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitBreakerState()

    def _check_timeout_transition(self) -> CircuitState:
        """Check for OPEN -> HALF_OPEN transition (internal, not thread-safe)."""
        if self._state.state == CircuitState.OPEN:
            if self._state.last_failure_time:
                elapsed = time.time() - self._state.last_failure_time
                if elapsed >= self.config.timeout_seconds:
                    logger.info(f"Circuit {self.name}: OPEN -> HALF_OPEN (timeout elapsed)")
                    self._state.state = CircuitState.HALF_OPEN
                    self._state.half_open_calls = 0
                    self._state.success_count = 0
        return self._state.state

    @property
    def state(self) -> CircuitState:
        """Get current circuit state, checking for timeout.

        Note: This property is not thread-safe. For concurrent access,
        use can_execute_async() which properly acquires the lock.
        """
        return self._check_timeout_transition()

    def can_execute(self) -> bool:
        """Check if a request should be allowed.

        WARNING: This method is NOT thread-safe for concurrent async operations.
        Use can_execute_async() instead when using asyncio.gather() or similar.
        """
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

    async def can_execute_async(self) -> bool:
        """Check if a request should be allowed (thread-safe for async).

        Uses asyncio.Lock to prevent race conditions in half-open state
        when multiple coroutines check simultaneously.
        """
        async with self._state.lock:
            current_state = self._check_timeout_transition()

            if current_state == CircuitState.CLOSED:
                return True

            if current_state == CircuitState.OPEN:
                return False

            # HALF_OPEN: Allow limited requests (atomic check-and-increment)
            if self._state.half_open_calls < self.config.half_open_max_calls:
                self._state.half_open_calls += 1
                return True

            return False

    def record_success(self) -> None:
        """Record a successful request.

        WARNING: This method is NOT thread-safe for concurrent async operations.
        Use record_success_async() instead when using asyncio.gather() or similar.
        """
        if self._state.state == CircuitState.HALF_OPEN:
            self._state.success_count += 1
            if self._state.success_count >= self.config.success_threshold:
                logger.info(f"Circuit {self.name}: HALF_OPEN -> CLOSED (service recovered)")
                self._state.state = CircuitState.CLOSED
                self._state.failure_count = 0
        elif self._state.state == CircuitState.CLOSED:
            # Reset failure count on success
            self._state.failure_count = 0

    async def record_success_async(self) -> None:
        """Record a successful request (thread-safe for async)."""
        async with self._state.lock:
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
        """Record a failed request.

        WARNING: This method is NOT thread-safe for concurrent async operations.
        Use record_failure_async() instead when using asyncio.gather() or similar.
        """
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

    async def record_failure_async(self, error: Optional[Exception] = None) -> None:
        """Record a failed request (thread-safe for async)."""
        async with self._state.lock:
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

    Uses thread-safe async methods to prevent race conditions when
    multiple decorated functions are called concurrently.

    Usage:
        github_circuit = InMemoryCircuitBreaker("github")

        @circuit_breaker(github_circuit)
        async def call_github_api():
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            # Use thread-safe async method
            if not await breaker.can_execute_async():
                raise CircuitOpenError(
                    breaker.name,
                    breaker.config.timeout_seconds
                )

            try:
                result = await func(*args, **kwargs)
                await breaker.record_success_async()
                return result
            except Exception as e:
                await breaker.record_failure_async(e)
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

BUNDLEPHOBIA_CIRCUIT = InMemoryCircuitBreaker(
    "bundlephobia",
    CircuitBreakerConfig(
        failure_threshold=5,
        timeout_seconds=120,
        success_threshold=2,
    )
)

PYPI_CIRCUIT = InMemoryCircuitBreaker(
    "pypi",
    CircuitBreakerConfig(
        failure_threshold=10,
        timeout_seconds=60,
        success_threshold=3,
    )
)

# DynamoDB circuit breaker - for protecting against throttling cascades
# NOTE: Available for future use - not yet wired to DynamoDB operations.
# When integrated, wrap DynamoDB calls to prevent cascade failures during
# throttling events or capacity issues.
DYNAMODB_CIRCUIT = InMemoryCircuitBreaker(
    "dynamodb",
    CircuitBreakerConfig(
        failure_threshold=3,     # DynamoDB failures are serious
        timeout_seconds=30,      # Short timeout - DynamoDB recovers quickly
        success_threshold=2,
        half_open_max_calls=2,
    )
)
