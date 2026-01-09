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
