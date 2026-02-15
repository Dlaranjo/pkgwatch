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
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from functools import wraps
from typing import Callable, Optional, TypeVar

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

    failure_threshold: int = 5  # Failures before opening
    success_threshold: int = 2  # Successes to close from half-open
    timeout_seconds: int = 60  # Time before testing recovery
    half_open_max_calls: int = 3  # Max calls in half-open state


@dataclass
class CircuitBreakerState:
    """Current state of a circuit breaker."""

    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[float] = None
    half_open_calls: int = 0
    # NOTE: Lock removed from dataclass - see InMemoryCircuitBreaker._get_lock()
    # for lazy initialization that handles Lambda event loop changes


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
        # Lazy-initialized lock with event loop tracking
        # Lambda can reuse containers but create new event loops
        self._lock: Optional[asyncio.Lock] = None
        self._lock_loop_id: Optional[int] = None

    def _get_lock(self) -> asyncio.Lock:
        """Get asyncio.Lock, recreating if event loop changed."""
        try:
            current_loop_id = id(asyncio.get_running_loop())
        except RuntimeError:
            current_loop_id = None

        if self._lock is not None and self._lock_loop_id != current_loop_id:
            self._lock = None

        if self._lock is None:
            self._lock = asyncio.Lock()
            self._lock_loop_id = current_loop_id

        return self._lock

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
        async with self._get_lock():
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
                self._state.half_open_calls = 0  # Reset for next open cycle
                self._state.success_count = 0  # Reset for next open cycle
        elif self._state.state == CircuitState.CLOSED:
            # Reset failure count on success
            self._state.failure_count = 0

    async def record_success_async(self) -> None:
        """Record a successful request (thread-safe for async)."""
        async with self._get_lock():
            if self._state.state == CircuitState.HALF_OPEN:
                self._state.success_count += 1
                if self._state.success_count >= self.config.success_threshold:
                    logger.info(f"Circuit {self.name}: HALF_OPEN -> CLOSED (service recovered)")
                    self._state.state = CircuitState.CLOSED
                    self._state.failure_count = 0
                    self._state.half_open_calls = 0  # Reset for next open cycle
                    self._state.success_count = 0  # Reset for next open cycle
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
                logger.warning(f"Circuit {self.name}: CLOSED -> OPEN ({self._state.failure_count} failures)")
                self._state.state = CircuitState.OPEN

    async def record_failure_async(self, error: Optional[Exception] = None) -> None:
        """Record a failed request (thread-safe for async)."""
        async with self._get_lock():
            self._state.failure_count += 1
            self._state.last_failure_time = time.time()

            if self._state.state == CircuitState.HALF_OPEN:
                logger.warning(f"Circuit {self.name}: HALF_OPEN -> OPEN (service still failing)")
                self._state.state = CircuitState.OPEN
            elif self._state.state == CircuitState.CLOSED:
                if self._state.failure_count >= self.config.failure_threshold:
                    logger.warning(f"Circuit {self.name}: CLOSED -> OPEN ({self._state.failure_count} failures)")
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
                raise CircuitOpenError(breaker.name, breaker.config.timeout_seconds)

            try:
                result = await func(*args, **kwargs)
                await breaker.record_success_async()
                return result
            except Exception as e:
                await breaker.record_failure_async(e)
                raise

        return wrapper

    return decorator


# DynamoDB table for distributed circuit breaker state
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")


class DynamoDBCircuitBreaker:
    """
    Distributed circuit breaker using DynamoDB for state coordination.

    State is shared across all Lambda instances, preventing issues where
    10 instances × 5 failure threshold = 50 failures before all circuits open.

    Schema:
        pk: "circuit#{service_name}"
        sk: "STATE"
        state: "closed" | "open" | "half_open"
        failure_count: N
        success_count: N (for half-open)
        last_failure_at: ISO timestamp
        opened_at: ISO timestamp
        version: N (optimistic locking)
        ttl: epoch (auto-cleanup)

    Design decisions:
    - Optimistic locking via version field prevents race conditions
    - Fail-open strategy when DynamoDB unavailable (allow requests through)
    - 1-second local cache reduces DynamoDB reads
    - Atomic state transitions using conditional updates
    """

    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._local_cache: Optional[dict] = None
        self._cache_time: float = 0
        self._cache_ttl_seconds: float = 1.0  # Local cache TTL
        self._pk = f"circuit#{name}"
        self._sk = "STATE"

    def _get_dynamodb_table(self):
        """Get DynamoDB table with lazy initialization."""
        return boto3.resource("dynamodb").Table(API_KEYS_TABLE)

    def _get_state(self) -> dict:
        """
        Get current circuit state from DynamoDB with local caching.

        Returns default closed state if DynamoDB unavailable (fail-open).
        """
        now = time.time()

        # Return cached state if fresh
        if self._local_cache and (now - self._cache_time) < self._cache_ttl_seconds:
            return self._local_cache

        try:
            table = self._get_dynamodb_table()
            response = table.get_item(
                Key={"pk": self._pk, "sk": self._sk},
                ConsistentRead=False,  # Eventually consistent is fine
            )
            item = response.get("Item")

            if item:
                self._local_cache = item
                self._cache_time = now
                return item

            # No state exists - create initial closed state
            initial_state = self._create_initial_state()
            self._local_cache = initial_state
            self._cache_time = now
            return initial_state

        except ClientError as e:
            logger.warning(f"DynamoDB error reading circuit state for {self.name}: {e}")
            # Fail-open: return closed state to allow requests
            return self._get_default_state()

    def _get_default_state(self) -> dict:
        """Get default closed state for fail-open behavior."""
        return {
            "state": CircuitState.CLOSED.value,
            "failure_count": 0,
            "success_count": 0,
            "version": 0,
        }

    def _create_initial_state(self) -> dict:
        """Create initial circuit state in DynamoDB."""
        now = datetime.now(timezone.utc)
        ttl = int(now.timestamp()) + 86400  # 24 hour TTL

        initial = {
            "pk": self._pk,
            "sk": self._sk,
            "state": CircuitState.CLOSED.value,
            "failure_count": 0,
            "success_count": 0,
            "version": 1,
            "created_at": now.isoformat(),
            "ttl": ttl,
        }

        try:
            table = self._get_dynamodb_table()
            table.put_item(
                Item=initial,
                ConditionExpression="attribute_not_exists(pk)",
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                logger.warning(f"Failed to create initial circuit state: {e}")
            # If condition failed, state already exists - that's fine

        return initial

    def _should_attempt_reset(self, state: dict) -> bool:
        """Check if enough time has passed to attempt reset from OPEN."""
        opened_at = state.get("opened_at")
        if not opened_at:
            return True

        try:
            opened_dt = datetime.fromisoformat(opened_at.replace("Z", "+00:00"))
            elapsed = (datetime.now(timezone.utc) - opened_dt).total_seconds()
            return elapsed >= self.config.timeout_seconds
        except (ValueError, TypeError):
            return True

    def _transition_to_half_open(self, state: dict) -> bool:
        """Attempt atomic transition from OPEN to HALF_OPEN."""
        try:
            table = self._get_dynamodb_table()
            now = datetime.now(timezone.utc)
            version = state.get("version", 0)

            table.update_item(
                Key={"pk": self._pk, "sk": self._sk},
                UpdateExpression=(
                    "SET #state = :half_open, "
                    "success_count = :zero, "
                    "half_open_at = :now, "
                    "version = version + :one, "
                    "#ttl = :ttl"
                ),
                ExpressionAttributeNames={
                    "#state": "state",
                    "#ttl": "ttl",
                },
                ExpressionAttributeValues={
                    ":half_open": CircuitState.HALF_OPEN.value,
                    ":zero": 0,
                    ":now": now.isoformat(),
                    ":one": 1,
                    ":ttl": int(now.timestamp()) + 86400,
                    ":version": version,
                    ":open": CircuitState.OPEN.value,
                },
                ConditionExpression="version = :version AND #state = :open",
            )

            # Invalidate cache
            self._local_cache = None
            logger.info(f"Circuit {self.name}: OPEN -> HALF_OPEN")
            return True

        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # Race condition - another instance transitioned first
                self._local_cache = None
                return self.can_execute()  # Re-check state
            logger.warning(f"Failed to transition to half-open: {e}")
            return True  # Fail-open

    def can_execute(self) -> bool:
        """
        Check if a request should be allowed.

        Thread-safe through DynamoDB conditional updates.
        Returns True on DynamoDB errors (fail-open strategy).
        """
        state = self._get_state()
        current_state = state.get("state", CircuitState.CLOSED.value)

        if current_state == CircuitState.CLOSED.value:
            return True

        if current_state == CircuitState.OPEN.value:
            if self._should_attempt_reset(state):
                return self._transition_to_half_open(state)
            return False

        # HALF_OPEN: Allow limited requests
        half_open_calls = state.get("half_open_calls", 0)
        if half_open_calls < self.config.half_open_max_calls:
            # Atomically increment half_open_calls
            self._increment_half_open_calls(state)
            return True

        # Half-open calls exhausted - check if enough time has passed to retry
        # This prevents the circuit from being stuck forever when all probes failed
        # but record_failure wasn't called (e.g., circuit check itself prevented the call)
        if self._should_reset_half_open_calls(state):
            self._reset_half_open_calls(state)
            return True

        return False

    async def can_execute_async(self) -> bool:
        """
        Async version of can_execute.

        Uses asyncio.to_thread() to run sync boto3 calls without blocking
        the event loop.
        """
        return await asyncio.to_thread(self.can_execute)

    def _increment_half_open_calls(self, state: dict) -> None:
        """Atomically increment half_open_calls counter."""
        try:
            table = self._get_dynamodb_table()
            version = state.get("version", 0)

            table.update_item(
                Key={"pk": self._pk, "sk": self._sk},
                UpdateExpression="SET half_open_calls = if_not_exists(half_open_calls, :zero) + :one",
                ExpressionAttributeValues={
                    ":zero": 0,
                    ":one": 1,
                    ":version": version,
                },
                ConditionExpression="version = :version",
            )
            self._local_cache = None
        except ClientError:
            pass  # Ignore - we already allowed the request

    def _should_reset_half_open_calls(self, state: dict) -> bool:
        """
        Check if enough time has passed to reset half_open_calls.

        This prevents circuits from being stuck forever when half_open_calls
        exceeds the limit but failures weren't recorded (e.g., when the circuit
        check itself blocks the request before it's made).
        """
        half_open_at = state.get("half_open_at")
        if not half_open_at:
            return True

        try:
            half_open_dt = datetime.fromisoformat(half_open_at.replace("Z", "+00:00"))
            elapsed = (datetime.now(timezone.utc) - half_open_dt).total_seconds()
            # Reset after timeout period has passed
            return elapsed >= self.config.timeout_seconds
        except (ValueError, TypeError):
            return True

    def _reset_half_open_calls(self, state: dict) -> None:
        """Reset half_open_calls counter to allow new probe requests."""
        try:
            table = self._get_dynamodb_table()
            now = datetime.now(timezone.utc)
            version = state.get("version", 0)

            table.update_item(
                Key={"pk": self._pk, "sk": self._sk},
                UpdateExpression=("SET half_open_calls = :one, half_open_at = :now, version = version + :inc"),
                ExpressionAttributeValues={
                    ":one": 1,  # Set to 1 since we're allowing this request
                    ":now": now.isoformat(),
                    ":inc": 1,
                    ":version": version,
                },
                ConditionExpression="version = :version",
            )
            logger.info(f"Circuit {self.name}: Reset half_open_calls (timeout elapsed)")
            self._local_cache = None
        except ClientError:
            pass  # Ignore - we'll try again next time

    def record_success(self) -> None:
        """Record a successful request."""
        state = self._get_state()
        current_state = state.get("state", CircuitState.CLOSED.value)

        if current_state == CircuitState.HALF_OPEN.value:
            self._record_half_open_success(state)
        elif current_state == CircuitState.CLOSED.value:
            self._reset_failure_count(state)

    async def record_success_async(self) -> None:
        """
        Async version of record_success.

        Uses asyncio.to_thread() to run sync boto3 calls without blocking
        the event loop.
        """
        await asyncio.to_thread(self.record_success)

    def _record_half_open_success(self, state: dict) -> None:
        """
        Record success in half-open state, potentially closing circuit.

        Uses atomic increment with ReturnValues to get actual new count,
        avoiding race conditions from stale cached state.
        """
        try:
            table = self._get_dynamodb_table()
            now = datetime.now(timezone.utc)

            # Atomically increment success_count and get the new value
            # This avoids race condition where multiple instances read stale state
            response = table.update_item(
                Key={"pk": self._pk, "sk": self._sk},
                UpdateExpression=("SET success_count = if_not_exists(success_count, :zero) + :one"),
                ExpressionAttributeValues={
                    ":zero": 0,
                    ":one": 1,
                },
                ReturnValues="UPDATED_NEW",
            )

            # Get actual new success count from DynamoDB response
            new_success_count = response.get("Attributes", {}).get("success_count", 1)

            if new_success_count >= self.config.success_threshold:
                # Transition to CLOSED - use conditional to ensure only one instance does this
                try:
                    table.update_item(
                        Key={"pk": self._pk, "sk": self._sk},
                        UpdateExpression=(
                            "SET #state = :closed, "
                            "failure_count = :zero, "
                            "success_count = :zero, "
                            "half_open_calls = :zero, "
                            "closed_at = :now, "
                            "version = version + :one, "
                            "#ttl = :ttl"
                        ),
                        ExpressionAttributeNames={
                            "#state": "state",
                            "#ttl": "ttl",
                        },
                        ExpressionAttributeValues={
                            ":closed": CircuitState.CLOSED.value,
                            ":zero": 0,
                            ":now": now.isoformat(),
                            ":one": 1,
                            ":ttl": int(now.timestamp()) + 86400,
                            ":half_open": CircuitState.HALF_OPEN.value,
                        },
                        # Only transition if still in half_open state
                        ConditionExpression="#state = :half_open",
                    )
                    logger.info(f"Circuit {self.name}: HALF_OPEN -> CLOSED (recovered)")
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                        # Another instance already transitioned - that's fine
                        pass
                    else:
                        raise

            self._local_cache = None

        except ClientError as e:
            logger.warning(f"Failed to record success: {e}")

    def _reset_failure_count(self, state: dict) -> None:
        """Reset failure count on success in closed state."""
        if state.get("failure_count", 0) > 0:
            try:
                table = self._get_dynamodb_table()
                table.update_item(
                    Key={"pk": self._pk, "sk": self._sk},
                    UpdateExpression="SET failure_count = :zero",
                    ExpressionAttributeValues={":zero": 0},
                )
                self._local_cache = None
            except ClientError:
                pass  # Non-critical

    def record_failure(self, error: Optional[Exception] = None) -> None:
        """Record a failed request."""
        state = self._get_state()
        current_state = state.get("state", CircuitState.CLOSED.value)

        if current_state == CircuitState.HALF_OPEN.value:
            self._transition_to_open_from_half_open(state)
        elif current_state == CircuitState.CLOSED.value:
            self._record_closed_failure(state)

    async def record_failure_async(self, error: Optional[Exception] = None) -> None:
        """
        Async version of record_failure.

        Uses asyncio.to_thread() to run sync boto3 calls without blocking
        the event loop.
        """
        await asyncio.to_thread(self.record_failure, error)

    def _transition_to_open_from_half_open(self, state: dict) -> None:
        """Transition from HALF_OPEN back to OPEN on failure."""
        try:
            table = self._get_dynamodb_table()
            now = datetime.now(timezone.utc)
            version = state.get("version", 0)

            table.update_item(
                Key={"pk": self._pk, "sk": self._sk},
                UpdateExpression=(
                    "SET #state = :open, "
                    "opened_at = :now, "
                    "last_failure_at = :now, "
                    "version = version + :one, "
                    "#ttl = :ttl"
                ),
                ExpressionAttributeNames={
                    "#state": "state",
                    "#ttl": "ttl",
                },
                ExpressionAttributeValues={
                    ":open": CircuitState.OPEN.value,
                    ":now": now.isoformat(),
                    ":one": 1,
                    ":ttl": int(now.timestamp()) + 86400,
                    ":version": version,
                },
                ConditionExpression="version = :version",
            )
            logger.warning(f"Circuit {self.name}: HALF_OPEN -> OPEN (still failing)")
            self._local_cache = None

        except ClientError as e:
            logger.warning(f"Failed to transition to open: {e}")

    def _record_closed_failure(self, state: dict) -> None:
        """Record failure in closed state, potentially opening circuit."""
        try:
            table = self._get_dynamodb_table()
            now = datetime.now(timezone.utc)
            version = state.get("version", 0)
            new_failure_count = state.get("failure_count", 0) + 1

            if new_failure_count >= self.config.failure_threshold:
                # Transition to OPEN
                table.update_item(
                    Key={"pk": self._pk, "sk": self._sk},
                    UpdateExpression=(
                        "SET #state = :open, "
                        "failure_count = :count, "
                        "opened_at = :now, "
                        "last_failure_at = :now, "
                        "version = version + :one, "
                        "#ttl = :ttl"
                    ),
                    ExpressionAttributeNames={
                        "#state": "state",
                        "#ttl": "ttl",
                    },
                    ExpressionAttributeValues={
                        ":open": CircuitState.OPEN.value,
                        ":count": new_failure_count,
                        ":now": now.isoformat(),
                        ":one": 1,
                        ":ttl": int(now.timestamp()) + 86400,
                        ":version": version,
                    },
                    ConditionExpression="version = :version",
                )
                logger.warning(f"Circuit {self.name}: CLOSED -> OPEN ({new_failure_count} failures)")
            else:
                # Just increment failure count
                table.update_item(
                    Key={"pk": self._pk, "sk": self._sk},
                    UpdateExpression=("SET failure_count = failure_count + :one, last_failure_at = :now"),
                    ExpressionAttributeValues={
                        ":one": 1,
                        ":now": now.isoformat(),
                    },
                )

            self._local_cache = None

        except ClientError as e:
            logger.warning(f"Failed to record failure: {e}")


# Flag to enable distributed circuit breaker (set via environment variable)
USE_DISTRIBUTED_CIRCUIT_BREAKER = os.environ.get("USE_DISTRIBUTED_CIRCUIT_BREAKER", "false").lower() == "true"


def _create_circuit_breaker(name: str, config: CircuitBreakerConfig):
    """Factory to create circuit breaker based on configuration."""
    if USE_DISTRIBUTED_CIRCUIT_BREAKER:
        return DynamoDBCircuitBreaker(name, config)
    return InMemoryCircuitBreaker(name, config)


# Pre-configured circuit breakers for external services
GITHUB_CIRCUIT = _create_circuit_breaker(
    "github",
    CircuitBreakerConfig(
        failure_threshold=5,
        timeout_seconds=120,
        success_threshold=2,
    ),
)

DEPSDEV_CIRCUIT = _create_circuit_breaker(
    "deps.dev",
    CircuitBreakerConfig(
        failure_threshold=10,
        timeout_seconds=60,
        success_threshold=3,
    ),
)

NPM_CIRCUIT = _create_circuit_breaker(
    "npm",
    CircuitBreakerConfig(
        failure_threshold=10,
        timeout_seconds=60,
        success_threshold=3,
    ),
)

# npm downloads API is separate from the npm registry
# Needs independent circuit breaker to prevent downloads outages from blocking npm metadata
NPM_DOWNLOADS_CIRCUIT = _create_circuit_breaker(
    "npm_downloads",
    CircuitBreakerConfig(
        failure_threshold=5,
        timeout_seconds=120,
        success_threshold=2,
    ),
)

BUNDLEPHOBIA_CIRCUIT = _create_circuit_breaker(
    "bundlephobia",
    CircuitBreakerConfig(
        failure_threshold=5,
        timeout_seconds=120,
        success_threshold=2,
    ),
)

PYPI_CIRCUIT = _create_circuit_breaker(
    "pypi",
    CircuitBreakerConfig(
        failure_threshold=10,
        timeout_seconds=60,
        success_threshold=3,
    ),
)

# pypistats.org is a separate third-party service from PyPI registry
# Needs independent circuit breaker to prevent pypistats outages from blocking PyPI metadata
PYPISTATS_CIRCUIT = _create_circuit_breaker(
    "pypistats",
    CircuitBreakerConfig(
        failure_threshold=5,  # Conservative - undocumented rate limits
        timeout_seconds=120,  # Give time to recover
        success_threshold=2,  # Quick recovery once healthy
    ),
)

OPENSSF_CIRCUIT = _create_circuit_breaker(
    "openssf",
    CircuitBreakerConfig(
        failure_threshold=5,
        timeout_seconds=120,
        half_open_max_calls=3,
        success_threshold=2,
    ),
)

# DynamoDB circuit breaker - for protecting against throttling cascades
# Wired to auth.py functions (validate_api_key, check_and_increment_usage, etc.)
# to prevent cascade failures during throttling events or capacity issues.
# Uses fail-open strategy for usage tracking to avoid total service outage.
# Note: Always use in-memory for DynamoDB circuit to avoid recursive dependency
DYNAMODB_CIRCUIT = InMemoryCircuitBreaker(
    "dynamodb",
    CircuitBreakerConfig(
        failure_threshold=3,  # DynamoDB failures are serious
        timeout_seconds=30,  # Short timeout - DynamoDB recovers quickly
        success_threshold=2,
        half_open_max_calls=2,
    ),
)
