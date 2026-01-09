"""
Tests for circuit breaker implementation.
"""

import asyncio
import time
import pytest

from functions.shared.circuit_breaker import (
    InMemoryCircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    CircuitOpenError,
    circuit_breaker,
)


def test_circuit_breaker_starts_closed():
    """Circuit breaker should start in CLOSED state."""
    breaker = InMemoryCircuitBreaker("test")
    assert breaker.state == CircuitState.CLOSED
    assert breaker.can_execute() is True


def test_circuit_opens_after_threshold_failures():
    """Circuit should open after reaching failure threshold."""
    config = CircuitBreakerConfig(failure_threshold=3)
    breaker = InMemoryCircuitBreaker("test", config)

    # Record failures
    for i in range(3):
        breaker.record_failure()

    assert breaker.state == CircuitState.OPEN
    assert breaker.can_execute() is False


def test_circuit_closes_after_success_in_half_open():
    """Circuit should close after enough successes in HALF_OPEN state."""
    config = CircuitBreakerConfig(
        failure_threshold=2,
        success_threshold=2,
        timeout_seconds=0.1,  # Very short timeout
    )
    breaker = InMemoryCircuitBreaker("test", config)

    # Open the circuit
    breaker.record_failure()
    breaker.record_failure()
    assert breaker._state.state == CircuitState.OPEN

    # Wait for timeout to transition to HALF_OPEN
    time.sleep(0.15)
    assert breaker.state == CircuitState.HALF_OPEN

    # Record successes
    breaker.can_execute()  # First attempt
    breaker.record_success()
    breaker.can_execute()  # Second attempt
    breaker.record_success()

    assert breaker.state == CircuitState.CLOSED


def test_circuit_returns_to_open_on_failure_in_half_open():
    """Circuit should return to OPEN if failure occurs in HALF_OPEN state."""
    config = CircuitBreakerConfig(
        failure_threshold=2,
        timeout_seconds=0.1,
    )
    breaker = InMemoryCircuitBreaker("test", config)

    # Open the circuit
    breaker.record_failure()
    breaker.record_failure()
    assert breaker._state.state == CircuitState.OPEN

    # Wait for timeout
    time.sleep(0.15)
    assert breaker.state == CircuitState.HALF_OPEN

    # Failure in HALF_OPEN
    breaker.record_failure()
    assert breaker.state == CircuitState.OPEN


def test_circuit_resets_failure_count_on_success():
    """Failure count should reset on success in CLOSED state."""
    config = CircuitBreakerConfig(failure_threshold=3)
    breaker = InMemoryCircuitBreaker("test", config)

    # Record some failures
    breaker.record_failure()
    breaker.record_failure()
    assert breaker._state.failure_count == 2
    assert breaker.state == CircuitState.CLOSED

    # Success resets counter
    breaker.record_success()
    assert breaker._state.failure_count == 0


def test_half_open_allows_limited_requests():
    """HALF_OPEN state should allow limited number of requests."""
    config = CircuitBreakerConfig(
        failure_threshold=2,
        timeout_seconds=0,
        half_open_max_calls=2,
    )
    breaker = InMemoryCircuitBreaker("test", config)

    # Open the circuit
    breaker.record_failure()
    breaker.record_failure()
    time.sleep(0.1)  # Transition to HALF_OPEN

    # Should allow configured number of requests
    assert breaker.can_execute() is True
    assert breaker.can_execute() is True
    assert breaker.can_execute() is False  # Limit reached


@pytest.mark.asyncio
async def test_circuit_breaker_decorator_success():
    """Decorator should allow requests when circuit is closed."""
    test_breaker = InMemoryCircuitBreaker("test")

    @circuit_breaker(test_breaker)
    async def test_func():
        return "success"

    result = await test_func()
    assert result == "success"
    assert test_breaker.state == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_circuit_breaker_decorator_failure():
    """Decorator should record failures and open circuit."""
    config = CircuitBreakerConfig(failure_threshold=2)
    test_breaker = InMemoryCircuitBreaker("test", config)

    @circuit_breaker(test_breaker)
    async def test_func():
        raise ValueError("test error")

    # First failure
    with pytest.raises(ValueError):
        await test_func()

    # Second failure - should open circuit
    with pytest.raises(ValueError):
        await test_func()

    assert test_breaker.state == CircuitState.OPEN

    # Third attempt - should raise CircuitOpenError
    with pytest.raises(CircuitOpenError) as exc_info:
        await test_func()

    assert "test" in str(exc_info.value)


@pytest.mark.asyncio
async def test_circuit_breaker_decorator_blocks_when_open():
    """Decorator should raise CircuitOpenError when circuit is open."""
    config = CircuitBreakerConfig(failure_threshold=1)
    test_breaker = InMemoryCircuitBreaker("test", config)

    @circuit_breaker(test_breaker)
    async def test_func():
        raise ValueError("test error")

    # Open the circuit
    with pytest.raises(ValueError):
        await test_func()

    assert test_breaker.state == CircuitState.OPEN

    # Should block subsequent requests
    with pytest.raises(CircuitOpenError):
        await test_func()


def test_circuit_timeout_transitions_to_half_open():
    """Circuit should transition from OPEN to HALF_OPEN after timeout."""
    config = CircuitBreakerConfig(
        failure_threshold=1,
        timeout_seconds=1,  # 1 second timeout
    )
    breaker = InMemoryCircuitBreaker("test", config)

    # Open the circuit
    breaker.record_failure()
    assert breaker.state == CircuitState.OPEN

    # Should remain open before timeout
    time.sleep(0.5)
    assert breaker.state == CircuitState.OPEN

    # Should transition to HALF_OPEN after timeout
    time.sleep(0.6)  # Total > 1 second
    assert breaker.state == CircuitState.HALF_OPEN
