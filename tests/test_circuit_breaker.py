"""
Tests for circuit breaker implementation.
"""

import asyncio
import time

import pytest

from functions.shared.circuit_breaker import (
    CircuitBreakerConfig,
    CircuitOpenError,
    CircuitState,
    InMemoryCircuitBreaker,
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


def test_get_lock_no_running_loop():
    """_get_lock should handle case where no event loop is running."""
    breaker = InMemoryCircuitBreaker("test-lock")
    # When called outside async context, there is no running loop
    lock = breaker._get_lock()
    assert isinstance(lock, asyncio.Lock)
    # current_loop_id should be None
    assert breaker._lock_loop_id is None


def test_get_lock_recreated_on_loop_change():
    """_get_lock should recreate lock when event loop changes."""
    breaker = InMemoryCircuitBreaker("test-lock-change")

    # First: get lock outside any event loop
    lock1 = breaker._get_lock()
    assert lock1 is not None
    assert breaker._lock_loop_id is None

    # Simulate being in an event loop by setting the loop id
    breaker._lock_loop_id = 12345  # Fake loop id

    # Getting lock again - loop id is still None (no running loop), so it differs from 12345
    lock2 = breaker._get_lock()
    # Lock should be recreated since loop id changed
    assert lock2 is not lock1


@pytest.mark.asyncio
async def test_can_execute_async_half_open_limit():
    """Async can_execute should respect half_open_max_calls."""
    config = CircuitBreakerConfig(
        failure_threshold=2,
        timeout_seconds=0,
        half_open_max_calls=2,
        success_threshold=3,
    )
    breaker = InMemoryCircuitBreaker("test-async-half-open", config)

    # Open the circuit
    breaker.record_failure()
    breaker.record_failure()
    time.sleep(0.1)  # Trigger HALF_OPEN transition

    # Should allow configured number
    assert await breaker.can_execute_async() is True
    assert await breaker.can_execute_async() is True
    # Should block after limit
    assert await breaker.can_execute_async() is False


@pytest.mark.asyncio
async def test_record_success_async_half_open_to_closed():
    """Async record_success should transition HALF_OPEN to CLOSED after threshold."""
    config = CircuitBreakerConfig(
        failure_threshold=1,
        success_threshold=2,
        timeout_seconds=0,
    )
    breaker = InMemoryCircuitBreaker("test-async-success", config)

    # Open then transition to half-open
    breaker.record_failure()
    time.sleep(0.1)
    assert breaker.state == CircuitState.HALF_OPEN

    # Record successes via async method
    await breaker.record_success_async()
    assert breaker._state.state == CircuitState.HALF_OPEN  # Not yet
    await breaker.record_success_async()
    assert breaker._state.state == CircuitState.CLOSED  # Now closed

    # Verify all counters are reset
    assert breaker._state.failure_count == 0
    assert breaker._state.half_open_calls == 0
    assert breaker._state.success_count == 0


@pytest.mark.asyncio
async def test_record_success_async_closed_resets_failures():
    """Async record_success in CLOSED state should reset failure count."""
    config = CircuitBreakerConfig(failure_threshold=5)
    breaker = InMemoryCircuitBreaker("test-async-closed-success", config)

    # Record some failures
    breaker.record_failure()
    breaker.record_failure()
    assert breaker._state.failure_count == 2

    # Success resets failure count
    await breaker.record_success_async()
    assert breaker._state.failure_count == 0


@pytest.mark.asyncio
async def test_record_failure_async_half_open_to_open():
    """Async record_failure in HALF_OPEN state should reopen circuit."""
    config = CircuitBreakerConfig(
        failure_threshold=1,
        timeout_seconds=0,
    )
    breaker = InMemoryCircuitBreaker("test-async-fail-half-open", config)

    # Open then transition to half-open
    breaker.record_failure()
    time.sleep(0.1)
    assert breaker.state == CircuitState.HALF_OPEN

    # Failure in half-open should reopen
    await breaker.record_failure_async()
    assert breaker._state.state == CircuitState.OPEN


@pytest.mark.asyncio
async def test_record_failure_async_closed_to_open():
    """Async record_failure in CLOSED state should open circuit at threshold."""
    config = CircuitBreakerConfig(failure_threshold=2)
    breaker = InMemoryCircuitBreaker("test-async-fail-closed", config)

    # First failure
    await breaker.record_failure_async()
    assert breaker._state.state == CircuitState.CLOSED

    # Second failure reaches threshold
    await breaker.record_failure_async()
    assert breaker._state.state == CircuitState.OPEN


def test_circuit_open_error_attributes():
    """CircuitOpenError should carry circuit_name and retry_after."""
    error = CircuitOpenError("test-circuit", 60)
    assert error.circuit_name == "test-circuit"
    assert error.retry_after == 60
    assert "test-circuit" in str(error)
    assert "60" in str(error)


def test_success_in_open_state_is_noop():
    """Recording success in OPEN state should do nothing."""
    config = CircuitBreakerConfig(failure_threshold=1)
    breaker = InMemoryCircuitBreaker("test-open-success", config)

    # Open the circuit
    breaker.record_failure()
    assert breaker._state.state == CircuitState.OPEN

    # Success in OPEN state should not change state
    breaker.record_success()
    assert breaker._state.state == CircuitState.OPEN


def test_failure_in_open_state_updates_counters():
    """Recording failure in OPEN state should update counters but state stays OPEN."""
    config = CircuitBreakerConfig(failure_threshold=1)
    breaker = InMemoryCircuitBreaker("test-open-failure", config)

    # Open the circuit
    breaker.record_failure()
    assert breaker._state.state == CircuitState.OPEN
    assert breaker._state.failure_count == 1

    # Another failure - state stays OPEN, count increments
    breaker.record_failure()
    assert breaker._state.state == CircuitState.OPEN
    assert breaker._state.failure_count == 2


def test_check_timeout_transition_no_failure_time():
    """OPEN state with no last_failure_time should not transition."""
    config = CircuitBreakerConfig(failure_threshold=1, timeout_seconds=0)
    breaker = InMemoryCircuitBreaker("test-no-failure-time", config)

    # Manually set to OPEN without failure time
    breaker._state.state = CircuitState.OPEN
    breaker._state.last_failure_time = None

    # Should stay OPEN since there's no failure time to check against
    result = breaker._check_timeout_transition()
    assert result == CircuitState.OPEN


def test_full_lifecycle_closed_open_halfopen_closed():
    """Test the complete circuit breaker lifecycle."""
    config = CircuitBreakerConfig(
        failure_threshold=2,
        success_threshold=2,
        timeout_seconds=0.1,
        half_open_max_calls=3,
    )
    breaker = InMemoryCircuitBreaker("lifecycle", config)

    # 1. Start CLOSED
    assert breaker.state == CircuitState.CLOSED
    assert breaker.can_execute() is True

    # 2. Failures open the circuit
    breaker.record_failure()
    breaker.record_failure()
    assert breaker._state.state == CircuitState.OPEN

    # 3. After timeout, transitions to HALF_OPEN
    time.sleep(0.15)
    assert breaker.state == CircuitState.HALF_OPEN

    # 4. Allow limited requests in HALF_OPEN
    assert breaker.can_execute() is True  # Call 1
    breaker.record_success()
    assert breaker.can_execute() is True  # Call 2
    breaker.record_success()

    # 5. After success_threshold successes, back to CLOSED
    assert breaker.state == CircuitState.CLOSED
    assert breaker._state.failure_count == 0


# =============================================================================
# ADDITIONAL CIRCUIT BREAKER TESTS
# =============================================================================


def test_record_failure_with_error_object():
    """record_failure should accept an error object."""
    config = CircuitBreakerConfig(failure_threshold=5)
    breaker = InMemoryCircuitBreaker("test-with-error", config)

    error = ValueError("test error")
    breaker.record_failure(error=error)
    assert breaker._state.failure_count == 1


def test_multiple_open_close_cycles():
    """Circuit should handle multiple open/close cycles correctly."""
    config = CircuitBreakerConfig(
        failure_threshold=2,
        success_threshold=1,
        timeout_seconds=0.05,
    )
    breaker = InMemoryCircuitBreaker("multi-cycle", config)

    for cycle in range(3):
        # Open the circuit
        breaker.record_failure()
        breaker.record_failure()
        assert breaker._state.state == CircuitState.OPEN

        # Wait for half-open
        time.sleep(0.1)
        assert breaker.state == CircuitState.HALF_OPEN

        # Close with success
        breaker.can_execute()
        breaker.record_success()
        assert breaker.state == CircuitState.CLOSED
        assert breaker._state.failure_count == 0


def test_closed_state_check_timeout_is_noop():
    """_check_timeout_transition should be a no-op in CLOSED state."""
    breaker = InMemoryCircuitBreaker("closed-timeout")
    # In CLOSED state, check_timeout should just return CLOSED
    result = breaker._check_timeout_transition()
    assert result == CircuitState.CLOSED


def test_half_open_state_check_timeout_is_noop():
    """_check_timeout_transition should be a no-op in HALF_OPEN state."""
    config = CircuitBreakerConfig(failure_threshold=1, timeout_seconds=0)
    breaker = InMemoryCircuitBreaker("ho-timeout", config)

    # Manually set to HALF_OPEN
    breaker._state.state = CircuitState.HALF_OPEN

    result = breaker._check_timeout_transition()
    assert result == CircuitState.HALF_OPEN


@pytest.mark.asyncio
async def test_can_execute_async_open_state():
    """Async can_execute should return False when circuit is OPEN."""
    config = CircuitBreakerConfig(failure_threshold=1, timeout_seconds=60)
    breaker = InMemoryCircuitBreaker("async-open", config)

    breaker.record_failure()
    assert breaker._state.state == CircuitState.OPEN

    result = await breaker.can_execute_async()
    assert result is False


@pytest.mark.asyncio
async def test_can_execute_async_closed_state():
    """Async can_execute should return True when circuit is CLOSED."""
    breaker = InMemoryCircuitBreaker("async-closed")
    result = await breaker.can_execute_async()
    assert result is True


@pytest.mark.asyncio
async def test_record_success_async_open_state_noop():
    """Async record_success in OPEN state should be a no-op."""
    config = CircuitBreakerConfig(failure_threshold=1)
    breaker = InMemoryCircuitBreaker("async-open-success", config)

    breaker.record_failure()
    assert breaker._state.state == CircuitState.OPEN

    await breaker.record_success_async()
    # Should still be OPEN
    assert breaker._state.state == CircuitState.OPEN


@pytest.mark.asyncio
async def test_record_failure_async_open_state():
    """Async record_failure in OPEN state should still update counters."""
    config = CircuitBreakerConfig(failure_threshold=1)
    breaker = InMemoryCircuitBreaker("async-open-fail", config)

    breaker.record_failure()
    assert breaker._state.state == CircuitState.OPEN
    assert breaker._state.failure_count == 1

    await breaker.record_failure_async()
    assert breaker._state.state == CircuitState.OPEN
    assert breaker._state.failure_count == 2


def test_pre_configured_circuit_breakers():
    """Verify pre-configured circuit breakers exist with correct names."""
    from functions.shared.circuit_breaker import (
        BUNDLEPHOBIA_CIRCUIT,
        DEPSDEV_CIRCUIT,
        DYNAMODB_CIRCUIT,
        GITHUB_CIRCUIT,
        NPM_CIRCUIT,
        OPENSSF_CIRCUIT,
        PYPI_CIRCUIT,
        PYPISTATS_CIRCUIT,
    )

    assert GITHUB_CIRCUIT.name == "github"
    assert DEPSDEV_CIRCUIT.name == "deps.dev"
    assert NPM_CIRCUIT.name == "npm"
    assert BUNDLEPHOBIA_CIRCUIT.name == "bundlephobia"
    assert PYPI_CIRCUIT.name == "pypi"
    assert PYPISTATS_CIRCUIT.name == "pypistats"
    assert OPENSSF_CIRCUIT.name == "openssf"
    assert DYNAMODB_CIRCUIT.name == "dynamodb"

    # DYNAMODB_CIRCUIT should always be InMemoryCircuitBreaker
    assert isinstance(DYNAMODB_CIRCUIT, InMemoryCircuitBreaker)


def test_circuit_breaker_config_defaults():
    """Default config values should be sensible."""
    config = CircuitBreakerConfig()
    assert config.failure_threshold == 5
    assert config.success_threshold == 2
    assert config.timeout_seconds == 60
    assert config.half_open_max_calls == 3


@pytest.mark.asyncio
async def test_circuit_breaker_decorator_records_success():
    """Decorator should record success after successful function call."""
    config = CircuitBreakerConfig(failure_threshold=5)
    test_breaker = InMemoryCircuitBreaker("test-decorator-success", config)

    # Record some failures first
    test_breaker.record_failure()
    test_breaker.record_failure()
    assert test_breaker._state.failure_count == 2

    @circuit_breaker(test_breaker)
    async def test_func():
        return "ok"

    result = await test_func()
    assert result == "ok"
    # Success should reset failure count
    assert test_breaker._state.failure_count == 0
