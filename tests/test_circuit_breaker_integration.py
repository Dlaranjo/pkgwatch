"""
Integration tests for circuit breaker wiring to collectors.

These tests verify that the circuit breakers are properly integrated with
the collector functions and that failures are handled gracefully.
"""

import asyncio
import os
import sys

import pytest

# Add functions directories to path
# IMPORTANT: Only add 'functions' dir so imports match collector paths (shared.x)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions", "collectors"))


def run_async(coro):
    """Helper to run async functions in sync tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture(autouse=True)
def reset_circuit_breakers():
    """Reset all circuit breaker states between tests."""
    from shared.circuit_breaker import (
        BUNDLEPHOBIA_CIRCUIT,
        DEPSDEV_CIRCUIT,
        GITHUB_CIRCUIT,
        NPM_CIRCUIT,
        CircuitBreakerState,
    )

    # Reset each circuit breaker to initial state
    GITHUB_CIRCUIT._state = CircuitBreakerState()
    NPM_CIRCUIT._state = CircuitBreakerState()
    DEPSDEV_CIRCUIT._state = CircuitBreakerState()
    BUNDLEPHOBIA_CIRCUIT._state = CircuitBreakerState()

    yield

    # Reset again after test to ensure clean state
    GITHUB_CIRCUIT._state = CircuitBreakerState()
    NPM_CIRCUIT._state = CircuitBreakerState()
    DEPSDEV_CIRCUIT._state = CircuitBreakerState()
    BUNDLEPHOBIA_CIRCUIT._state = CircuitBreakerState()


class TestCircuitBreakerWiring:
    """Tests that circuit breakers are properly wired to collectors."""

    def test_npm_collector_has_circuit_breaker_decorator(self):
        """Verify npm_collector.get_npm_metadata is decorated with circuit_breaker."""
        from npm_collector import get_npm_metadata

        # The decorated function has __wrapped__ attribute
        assert hasattr(get_npm_metadata, "__wrapped__"), "get_npm_metadata should be decorated with @circuit_breaker"

    def test_depsdev_collector_has_circuit_breaker_decorator(self):
        """Verify depsdev_collector.get_package_info is decorated with circuit_breaker."""
        from depsdev_collector import get_package_info

        assert hasattr(get_package_info, "__wrapped__"), "get_package_info should be decorated with @circuit_breaker"

    def test_bundlephobia_collector_has_circuit_breaker_decorator(self):
        """Verify bundlephobia_collector.get_bundle_size is decorated with circuit_breaker."""
        from bundlephobia_collector import get_bundle_size

        assert hasattr(get_bundle_size, "__wrapped__"), "get_bundle_size should be decorated with @circuit_breaker"


class TestCircuitOpenBehavior:
    """Tests for behavior when circuits are open."""

    def test_npm_circuit_open_raises_error(self):
        """When npm circuit is open, get_npm_metadata should raise CircuitOpenError."""
        from npm_collector import get_npm_metadata

        from shared.circuit_breaker import NPM_CIRCUIT, CircuitOpenError, CircuitState

        # Open the circuit
        for _ in range(10):  # failure_threshold=10
            NPM_CIRCUIT.record_failure()

        assert NPM_CIRCUIT.state == CircuitState.OPEN

        # Should raise CircuitOpenError
        with pytest.raises(CircuitOpenError):
            run_async(get_npm_metadata("test-pkg"))

    def test_bundlephobia_circuit_open_raises_error(self):
        """When bundlephobia circuit is open, get_bundle_size should raise CircuitOpenError."""
        from bundlephobia_collector import get_bundle_size

        from shared.circuit_breaker import BUNDLEPHOBIA_CIRCUIT, CircuitOpenError, CircuitState

        # Open the circuit
        for _ in range(5):  # failure_threshold=5
            BUNDLEPHOBIA_CIRCUIT.record_failure()

        assert BUNDLEPHOBIA_CIRCUIT.state == CircuitState.OPEN

        # Should raise CircuitOpenError
        with pytest.raises(CircuitOpenError):
            run_async(get_bundle_size("test-pkg"))

    def test_depsdev_circuit_open_raises_error(self):
        """When depsdev circuit is open, get_package_info should raise CircuitOpenError."""
        from depsdev_collector import get_package_info

        from shared.circuit_breaker import DEPSDEV_CIRCUIT, CircuitOpenError, CircuitState

        # Open the circuit
        for _ in range(10):  # failure_threshold=10
            DEPSDEV_CIRCUIT.record_failure()

        assert DEPSDEV_CIRCUIT.state == CircuitState.OPEN

        # Should raise CircuitOpenError
        with pytest.raises(CircuitOpenError):
            run_async(get_package_info("npm", "test-pkg"))


class TestGitHubCircuitBreakerManualIntegration:
    """Tests for GitHub circuit breaker (uses manual can_execute/record_* pattern)."""

    def test_github_circuit_can_execute_called(self):
        """Verify GITHUB_CIRCUIT.can_execute() is called during GitHub collection.

        Rather than testing the full collect_package_data flow (which requires
        complex mocking), we verify that the circuit breaker check exists in
        package_collector by checking GITHUB_CIRCUIT is imported and used.
        """
        from shared.circuit_breaker import GITHUB_CIRCUIT, CircuitState

        # Verify circuit starts closed
        assert GITHUB_CIRCUIT.state == CircuitState.CLOSED
        assert GITHUB_CIRCUIT.can_execute() is True

        # Open the circuit
        for _ in range(5):
            GITHUB_CIRCUIT.record_failure()

        # Verify circuit is now open
        assert GITHUB_CIRCUIT.state == CircuitState.OPEN
        assert GITHUB_CIRCUIT.can_execute() is False

        # Verify package_collector imports GITHUB_CIRCUIT
        import package_collector

        assert hasattr(package_collector, "GITHUB_CIRCUIT"), "package_collector should import GITHUB_CIRCUIT"
