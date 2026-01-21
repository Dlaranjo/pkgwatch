"""
Tests for DynamoDB-backed distributed circuit breaker.
"""

import os
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

# Set up environment before importing
os.environ.setdefault("API_KEYS_TABLE", "pkgwatch-api-keys")
os.environ.setdefault("USE_DISTRIBUTED_CIRCUIT_BREAKER", "false")

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../functions/shared"))

from circuit_breaker import (
    DynamoDBCircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
)


class TestDynamoDBCircuitBreaker:
    """Tests for DynamoDB-backed distributed circuit breaker."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = CircuitBreakerConfig(
            failure_threshold=3,
            timeout_seconds=60,
            success_threshold=2,
            half_open_max_calls=3,
        )
        self.circuit = DynamoDBCircuitBreaker("test-service", self.config)

    def test_init(self):
        """Test circuit breaker initialization."""
        assert self.circuit.name == "test-service"
        assert self.circuit.config.failure_threshold == 3
        assert self.circuit._pk == "circuit#test-service"
        assert self.circuit._sk == "STATE"

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_get_state_creates_initial_state(self, mock_get_table):
        """Test that initial state is created if none exists."""
        mock_table = MagicMock()
        mock_table.get_item.return_value = {}  # No item
        mock_get_table.return_value = mock_table

        state = self.circuit._get_state()

        # Should create initial state
        assert state["state"] == CircuitState.CLOSED.value
        assert state["failure_count"] == 0
        mock_table.put_item.assert_called_once()

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_get_state_returns_cached(self, mock_get_table):
        """Test that cached state is returned within TTL."""
        mock_table = MagicMock()
        mock_get_table.return_value = mock_table

        # Prime the cache
        self.circuit._local_cache = {
            "state": CircuitState.CLOSED.value,
            "failure_count": 1,
        }
        self.circuit._cache_time = datetime.now(timezone.utc).timestamp()

        state = self.circuit._get_state()

        # Should return cached value without hitting DynamoDB
        mock_table.get_item.assert_not_called()
        assert state["failure_count"] == 1

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_get_state_fails_open(self, mock_get_table):
        """Test fail-open behavior when DynamoDB is unavailable."""
        mock_table = MagicMock()
        mock_table.get_item.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable"}},
            "GetItem"
        )
        mock_get_table.return_value = mock_table

        # Clear cache to force DynamoDB call
        self.circuit._local_cache = None
        state = self.circuit._get_state()

        # Should return closed state (fail-open)
        assert state["state"] == CircuitState.CLOSED.value

    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_can_execute_closed_allows(self, mock_get_state):
        """Test that closed circuit allows execution."""
        mock_get_state.return_value = {
            "state": CircuitState.CLOSED.value,
            "failure_count": 0,
        }

        result = self.circuit.can_execute()

        assert result is True

    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_can_execute_open_blocks(self, mock_get_state):
        """Test that open circuit blocks execution."""
        now = datetime.now(timezone.utc)
        mock_get_state.return_value = {
            "state": CircuitState.OPEN.value,
            "opened_at": now.isoformat(),  # Just opened
        }

        result = self.circuit.can_execute()

        assert result is False

    @patch.object(DynamoDBCircuitBreaker, "_transition_to_half_open")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_can_execute_open_transitions_after_timeout(self, mock_get_state, mock_transition):
        """Test that open circuit transitions to half-open after timeout."""
        opened_time = datetime.now(timezone.utc) - timedelta(seconds=120)
        mock_get_state.return_value = {
            "state": CircuitState.OPEN.value,
            "opened_at": opened_time.isoformat(),
            "version": 1,
        }
        mock_transition.return_value = True

        result = self.circuit.can_execute()

        assert result is True
        mock_transition.assert_called_once()

    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_can_execute_half_open_allows_limited(self, mock_get_state):
        """Test that half-open circuit allows limited calls."""
        mock_get_state.return_value = {
            "state": CircuitState.HALF_OPEN.value,
            "half_open_calls": 0,
            "version": 1,
        }

        # Mock the increment method to avoid DynamoDB calls
        with patch.object(self.circuit, "_increment_half_open_calls"):
            result = self.circuit.can_execute()

        assert result is True

    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_can_execute_half_open_blocks_excess(self, mock_get_state):
        """Test that half-open circuit blocks after max calls when timeout hasn't passed."""
        # Set half_open_at to now, so timeout hasn't passed yet
        mock_get_state.return_value = {
            "state": CircuitState.HALF_OPEN.value,
            "half_open_calls": 10,  # Exceeds max_calls (3)
            "half_open_at": datetime.now(timezone.utc).isoformat(),
            "version": 1,
        }

        result = self.circuit.can_execute()

        assert result is False

    @patch.object(DynamoDBCircuitBreaker, "_reset_half_open_calls")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_can_execute_half_open_resets_after_timeout(self, mock_get_state, mock_reset):
        """Test that half-open circuit resets calls after timeout has passed."""
        # Set half_open_at to well in the past (timeout has passed)
        old_time = (datetime.now(timezone.utc) - timedelta(seconds=200)).isoformat()
        mock_get_state.return_value = {
            "state": CircuitState.HALF_OPEN.value,
            "half_open_calls": 10,  # Exceeds max_calls (3)
            "half_open_at": old_time,
            "version": 1,
        }

        result = self.circuit.can_execute()

        assert result is True
        mock_reset.assert_called_once()

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_failure_increments_count(self, mock_get_state, mock_get_table):
        """Test that recording failure increments failure count."""
        mock_get_state.return_value = {
            "state": CircuitState.CLOSED.value,
            "failure_count": 1,
            "version": 1,
        }
        mock_table = MagicMock()
        mock_get_table.return_value = mock_table

        self.circuit.record_failure()

        mock_table.update_item.assert_called_once()

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_failure_opens_circuit_at_threshold(self, mock_get_state, mock_get_table):
        """Test that circuit opens when threshold is reached."""
        mock_get_state.return_value = {
            "state": CircuitState.CLOSED.value,
            "failure_count": 2,  # One more failure will reach threshold (3)
            "version": 1,
        }
        mock_table = MagicMock()
        mock_get_table.return_value = mock_table

        self.circuit.record_failure()

        # Should update with OPEN state
        call_args = mock_table.update_item.call_args
        assert ":open" in call_args.kwargs["ExpressionAttributeValues"]

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_success_in_half_open_may_close(self, mock_get_state, mock_get_table):
        """Test that successful calls in half-open state can close circuit."""
        mock_get_state.return_value = {
            "state": CircuitState.HALF_OPEN.value,
            "success_count": 1,  # One more success will reach threshold (2)
            "version": 1,
        }
        mock_table = MagicMock()
        # Mock update_item to return the new success_count (now 2, meeting threshold)
        mock_table.update_item.return_value = {
            "Attributes": {"success_count": 2}
        }
        mock_get_table.return_value = mock_table

        self.circuit.record_success()

        # Should have been called twice: once to increment, once to transition to CLOSED
        assert mock_table.update_item.call_count == 2
        # The second call should update with CLOSED state
        second_call_args = mock_table.update_item.call_args_list[1]
        assert ":closed" in second_call_args.kwargs["ExpressionAttributeValues"]

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_failure_in_half_open_reopens(self, mock_get_state, mock_get_table):
        """Test that failure in half-open state reopens circuit."""
        mock_get_state.return_value = {
            "state": CircuitState.HALF_OPEN.value,
            "success_count": 0,
            "version": 1,
        }
        mock_table = MagicMock()
        mock_get_table.return_value = mock_table

        self.circuit.record_failure()

        # Should update with OPEN state
        call_args = mock_table.update_item.call_args
        assert ":open" in call_args.kwargs["ExpressionAttributeValues"]


class TestCircuitBreakerConfig:
    """Tests for circuit breaker configuration."""

    def test_default_config(self):
        config = CircuitBreakerConfig()
        assert config.failure_threshold == 5
        assert config.timeout_seconds == 60
        assert config.success_threshold == 2
        assert config.half_open_max_calls == 3

    def test_custom_config(self):
        config = CircuitBreakerConfig(
            failure_threshold=10,
            timeout_seconds=120,
            success_threshold=5,
            half_open_max_calls=1,
        )
        assert config.failure_threshold == 10
        assert config.timeout_seconds == 120
        assert config.success_threshold == 5
        assert config.half_open_max_calls == 1


class TestCircuitBreakerFactory:
    """Tests for circuit breaker factory function."""

    @patch.dict(os.environ, {"USE_DISTRIBUTED_CIRCUIT_BREAKER": "false"})
    def test_factory_returns_in_memory_by_default(self):
        # Re-import to pick up environment change
        import importlib
        import circuit_breaker
        importlib.reload(circuit_breaker)

        from circuit_breaker import _create_circuit_breaker, InMemoryCircuitBreaker

        cb = _create_circuit_breaker("test", CircuitBreakerConfig())
        assert isinstance(cb, InMemoryCircuitBreaker)

    @patch.dict(os.environ, {"USE_DISTRIBUTED_CIRCUIT_BREAKER": "true"})
    def test_factory_returns_dynamodb_when_enabled(self):
        # Re-import to pick up environment change
        import importlib
        import circuit_breaker
        importlib.reload(circuit_breaker)

        from circuit_breaker import _create_circuit_breaker, DynamoDBCircuitBreaker

        cb = _create_circuit_breaker("test", CircuitBreakerConfig())
        assert isinstance(cb, DynamoDBCircuitBreaker)
