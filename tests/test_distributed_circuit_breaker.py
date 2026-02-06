"""
Tests for DynamoDB-backed distributed circuit breaker.
"""

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

# Set up environment before importing
os.environ.setdefault("API_KEYS_TABLE", "pkgwatch-api-keys")
os.environ.setdefault("USE_DISTRIBUTED_CIRCUIT_BREAKER", "false")

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../functions/shared"))

from circuit_breaker import (
    CircuitBreakerConfig,
    CircuitState,
    DynamoDBCircuitBreaker,
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

        from circuit_breaker import InMemoryCircuitBreaker, _create_circuit_breaker

        cb = _create_circuit_breaker("test", CircuitBreakerConfig())
        assert isinstance(cb, InMemoryCircuitBreaker)

    @patch.dict(os.environ, {"USE_DISTRIBUTED_CIRCUIT_BREAKER": "true"})
    def test_factory_returns_dynamodb_when_enabled(self):
        # Re-import to pick up environment change
        import importlib

        import circuit_breaker
        importlib.reload(circuit_breaker)

        from circuit_breaker import DynamoDBCircuitBreaker, _create_circuit_breaker

        cb = _create_circuit_breaker("test", CircuitBreakerConfig())
        assert isinstance(cb, DynamoDBCircuitBreaker)


class TestDynamoDBCircuitBreakerAdvanced:
    """Advanced tests covering uncovered DynamoDB circuit breaker paths."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = CircuitBreakerConfig(
            failure_threshold=3,
            timeout_seconds=60,
            success_threshold=2,
            half_open_max_calls=3,
        )
        self.circuit = DynamoDBCircuitBreaker("test-advanced", self.config)

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_get_dynamodb_table_returns_table(self, mock_get_table):
        """_get_dynamodb_table should return a DynamoDB table."""
        mock_table = MagicMock()
        mock_get_table.return_value = mock_table
        result = self.circuit._get_dynamodb_table()
        assert result == mock_table

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_get_state_returns_existing_item(self, mock_get_table):
        """_get_state should return existing item from DynamoDB."""
        mock_table = MagicMock()
        expected_item = {
            "pk": "circuit#test-advanced",
            "sk": "STATE",
            "state": "closed",
            "failure_count": 2,
            "version": 3,
        }
        mock_table.get_item.return_value = {"Item": expected_item}
        mock_get_table.return_value = mock_table

        # Clear cache
        self.circuit._local_cache = None

        state = self.circuit._get_state()
        assert state == expected_item
        assert self.circuit._local_cache == expected_item

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_create_initial_state_race_condition(self, mock_get_table):
        """_create_initial_state should handle ConditionalCheckFailedException gracefully."""
        mock_table = MagicMock()
        mock_table.put_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Already exists"}},
            "PutItem"
        )
        mock_table.get_item.return_value = {}  # No item
        mock_get_table.return_value = mock_table

        # Clear cache
        self.circuit._local_cache = None

        # Should not raise, just returns initial state
        state = self.circuit._get_state()
        assert state["state"] == CircuitState.CLOSED.value

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_create_initial_state_other_error_logs_warning(self, mock_get_table):
        """_create_initial_state with non-condition error should log warning but still return state."""
        mock_table = MagicMock()
        mock_table.put_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "DynamoDB error"}},
            "PutItem"
        )
        mock_table.get_item.return_value = {}  # No item
        mock_get_table.return_value = mock_table

        self.circuit._local_cache = None
        state = self.circuit._get_state()

        # Should still return initial state (fail-open behavior)
        assert state["state"] == CircuitState.CLOSED.value

    def test_should_attempt_reset_no_opened_at(self):
        """_should_attempt_reset should return True when no opened_at."""
        state = {"state": CircuitState.OPEN.value}
        assert self.circuit._should_attempt_reset(state) is True

    def test_should_attempt_reset_invalid_timestamp(self):
        """_should_attempt_reset should return True for invalid timestamps."""
        state = {"state": CircuitState.OPEN.value, "opened_at": "not-a-date"}
        assert self.circuit._should_attempt_reset(state) is True

    def test_should_attempt_reset_none_opened_at(self):
        """_should_attempt_reset should return True when opened_at is None."""
        state = {"state": CircuitState.OPEN.value, "opened_at": None}
        assert self.circuit._should_attempt_reset(state) is True

    def test_should_attempt_reset_not_yet_elapsed(self):
        """_should_attempt_reset should return False when timeout hasn't elapsed."""
        now = datetime.now(timezone.utc)
        state = {"state": CircuitState.OPEN.value, "opened_at": now.isoformat()}
        assert self.circuit._should_attempt_reset(state) is False

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_transition_to_half_open_success(self, mock_get_table):
        """_transition_to_half_open should return True on successful transition."""
        mock_table = MagicMock()
        mock_get_table.return_value = mock_table

        state = {"state": CircuitState.OPEN.value, "version": 1}
        result = self.circuit._transition_to_half_open(state)

        assert result is True
        assert self.circuit._local_cache is None  # Cache invalidated
        mock_table.update_item.assert_called_once()

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_transition_to_half_open_race_condition(self, mock_get_table):
        """_transition_to_half_open should handle race condition via recursive can_execute."""
        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Version mismatch"}},
            "UpdateItem"
        )
        mock_get_table.return_value = mock_table

        state = {"state": CircuitState.OPEN.value, "version": 1}

        # Patch can_execute to avoid infinite recursion
        with patch.object(self.circuit, "can_execute", return_value=True) as mock_can_execute:
            _result = self.circuit._transition_to_half_open(state)

        assert self.circuit._local_cache is None  # Cache invalidated
        mock_can_execute.assert_called_once()

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_transition_to_half_open_other_error_fails_open(self, mock_get_table):
        """_transition_to_half_open with non-condition error should fail-open (return True)."""
        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "DynamoDB down"}},
            "UpdateItem"
        )
        mock_get_table.return_value = mock_table

        state = {"state": CircuitState.OPEN.value, "version": 1}
        result = self.circuit._transition_to_half_open(state)

        assert result is True  # Fail-open

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_increment_half_open_calls_success(self, mock_get_table):
        """_increment_half_open_calls should increment counter atomically."""
        mock_table = MagicMock()
        mock_get_table.return_value = mock_table

        state = {"version": 1}
        self.circuit._increment_half_open_calls(state)

        mock_table.update_item.assert_called_once()
        assert self.circuit._local_cache is None  # Cache invalidated

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_increment_half_open_calls_error_ignored(self, mock_get_table):
        """_increment_half_open_calls errors should be silently ignored."""
        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": ""}},
            "UpdateItem"
        )
        mock_get_table.return_value = mock_table

        state = {"version": 1}
        # Should not raise
        self.circuit._increment_half_open_calls(state)

    def test_should_reset_half_open_calls_no_timestamp(self):
        """_should_reset_half_open_calls should return True when no half_open_at."""
        state = {"state": CircuitState.HALF_OPEN.value}
        assert self.circuit._should_reset_half_open_calls(state) is True

    def test_should_reset_half_open_calls_invalid_timestamp(self):
        """_should_reset_half_open_calls should return True for invalid timestamps."""
        state = {"state": CircuitState.HALF_OPEN.value, "half_open_at": "garbage"}
        assert self.circuit._should_reset_half_open_calls(state) is True

    def test_should_reset_half_open_calls_not_elapsed(self):
        """_should_reset_half_open_calls should return False when timeout hasn't elapsed."""
        now = datetime.now(timezone.utc)
        state = {"state": CircuitState.HALF_OPEN.value, "half_open_at": now.isoformat()}
        assert self.circuit._should_reset_half_open_calls(state) is False

    def test_should_reset_half_open_calls_elapsed(self):
        """_should_reset_half_open_calls should return True after timeout."""
        old_time = datetime.now(timezone.utc) - timedelta(seconds=200)
        state = {"state": CircuitState.HALF_OPEN.value, "half_open_at": old_time.isoformat()}
        assert self.circuit._should_reset_half_open_calls(state) is True

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_reset_half_open_calls_success(self, mock_get_table):
        """_reset_half_open_calls should reset counter and invalidate cache."""
        mock_table = MagicMock()
        mock_get_table.return_value = mock_table

        state = {"version": 5}
        self.circuit._reset_half_open_calls(state)

        mock_table.update_item.assert_called_once()
        assert self.circuit._local_cache is None

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    def test_reset_half_open_calls_error_ignored(self, mock_get_table):
        """_reset_half_open_calls errors should be silently ignored."""
        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": ""}},
            "UpdateItem"
        )
        mock_get_table.return_value = mock_table

        state = {"version": 5}
        # Should not raise
        self.circuit._reset_half_open_calls(state)

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_success_closed_resets_failure_count(self, mock_get_state, mock_get_table):
        """record_success in CLOSED state should reset failure_count if > 0."""
        mock_get_state.return_value = {
            "state": CircuitState.CLOSED.value,
            "failure_count": 2,
            "version": 1,
        }
        mock_table = MagicMock()
        mock_get_table.return_value = mock_table

        self.circuit.record_success()

        # Should have called update_item to reset failure_count
        mock_table.update_item.assert_called_once()
        call_kwargs = mock_table.update_item.call_args.kwargs
        assert ":zero" in call_kwargs["ExpressionAttributeValues"]

    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_success_closed_no_failures_is_noop(self, mock_get_state):
        """record_success in CLOSED state with zero failures should be a no-op."""
        mock_get_state.return_value = {
            "state": CircuitState.CLOSED.value,
            "failure_count": 0,
            "version": 1,
        }

        # Should not call _get_dynamodb_table since failure_count is 0
        with patch.object(self.circuit, "_get_dynamodb_table") as mock_get_table:
            self.circuit.record_success()
            mock_get_table.assert_not_called()

    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_success_open_is_noop(self, mock_get_state):
        """record_success in OPEN state should do nothing."""
        mock_get_state.return_value = {
            "state": CircuitState.OPEN.value,
            "failure_count": 5,
            "version": 1,
        }

        with patch.object(self.circuit, "_get_dynamodb_table") as mock_get_table:
            self.circuit.record_success()
            mock_get_table.assert_not_called()

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_half_open_success_increments_then_closes(self, mock_get_state, mock_get_table):
        """record_success in HALF_OPEN should increment and close at threshold."""
        mock_get_state.return_value = {
            "state": CircuitState.HALF_OPEN.value,
            "success_count": 0,
            "version": 1,
        }
        mock_table = MagicMock()
        # First call: increment success_count, returns new count = 2 (threshold met)
        mock_table.update_item.return_value = {"Attributes": {"success_count": 2}}
        mock_get_table.return_value = mock_table

        self.circuit.record_success()

        # Two calls: one to increment, one to transition to CLOSED
        assert mock_table.update_item.call_count == 2

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_half_open_success_below_threshold(self, mock_get_state, mock_get_table):
        """record_success in HALF_OPEN below threshold should only increment."""
        mock_get_state.return_value = {
            "state": CircuitState.HALF_OPEN.value,
            "success_count": 0,
            "version": 1,
        }
        mock_table = MagicMock()
        # Returns 1, which is below threshold (2)
        mock_table.update_item.return_value = {"Attributes": {"success_count": 1}}
        mock_get_table.return_value = mock_table

        self.circuit.record_success()

        # Only one call (increment), no transition
        assert mock_table.update_item.call_count == 1

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_half_open_success_close_race_condition(self, mock_get_state, mock_get_table):
        """Close transition race should be handled gracefully."""
        mock_get_state.return_value = {
            "state": CircuitState.HALF_OPEN.value,
            "success_count": 1,
            "version": 1,
        }
        mock_table = MagicMock()

        call_count = [0]

        def mock_update(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call: increment returns threshold met
                return {"Attributes": {"success_count": 2}}
            else:
                # Second call: transition to CLOSED fails (another instance did it)
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": ""}},
                    "UpdateItem"
                )

        mock_table.update_item.side_effect = mock_update
        mock_get_table.return_value = mock_table

        # Should not raise
        self.circuit.record_success()
        assert call_count[0] == 2

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_half_open_success_close_other_error_caught_by_outer(self, mock_get_state, mock_get_table):
        """Close transition with non-condition error is caught by outer except and logged."""
        mock_get_state.return_value = {
            "state": CircuitState.HALF_OPEN.value,
            "success_count": 1,
            "version": 1,
        }
        mock_table = MagicMock()

        call_count = [0]

        def mock_update(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return {"Attributes": {"success_count": 2}}
            else:
                # Inner raise re-raises this, outer except catches it
                raise ClientError(
                    {"Error": {"Code": "InternalServerError", "Message": "DynamoDB down"}},
                    "UpdateItem"
                )

        mock_table.update_item.side_effect = mock_update
        mock_get_table.return_value = mock_table

        # Should NOT raise - the outer except ClientError catches and logs
        self.circuit.record_success()
        assert call_count[0] == 2

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_half_open_success_ddb_error_logged(self, mock_get_state, mock_get_table):
        """DynamoDB error during half-open success recording should be logged, not raised."""
        mock_get_state.return_value = {
            "state": CircuitState.HALF_OPEN.value,
            "success_count": 0,
            "version": 1,
        }
        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable", "Message": ""}},
            "UpdateItem"
        )
        mock_get_table.return_value = mock_table

        # Should not raise (outer except catches it)
        self.circuit.record_success()

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_failure_open_is_noop(self, mock_get_state, mock_get_table):
        """record_failure in OPEN state should not call DynamoDB."""
        mock_get_state.return_value = {
            "state": CircuitState.OPEN.value,
            "failure_count": 5,
            "version": 1,
        }
        mock_table = MagicMock()
        mock_get_table.return_value = mock_table

        self.circuit.record_failure()
        mock_table.update_item.assert_not_called()

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_transition_to_open_from_half_open_success(self, mock_get_state, mock_get_table):
        """Failure in HALF_OPEN should transition to OPEN."""
        mock_get_state.return_value = {
            "state": CircuitState.HALF_OPEN.value,
            "version": 1,
        }
        mock_table = MagicMock()
        mock_get_table.return_value = mock_table

        self.circuit.record_failure()

        mock_table.update_item.assert_called_once()
        call_kwargs = mock_table.update_item.call_args.kwargs
        assert call_kwargs["ExpressionAttributeValues"][":open"] == CircuitState.OPEN.value

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_transition_to_open_from_half_open_error_logged(self, mock_get_state, mock_get_table):
        """Error during HALF_OPEN -> OPEN transition should be logged, not raised."""
        mock_get_state.return_value = {
            "state": CircuitState.HALF_OPEN.value,
            "version": 1,
        }
        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable", "Message": ""}},
            "UpdateItem"
        )
        mock_get_table.return_value = mock_table

        # Should not raise
        self.circuit.record_failure()

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_closed_failure_below_threshold(self, mock_get_state, mock_get_table):
        """Failure below threshold should increment failure_count only."""
        mock_get_state.return_value = {
            "state": CircuitState.CLOSED.value,
            "failure_count": 0,  # 0 + 1 = 1 < 3 threshold
            "version": 1,
        }
        mock_table = MagicMock()
        mock_get_table.return_value = mock_table

        self.circuit.record_failure()

        mock_table.update_item.assert_called_once()
        call_kwargs = mock_table.update_item.call_args.kwargs
        # Should just increment, not open
        assert ":open" not in call_kwargs.get("ExpressionAttributeValues", {})

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_record_closed_failure_ddb_error_logged(self, mock_get_state, mock_get_table):
        """DynamoDB error during failure recording should be logged, not raised."""
        mock_get_state.return_value = {
            "state": CircuitState.CLOSED.value,
            "failure_count": 1,
            "version": 1,
        }
        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ServiceUnavailable", "Message": ""}},
            "UpdateItem"
        )
        mock_get_table.return_value = mock_table

        # Should not raise
        self.circuit.record_failure()

    @patch.object(DynamoDBCircuitBreaker, "_get_dynamodb_table")
    @patch.object(DynamoDBCircuitBreaker, "_get_state")
    def test_reset_failure_count_error_ignored(self, mock_get_state, mock_get_table):
        """Error during failure count reset should be silently ignored."""
        mock_get_state.return_value = {
            "state": CircuitState.CLOSED.value,
            "failure_count": 2,
            "version": 1,
        }
        mock_table = MagicMock()
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": ""}},
            "UpdateItem"
        )
        mock_get_table.return_value = mock_table

        # Should not raise
        self.circuit.record_success()

    @patch.object(DynamoDBCircuitBreaker, "can_execute")
    def test_can_execute_async_delegates_to_sync(self, mock_can_execute):
        """can_execute_async should delegate to sync can_execute via to_thread."""
        import asyncio

        mock_can_execute.return_value = True

        async def run():
            return await self.circuit.can_execute_async()

        result = asyncio.run(run())
        assert result is True
        mock_can_execute.assert_called_once()

    @patch.object(DynamoDBCircuitBreaker, "record_success")
    def test_record_success_async_delegates(self, mock_record_success):
        """record_success_async should delegate to sync record_success."""
        import asyncio

        async def run():
            await self.circuit.record_success_async()

        asyncio.run(run())
        mock_record_success.assert_called_once()

    @patch.object(DynamoDBCircuitBreaker, "record_failure")
    def test_record_failure_async_delegates(self, mock_record_failure):
        """record_failure_async should delegate to sync record_failure."""
        import asyncio

        test_error = RuntimeError("test")

        async def run():
            await self.circuit.record_failure_async(test_error)

        asyncio.run(run())
        mock_record_failure.assert_called_once_with(test_error)
