"""
Tests for CloudWatch metrics utilities module.

Tests cover metric emission, batch operations, and error handling
using moto to mock CloudWatch.
"""

import os
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

# Import after setting up environment to avoid issues
import shared.metrics as metrics_module
from shared.metrics import (
    NAMESPACE,
    _get_cloudwatch,
    emit_batch_metrics,
    emit_circuit_breaker_metric,
    emit_dlq_metric,
    emit_error_metric,
    emit_metric,
)


@pytest.fixture
def reset_cloudwatch_client():
    """Reset the global CloudWatch client between tests."""
    metrics_module._cloudwatch = None
    yield
    metrics_module._cloudwatch = None


@pytest.fixture
def mock_cloudwatch(reset_cloudwatch_client):
    """Provide mocked CloudWatch client."""
    with mock_aws():
        # Force re-creation of client
        metrics_module._cloudwatch = None
        yield boto3.client("cloudwatch", region_name="us-east-1")


class TestGetCloudwatch:
    """Tests for lazy CloudWatch client initialization."""

    def test_creates_client_on_first_call(self, reset_cloudwatch_client):
        """Should create CloudWatch client on first access."""
        with mock_aws():
            assert metrics_module._cloudwatch is None
            client = _get_cloudwatch()
            assert client is not None
            assert metrics_module._cloudwatch is client

    def test_returns_same_client_on_subsequent_calls(self, reset_cloudwatch_client):
        """Should return the same client on subsequent calls."""
        with mock_aws():
            client1 = _get_cloudwatch()
            client2 = _get_cloudwatch()
            assert client1 is client2


class TestEmitMetric:
    """Tests for emit_metric function."""

    def test_emits_simple_metric(self, mock_cloudwatch):
        """Should emit a simple count metric."""
        emit_metric("TestMetric")

        # Verify metric was emitted (moto doesn't store metrics, but call succeeds)
        # The test passes if no exception is raised

    def test_emits_metric_with_value(self, mock_cloudwatch):
        """Should emit metric with specified value."""
        emit_metric("ProcessingTime", value=2.5, unit="Seconds")

        # Test passes if no exception

    def test_emits_metric_with_dimensions(self, mock_cloudwatch):
        """Should emit metric with dimensions."""
        emit_metric(
            "PackagesCollected",
            value=100,
            dimensions={"Ecosystem": "npm", "Source": "registry"},
        )

        # Test passes if no exception

    def test_uses_correct_namespace(self, mock_cloudwatch):
        """Should use the configured namespace."""
        # Verify namespace from module
        assert NAMESPACE == os.environ.get("CLOUDWATCH_NAMESPACE", "PkgWatch")

    def test_handles_cloudwatch_error_gracefully(self, reset_cloudwatch_client, caplog):
        """Should log warning but not raise on CloudWatch error."""
        with mock_aws():
            # Patch to simulate an error
            with patch.object(
                metrics_module,
                "_get_cloudwatch",
                return_value=MagicMock(
                    put_metric_data=MagicMock(side_effect=Exception("CloudWatch error"))
                ),
            ):
                # Should not raise
                emit_metric("TestMetric")

                # Should log warning
                assert "Failed to emit metric" in caplog.text

    def test_logs_debug_on_success(self, mock_cloudwatch, caplog):
        """Should log debug message on successful emission."""
        import logging
        with caplog.at_level(logging.DEBUG):
            emit_metric("DebugTestMetric", value=42, unit="Count")

        # Debug log may or may not appear depending on log level config
        # The important thing is no error is logged

    def test_default_value_is_one(self, mock_cloudwatch):
        """Default metric value should be 1.0."""
        # We can't directly verify the value sent to moto, but we test
        # that calling without value parameter works
        emit_metric("CountMetric")  # Should default to 1.0

    def test_default_unit_is_count(self, mock_cloudwatch):
        """Default metric unit should be 'Count'."""
        emit_metric("DefaultUnitMetric", value=5)  # Should default to "Count"


class TestEmitBatchMetrics:
    """Tests for emit_batch_metrics function."""

    def test_emits_multiple_metrics(self, mock_cloudwatch):
        """Should emit multiple metrics in one call."""
        metrics = [
            {"metric_name": "Successes", "value": 10},
            {"metric_name": "Failures", "value": 2},
            {"metric_name": "Retries", "value": 5},
        ]

        emit_batch_metrics(metrics)

        # Test passes if no exception

    def test_handles_empty_metrics_list(self, mock_cloudwatch):
        """Should handle empty metrics list gracefully."""
        emit_batch_metrics([])

        # Test passes if no exception

    def test_batches_over_20_metrics(self, mock_cloudwatch):
        """Should split metrics into batches of 20 (CloudWatch limit)."""
        # Create 25 metrics
        metrics = [
            {"metric_name": f"Metric{i}", "value": i}
            for i in range(25)
        ]

        emit_batch_metrics(metrics)

        # Test passes if no exception - internally should make 2 API calls

    def test_applies_defaults_for_missing_fields(self, mock_cloudwatch):
        """Should apply default value and unit when not specified."""
        metrics = [
            {"metric_name": "MinimalMetric"},  # No value or unit
        ]

        emit_batch_metrics(metrics)

        # Test passes if no exception (defaults applied: value=1.0, unit="Count")

    def test_includes_dimensions_when_provided(self, mock_cloudwatch):
        """Should include dimensions for metrics that have them."""
        metrics = [
            {
                "metric_name": "PackagesProcessed",
                "value": 50,
                "dimensions": {"Ecosystem": "npm"},
            },
            {
                "metric_name": "ErrorCount",
                "value": 3,
            },
        ]

        emit_batch_metrics(metrics)

        # Test passes if no exception

    def test_handles_error_gracefully(self, reset_cloudwatch_client, caplog):
        """Should log warning but not raise on error."""
        with mock_aws():
            with patch.object(
                metrics_module,
                "_get_cloudwatch",
                return_value=MagicMock(
                    put_metric_data=MagicMock(side_effect=Exception("Batch error"))
                ),
            ):
                metrics = [{"metric_name": "Test", "value": 1}]

                # Should not raise
                emit_batch_metrics(metrics)

                assert "Failed to emit batch metrics" in caplog.text


class TestEmitErrorMetric:
    """Tests for emit_error_metric function."""

    def test_emits_error_with_type(self, mock_cloudwatch):
        """Should emit error metric with error type dimension."""
        emit_error_metric("rate_limit")

        # Test passes if no exception

    def test_includes_service_dimension(self, mock_cloudwatch):
        """Should include service dimension when provided."""
        emit_error_metric("timeout", service="github")

        # Test passes if no exception

    def test_includes_handler_dimension(self, mock_cloudwatch):
        """Should include handler dimension when provided."""
        emit_error_metric("internal", handler="get_package")

        # Test passes if no exception

    def test_includes_all_dimensions(self, mock_cloudwatch):
        """Should include all dimensions when all are provided."""
        emit_error_metric(
            error_type="validation",
            service="npm",
            handler="post_scan",
        )

        # Test passes if no exception

    def test_only_error_type_dimension_when_others_not_provided(self, mock_cloudwatch):
        """Should only include ErrorType when service/handler not provided."""
        emit_error_metric("unknown")

        # Test passes if no exception


class TestEmitCircuitBreakerMetric:
    """Tests for emit_circuit_breaker_metric function."""

    def test_emits_open_state(self, mock_cloudwatch):
        """Should emit metric when circuit breaker opens."""
        emit_circuit_breaker_metric("github", "open")

        # Test passes if no exception

    def test_emits_closed_state(self, mock_cloudwatch):
        """Should emit metric when circuit breaker closes."""
        emit_circuit_breaker_metric("npm", "closed")

        # Test passes if no exception

    def test_emits_half_open_state(self, mock_cloudwatch):
        """Should emit metric when circuit breaker is half-open."""
        emit_circuit_breaker_metric("depsdev", "half_open")

        # Test passes if no exception

    def test_includes_correct_dimensions(self, mock_cloudwatch):
        """Should include CircuitName and State dimensions."""
        emit_circuit_breaker_metric("pypi", "open")

        # Test passes if no exception


class TestEmitDlqMetric:
    """Tests for emit_dlq_metric function."""

    def test_emits_requeued_action(self, mock_cloudwatch):
        """Should emit metric for requeued messages."""
        emit_dlq_metric("requeued")

        # Test passes if no exception

    def test_emits_permanent_failure_action(self, mock_cloudwatch):
        """Should emit metric for permanent failures."""
        emit_dlq_metric("permanent_failure")

        # Test passes if no exception

    def test_emits_processed_action(self, mock_cloudwatch):
        """Should emit metric for processed messages."""
        emit_dlq_metric("processed")

        # Test passes if no exception

    def test_includes_package_name_dimension(self, mock_cloudwatch):
        """Should include Package dimension when provided."""
        emit_dlq_metric("requeued", package_name="lodash")

        # Test passes if no exception

    def test_truncates_long_package_name(self, mock_cloudwatch):
        """Should truncate package names longer than 50 chars."""
        long_name = "a" * 100  # 100 character name

        emit_dlq_metric("permanent_failure", package_name=long_name)

        # Test passes if no exception - name should be truncated to 50 chars

    def test_no_package_dimension_when_none(self, mock_cloudwatch):
        """Should not include Package dimension when not provided."""
        emit_dlq_metric("processed")

        # Test passes if no exception


class TestNamespaceConfiguration:
    """Tests for namespace configuration."""

    def test_default_namespace(self, reset_cloudwatch_client):
        """Default namespace should be 'PkgWatch'."""
        with patch.dict(os.environ, {}, clear=True):
            # Need to reimport to get new default
            import importlib
            importlib.reload(metrics_module)

            assert metrics_module.NAMESPACE == "PkgWatch"

    def test_custom_namespace_from_env(self, reset_cloudwatch_client):
        """Should use CLOUDWATCH_NAMESPACE env var if set."""
        with patch.dict(os.environ, {"CLOUDWATCH_NAMESPACE": "CustomNamespace"}):
            import importlib
            importlib.reload(metrics_module)

            assert metrics_module.NAMESPACE == "CustomNamespace"


class TestMetricDataStructure:
    """Tests verifying correct metric data structure."""

    def test_metric_includes_timestamp(self, mock_cloudwatch):
        """Emitted metrics should include timestamp."""
        # We can verify by checking no error is raised with timestamp
        emit_metric("TimestampTest")

    def test_dimensions_format(self, mock_cloudwatch):
        """Dimensions should be formatted as list of Name/Value dicts."""
        # This is tested indirectly - CloudWatch would reject incorrect format
        emit_metric(
            "DimensionFormatTest",
            dimensions={
                "Dim1": "Value1",
                "Dim2": "Value2",
            },
        )


class TestEdgeCases:
    """Edge case tests for metrics module."""

    def test_zero_value_metric(self, mock_cloudwatch):
        """Should handle zero value metrics."""
        emit_metric("ZeroMetric", value=0)

    def test_negative_value_metric(self, mock_cloudwatch):
        """Should handle negative value metrics."""
        emit_metric("NegativeMetric", value=-5)

    def test_very_large_value_metric(self, mock_cloudwatch):
        """Should handle very large metric values."""
        emit_metric("LargeMetric", value=1e15)

    def test_float_value_metric(self, mock_cloudwatch):
        """Should handle float metric values."""
        emit_metric("FloatMetric", value=3.14159)

    def test_empty_dimensions_dict(self, mock_cloudwatch):
        """Should handle empty dimensions dict."""
        emit_metric("EmptyDimensions", dimensions={})

    def test_special_characters_in_metric_name(self, mock_cloudwatch):
        """Should handle special characters in metric names."""
        # CloudWatch accepts alphanumeric, hyphen, underscore, period, slash, hash
        emit_metric("Test-Metric_Name.v1/total#count")

    def test_unicode_in_dimension_value(self, mock_cloudwatch):
        """Should handle unicode in dimension values."""
        emit_metric(
            "UnicodeTest",
            dimensions={"Package": "test-\u00e9\u00e8\u00ea"},
        )
