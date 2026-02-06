"""
Tests for pipeline health check endpoint.

Tests cover:
- Healthy status (queues empty/low)
- Degraded status (elevated queue depth or DLQ count)
- Unhealthy status (DLQ overflow or errors)
- GitHub rate limit monitoring
- CloudWatch metrics publishing
- Error handling (AWS API failures)
- Edge cases (missing queues, permission errors)

Run with: PYTHONPATH=functions:. pytest tests/test_pipeline_health.py -v
"""

import json
import os
import sys
from datetime import datetime
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

# Add functions directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions", "collectors"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions", "shared"))


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def mock_sqs_queues():
    """Create mock SQS queues for testing."""
    with mock_aws():
        sqs = boto3.client("sqs", region_name="us-east-1")

        # Create main queue
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]

        # Create DLQ
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        yield sqs, main_queue_url, dlq_url


@pytest.fixture
def setup_env_vars(mock_sqs_queues):
    """Set environment variables required by the handler."""
    sqs, main_queue_url, dlq_url = mock_sqs_queues

    env_vars = {
        "PACKAGE_QUEUE_URL": main_queue_url,
        "DLQ_URL": dlq_url,
        "CLOUDWATCH_NAMESPACE": "PkgWatch-Test",
        "API_KEYS_TABLE": "pkgwatch-api-keys",
    }

    with patch.dict(os.environ, env_vars):
        # Reset module-level clients before import
        yield sqs, main_queue_url, dlq_url


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def send_messages_to_queue(sqs, queue_url: str, count: int):
    """Send a specified number of messages to a queue."""
    for i in range(count):
        sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps({"test": i}))


def reload_pipeline_health():
    """Reload the pipeline_health module to pick up new environment variables."""
    # Clear cached modules that use environment variables
    modules_to_clear = [
        "collectors.pipeline_health",
        "pipeline_health",
        "shared.metrics",
        "metrics",
    ]
    for mod in modules_to_clear:
        if mod in sys.modules:
            del sys.modules[mod]

    # Import fresh module
    from collectors import pipeline_health

    # Reset module-level clients
    pipeline_health.sqs = boto3.client("sqs", region_name="us-east-1")
    pipeline_health.cloudwatch = boto3.client("cloudwatch", region_name="us-east-1")

    return pipeline_health


# =============================================================================
# HEALTHY STATUS TESTS
# =============================================================================


class TestHealthyStatus:
    """Tests for healthy pipeline status."""

    @mock_aws
    def test_healthy_when_queues_empty(self, mock_dynamodb):
        """Pipeline is healthy when queues are empty."""
        # Create SQS queues
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            # Mock GitHub rate limit check
            with patch.object(
                pipeline_health,
                "_get_rate_limit_window_key",
                return_value="2024-01-01-12",
                create=True,
            ), patch.object(
                pipeline_health,
                "_get_total_github_calls",
                return_value=100,
                create=True,
            ):
                # Mock the import of package_collector functions
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["status"] == "healthy"
        assert body["checks"]["main_queue"]["status"] == "healthy"
        assert body["checks"]["main_queue"]["depth"] == 0
        assert body["checks"]["dlq"]["status"] == "healthy"
        assert body["checks"]["dlq"]["depth"] == 0

    @mock_aws
    def test_healthy_with_low_queue_depth(self, mock_dynamodb):
        """Pipeline is healthy when queue depth is below threshold."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        # Add some messages to main queue (below 1000 threshold)
        for i in range(50):
            sqs.send_message(QueueUrl=main_queue_url, MessageBody=f"msg-{i}")

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            with patch.dict(sys.modules, {
                "package_collector": MagicMock(
                    _get_rate_limit_window_key=lambda: "2024-01-01-12",
                    _get_total_github_calls=lambda k: 500,
                    GITHUB_HOURLY_LIMIT=4000,
                )
            }):
                response = pipeline_health.handler({}, {})

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["status"] == "healthy"
        assert body["checks"]["main_queue"]["depth"] == 50

    @mock_aws
    def test_healthy_with_small_dlq_count(self, mock_dynamodb):
        """Pipeline is healthy when DLQ has few messages (< 10)."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        # Add a few messages to DLQ (below 10 threshold)
        for i in range(5):
            sqs.send_message(QueueUrl=dlq_url, MessageBody=f"dlq-msg-{i}")

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            with patch.dict(sys.modules, {
                "package_collector": MagicMock(
                    _get_rate_limit_window_key=lambda: "2024-01-01-12",
                    _get_total_github_calls=lambda k: 100,
                    GITHUB_HOURLY_LIMIT=4000,
                )
            }):
                response = pipeline_health.handler({}, {})

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["status"] == "healthy"
        assert body["checks"]["dlq"]["status"] == "healthy"
        assert body["checks"]["dlq"]["depth"] == 5


# =============================================================================
# DEGRADED STATUS TESTS
# =============================================================================


class TestDegradedStatus:
    """Tests for degraded pipeline status."""

    @mock_aws
    def test_degraded_when_queue_depth_high(self, mock_dynamodb):
        """Pipeline is degraded when main queue depth exceeds 1000."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            # Mock the SQS get_queue_attributes to return high queue depth
            original_get_attrs = pipeline_health.sqs.get_queue_attributes

            def mock_get_attrs(QueueUrl, AttributeNames):
                if QueueUrl == main_queue_url:
                    return {
                        "Attributes": {
                            "ApproximateNumberOfMessages": "1500",
                            "ApproximateNumberOfMessagesNotVisible": "100",
                        }
                    }
                return original_get_attrs(QueueUrl=QueueUrl, AttributeNames=AttributeNames)

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

        assert response["statusCode"] == 503
        body = json.loads(response["body"])
        assert body["status"] == "degraded"
        assert body["checks"]["main_queue"]["status"] == "degraded"
        assert body["checks"]["main_queue"]["depth"] == 1500

    @mock_aws
    def test_degraded_when_dlq_has_medium_count(self, mock_dynamodb):
        """Pipeline is degraded when DLQ has 10-99 messages."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            # Mock the SQS get_queue_attributes for DLQ
            _original_get_attrs = pipeline_health.sqs.get_queue_attributes

            def mock_get_attrs(QueueUrl, AttributeNames):
                if QueueUrl == dlq_url:
                    return {
                        "Attributes": {
                            "ApproximateNumberOfMessages": "50",
                        }
                    }
                return {
                    "Attributes": {
                        "ApproximateNumberOfMessages": "100",
                        "ApproximateNumberOfMessagesNotVisible": "10",
                    }
                }

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

        assert response["statusCode"] == 503
        body = json.loads(response["body"])
        assert body["status"] == "degraded"
        assert body["checks"]["dlq"]["status"] == "degraded"
        assert body["checks"]["dlq"]["depth"] == 50

    @mock_aws
    def test_degraded_when_github_rate_limit_high(self, mock_dynamodb):
        """Pipeline is degraded when GitHub rate limit usage is 75-90%."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            # 3200 / 4000 = 80% usage -> degraded
            with patch.dict(sys.modules, {
                "package_collector": MagicMock(
                    _get_rate_limit_window_key=lambda: "2024-01-01-12",
                    _get_total_github_calls=lambda k: 3200,
                    GITHUB_HOURLY_LIMIT=4000,
                )
            }):
                response = pipeline_health.handler({}, {})

        body = json.loads(response["body"])
        assert body["checks"]["github_rate_limit"]["status"] == "degraded"
        assert body["checks"]["github_rate_limit"]["usage_percent"] == 80.0


# =============================================================================
# UNHEALTHY STATUS TESTS
# =============================================================================


class TestUnhealthyStatus:
    """Tests for unhealthy pipeline status."""

    @mock_aws
    def test_unhealthy_when_dlq_overflow(self, mock_dynamodb):
        """Pipeline is unhealthy when DLQ has 100+ messages."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            # Mock the SQS get_queue_attributes for DLQ overflow
            def mock_get_attrs(QueueUrl, AttributeNames):
                if QueueUrl == dlq_url:
                    return {
                        "Attributes": {
                            "ApproximateNumberOfMessages": "150",
                        }
                    }
                return {
                    "Attributes": {
                        "ApproximateNumberOfMessages": "100",
                        "ApproximateNumberOfMessagesNotVisible": "10",
                    }
                }

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

        assert response["statusCode"] == 503
        body = json.loads(response["body"])
        assert body["status"] == "unhealthy"
        assert body["checks"]["dlq"]["status"] == "unhealthy"
        assert body["checks"]["dlq"]["depth"] == 150

    @mock_aws
    def test_unhealthy_when_main_queue_error(self, mock_dynamodb):
        """Pipeline is unhealthy when main queue check fails."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            call_count = [0]
            _original_get_attrs = pipeline_health.sqs.get_queue_attributes

            def mock_get_attrs(QueueUrl, AttributeNames):
                call_count[0] += 1
                if call_count[0] == 1:  # First call is main queue
                    raise Exception("Access Denied")
                return {
                    "Attributes": {
                        "ApproximateNumberOfMessages": "0",
                    }
                }

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

        assert response["statusCode"] == 503
        body = json.loads(response["body"])
        assert body["status"] == "unhealthy"
        assert body["checks"]["main_queue"]["status"] == "error"
        assert "Access Denied" in body["checks"]["main_queue"]["error"]

    @mock_aws
    def test_unhealthy_when_github_rate_limit_exhausted(self, mock_dynamodb):
        """Pipeline is unhealthy when GitHub rate limit usage exceeds 90%."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            # 3800 / 4000 = 95% usage -> unhealthy
            with patch.dict(sys.modules, {
                "package_collector": MagicMock(
                    _get_rate_limit_window_key=lambda: "2024-01-01-12",
                    _get_total_github_calls=lambda k: 3800,
                    GITHUB_HOURLY_LIMIT=4000,
                )
            }):
                response = pipeline_health.handler({}, {})

        assert response["statusCode"] == 503
        body = json.loads(response["body"])
        assert body["status"] == "unhealthy"
        assert body["checks"]["github_rate_limit"]["status"] == "unhealthy"
        assert body["checks"]["github_rate_limit"]["usage_percent"] == 95.0


# =============================================================================
# GITHUB RATE LIMIT TESTS
# =============================================================================


class TestGitHubRateLimitCheck:
    """Tests for GitHub rate limit monitoring."""

    @mock_aws
    def test_github_rate_limit_healthy(self, mock_dynamodb):
        """GitHub rate limit check is healthy when usage is below 75%."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            # 2000 / 4000 = 50% usage -> healthy
            with patch.dict(sys.modules, {
                "package_collector": MagicMock(
                    _get_rate_limit_window_key=lambda: "2024-01-01-12",
                    _get_total_github_calls=lambda k: 2000,
                    GITHUB_HOURLY_LIMIT=4000,
                )
            }):
                response = pipeline_health.handler({}, {})

        body = json.loads(response["body"])
        assert body["checks"]["github_rate_limit"]["status"] == "healthy"
        assert body["checks"]["github_rate_limit"]["calls"] == 2000
        assert body["checks"]["github_rate_limit"]["limit"] == 4000
        assert body["checks"]["github_rate_limit"]["usage_percent"] == 50.0

    @mock_aws
    def test_github_rate_limit_error_handling(self, mock_dynamodb):
        """GitHub rate limit check handles errors gracefully."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            # Mock import error for package_collector
            def raise_import_error():
                raise ImportError("Module not found")

            # Patch the import in the handler
            original_handler = pipeline_health.handler

            def handler_with_import_error(event, context):
                # Temporarily make the import fail
                import builtins
                original_import = builtins.__import__

                def mock_import(name, *args, **kwargs):
                    if name == "package_collector":
                        raise ImportError("Module not found")
                    return original_import(name, *args, **kwargs)

                builtins.__import__ = mock_import
                try:
                    result = original_handler(event, context)
                finally:
                    builtins.__import__ = original_import
                return result

            with patch.object(pipeline_health, "handler", handler_with_import_error):
                response = handler_with_import_error({}, {})

        body = json.loads(response["body"])
        assert body["checks"]["github_rate_limit"]["status"] == "error"
        assert "error" in body["checks"]["github_rate_limit"]


# =============================================================================
# CLOUDWATCH METRICS TESTS
# =============================================================================


class TestCloudWatchMetrics:
    """Tests for CloudWatch metrics emission."""

    @mock_aws
    def test_metrics_emitted_on_healthy_check(self, mock_dynamodb):
        """CloudWatch metrics are emitted during health check."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        _cloudwatch = boto3.client("cloudwatch", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
            "CLOUDWATCH_NAMESPACE": "PkgWatch-Test",
        }):
            pipeline_health = reload_pipeline_health()

            # Track emit_metric calls
            _emit_calls = []
            _original_emit = None

            # We need to patch the emit_metric in the metrics module
            with patch("shared.metrics.emit_metric") as mock_emit:
                # Also patch it where it's imported
                with patch.object(pipeline_health, "emit_metric", mock_emit):
                    with patch.dict(sys.modules, {
                        "package_collector": MagicMock(
                            _get_rate_limit_window_key=lambda: "2024-01-01-12",
                            _get_total_github_calls=lambda k: 100,
                            GITHUB_HOURLY_LIMIT=4000,
                        )
                    }):
                        _response = pipeline_health.handler({}, {})

                        # Verify emit_metric was called
                        assert mock_emit.call_count >= 3
                        # Check for expected metrics
                        metric_names = [call[0][0] for call in mock_emit.call_args_list]
                        assert "QueueDepth" in metric_names
                        assert "DLQDepth" in metric_names
                        assert "HealthStatus" in metric_names

    @mock_aws
    def test_metrics_continue_on_emit_failure(self, mock_dynamodb):
        """Health check continues even if metrics emission fails."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            # Make emit_metric raise an error
            def failing_emit(*args, **kwargs):
                raise Exception("CloudWatch unavailable")

            with patch.object(pipeline_health, "emit_metric", failing_emit):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    # Should not raise, health check should complete
                    response = pipeline_health.handler({}, {})

        # Health check should still complete successfully
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "status" in body

    @mock_aws
    def test_health_status_metric_value(self, mock_dynamodb):
        """HealthStatus metric is 1 for healthy, 0 for unhealthy."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            emit_calls = []

            def track_emit(metric_name, value=1, **kwargs):
                emit_calls.append((metric_name, value))

            with patch.object(pipeline_health, "emit_metric", track_emit):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    _response = pipeline_health.handler({}, {})

            # Find HealthStatus metric call
            health_calls = [(name, val) for name, val in emit_calls if name == "HealthStatus"]
            assert len(health_calls) == 1
            assert health_calls[0][1] == 1  # Healthy = 1


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================


class TestErrorHandling:
    """Tests for error handling scenarios."""

    @mock_aws
    def test_handles_missing_queue_url(self, mock_dynamodb):
        """Handler handles missing PACKAGE_QUEUE_URL gracefully."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        # Set only DLQ URL, not main queue
        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": "",  # Empty URL
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }, clear=False):
            pipeline_health = reload_pipeline_health()
            pipeline_health.QUEUE_URL = None  # Simulate missing env var

            with patch.dict(sys.modules, {
                "package_collector": MagicMock(
                    _get_rate_limit_window_key=lambda: "2024-01-01-12",
                    _get_total_github_calls=lambda k: 100,
                    GITHUB_HOURLY_LIMIT=4000,
                )
            }):
                response = pipeline_health.handler({}, {})

        # Should return error status for main queue
        assert response["statusCode"] == 503
        body = json.loads(response["body"])
        assert body["status"] == "unhealthy"
        assert body["checks"]["main_queue"]["status"] == "error"

    @mock_aws
    def test_handles_dlq_error(self, mock_dynamodb):
        """Handler handles DLQ check errors gracefully."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            call_count = [0]

            def mock_get_attrs(QueueUrl, AttributeNames):
                call_count[0] += 1
                if call_count[0] == 1:  # First call is main queue
                    return {
                        "Attributes": {
                            "ApproximateNumberOfMessages": "100",
                            "ApproximateNumberOfMessagesNotVisible": "10",
                        }
                    }
                # Second call is DLQ - raise error
                raise Exception("DLQ not accessible")

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

        body = json.loads(response["body"])
        # Main queue should still be healthy
        assert body["checks"]["main_queue"]["status"] == "healthy"
        # DLQ should show error
        assert body["checks"]["dlq"]["status"] == "error"
        assert "DLQ not accessible" in body["checks"]["dlq"]["error"]

    @mock_aws
    def test_handles_permission_error(self, mock_dynamodb):
        """Handler handles AWS permission errors gracefully."""
        from botocore.exceptions import ClientError

        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            def mock_get_attrs(QueueUrl, AttributeNames):
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
                    "GetQueueAttributes",
                )

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

        assert response["statusCode"] == 503
        body = json.loads(response["body"])
        assert body["status"] == "unhealthy"
        assert body["checks"]["main_queue"]["status"] == "error"


# =============================================================================
# EDGE CASES TESTS
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    @mock_aws
    def test_response_includes_timestamp(self, mock_dynamodb):
        """Response includes ISO format timestamp."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            with patch.dict(sys.modules, {
                "package_collector": MagicMock(
                    _get_rate_limit_window_key=lambda: "2024-01-01-12",
                    _get_total_github_calls=lambda k: 100,
                    GITHUB_HOURLY_LIMIT=4000,
                )
            }):
                response = pipeline_health.handler({}, {})

        body = json.loads(response["body"])
        assert "timestamp" in body
        # Verify it's a valid ISO timestamp
        datetime.fromisoformat(body["timestamp"].replace("Z", "+00:00"))

    @mock_aws
    def test_response_has_correct_content_type(self, mock_dynamodb):
        """Response has JSON content type header."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            with patch.dict(sys.modules, {
                "package_collector": MagicMock(
                    _get_rate_limit_window_key=lambda: "2024-01-01-12",
                    _get_total_github_calls=lambda k: 100,
                    GITHUB_HOURLY_LIMIT=4000,
                )
            }):
                response = pipeline_health.handler({}, {})

        assert response["headers"]["Content-Type"] == "application/json"

    @mock_aws
    def test_in_flight_messages_tracked(self, mock_dynamodb):
        """In-flight messages are tracked in queue check."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            def mock_get_attrs(QueueUrl, AttributeNames):
                if "ApproximateNumberOfMessagesNotVisible" in AttributeNames:
                    return {
                        "Attributes": {
                            "ApproximateNumberOfMessages": "50",
                            "ApproximateNumberOfMessagesNotVisible": "25",
                        }
                    }
                return {
                    "Attributes": {
                        "ApproximateNumberOfMessages": "0",
                    }
                }

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

        body = json.loads(response["body"])
        assert body["checks"]["main_queue"]["in_flight"] == 25

    @mock_aws
    def test_queue_depth_boundary_999_healthy(self, mock_dynamodb):
        """Queue depth 999 is healthy (below 1000 threshold)."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()
            captured_queue_url = pipeline_health.QUEUE_URL

            def mock_get_attrs(QueueUrl, AttributeNames):
                if QueueUrl == captured_queue_url:
                    return {
                        "Attributes": {
                            "ApproximateNumberOfMessages": "999",
                            "ApproximateNumberOfMessagesNotVisible": "0",
                        }
                    }
                return {
                    "Attributes": {
                        "ApproximateNumberOfMessages": "0",
                    }
                }

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

            body = json.loads(response["body"])
            assert body["checks"]["main_queue"]["status"] == "healthy"
            assert body["checks"]["main_queue"]["depth"] == 999

    @mock_aws
    def test_queue_depth_boundary_1000_degraded(self, mock_dynamodb):
        """Queue depth 1000 is degraded (at threshold)."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()
            captured_queue_url = pipeline_health.QUEUE_URL

            def mock_get_attrs(QueueUrl, AttributeNames):
                if QueueUrl == captured_queue_url:
                    return {
                        "Attributes": {
                            "ApproximateNumberOfMessages": "1000",
                            "ApproximateNumberOfMessagesNotVisible": "0",
                        }
                    }
                return {
                    "Attributes": {
                        "ApproximateNumberOfMessages": "0",
                    }
                }

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

            body = json.loads(response["body"])
            assert body["checks"]["main_queue"]["status"] == "degraded"
            assert body["checks"]["main_queue"]["depth"] == 1000

    @mock_aws
    def test_dlq_depth_boundary_9_healthy(self, mock_dynamodb):
        """DLQ depth 9 is healthy (below 10 threshold)."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()
            _captured_queue_url = pipeline_health.QUEUE_URL
            captured_dlq_url = pipeline_health.DLQ_URL

            def mock_get_attrs(QueueUrl, AttributeNames):
                if QueueUrl == captured_dlq_url:
                    return {
                        "Attributes": {
                            "ApproximateNumberOfMessages": "9",
                        }
                    }
                return {
                    "Attributes": {
                        "ApproximateNumberOfMessages": "0",
                        "ApproximateNumberOfMessagesNotVisible": "0",
                    }
                }

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

            body = json.loads(response["body"])
            assert body["checks"]["dlq"]["status"] == "healthy"
            assert body["checks"]["dlq"]["depth"] == 9

    @mock_aws
    def test_dlq_depth_boundary_10_degraded(self, mock_dynamodb):
        """DLQ depth 10 is degraded (at threshold)."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()
            captured_dlq_url = pipeline_health.DLQ_URL

            def mock_get_attrs(QueueUrl, AttributeNames):
                if QueueUrl == captured_dlq_url:
                    return {
                        "Attributes": {
                            "ApproximateNumberOfMessages": "10",
                        }
                    }
                return {
                    "Attributes": {
                        "ApproximateNumberOfMessages": "0",
                        "ApproximateNumberOfMessagesNotVisible": "0",
                    }
                }

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

            body = json.loads(response["body"])
            assert body["checks"]["dlq"]["status"] == "degraded"
            assert body["checks"]["dlq"]["depth"] == 10

    @mock_aws
    def test_dlq_depth_boundary_100_unhealthy(self, mock_dynamodb):
        """DLQ depth 100 is unhealthy (at threshold)."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()
            captured_dlq_url = pipeline_health.DLQ_URL

            def mock_get_attrs(QueueUrl, AttributeNames):
                if QueueUrl == captured_dlq_url:
                    return {
                        "Attributes": {
                            "ApproximateNumberOfMessages": "100",
                        }
                    }
                return {
                    "Attributes": {
                        "ApproximateNumberOfMessages": "0",
                        "ApproximateNumberOfMessagesNotVisible": "0",
                    }
                }

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

            body = json.loads(response["body"])
            assert body["checks"]["dlq"]["status"] == "unhealthy"
            assert body["checks"]["dlq"]["depth"] == 100
            assert body["status"] == "unhealthy"

    @mock_aws
    def test_github_rate_limit_74_percent_healthy(self, mock_dynamodb):
        """GitHub rate limit at 74.975% (2999/4000) is healthy."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            with patch.dict(sys.modules, {
                "package_collector": MagicMock(
                    _get_rate_limit_window_key=lambda: "2024-01-01-12",
                    _get_total_github_calls=lambda k: 2999,
                    GITHUB_HOURLY_LIMIT=4000,
                )
            }):
                response = pipeline_health.handler({}, {})

            body = json.loads(response["body"])
            assert body["checks"]["github_rate_limit"]["status"] == "healthy"

    @mock_aws
    def test_github_rate_limit_75_percent_degraded(self, mock_dynamodb):
        """GitHub rate limit at 75% (3000/4000) is degraded."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            with patch.dict(sys.modules, {
                "package_collector": MagicMock(
                    _get_rate_limit_window_key=lambda: "2024-01-01-12",
                    _get_total_github_calls=lambda k: 3000,
                    GITHUB_HOURLY_LIMIT=4000,
                )
            }):
                response = pipeline_health.handler({}, {})

            body = json.loads(response["body"])
            assert body["checks"]["github_rate_limit"]["status"] == "degraded"

    @mock_aws
    def test_github_rate_limit_90_percent_unhealthy(self, mock_dynamodb):
        """GitHub rate limit at 90% (3600/4000) is unhealthy."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            with patch.dict(sys.modules, {
                "package_collector": MagicMock(
                    _get_rate_limit_window_key=lambda: "2024-01-01-12",
                    _get_total_github_calls=lambda k: 3600,
                    GITHUB_HOURLY_LIMIT=4000,
                )
            }):
                response = pipeline_health.handler({}, {})

            body = json.loads(response["body"])
            assert body["checks"]["github_rate_limit"]["status"] == "unhealthy"
            assert body["status"] == "unhealthy"


# =============================================================================
# STATUS PRIORITY TESTS
# =============================================================================


class TestStatusPriority:
    """Tests for status priority (unhealthy > degraded > healthy)."""

    @mock_aws
    def test_unhealthy_overrides_degraded(self, mock_dynamodb):
        """Unhealthy status takes precedence over degraded."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()
            captured_queue_url = pipeline_health.QUEUE_URL
            _captured_dlq_url = pipeline_health.DLQ_URL

            # Main queue is degraded (1500 depth)
            # DLQ is unhealthy (150 depth)
            def mock_get_attrs(QueueUrl, AttributeNames):
                if QueueUrl == captured_queue_url:
                    return {
                        "Attributes": {
                            "ApproximateNumberOfMessages": "1500",  # Degraded
                            "ApproximateNumberOfMessagesNotVisible": "0",
                        }
                    }
                return {
                    "Attributes": {
                        "ApproximateNumberOfMessages": "150",  # Unhealthy
                    }
                }

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

            body = json.loads(response["body"])
            # Overall status should be unhealthy (from DLQ)
            assert body["status"] == "unhealthy"
            assert body["checks"]["main_queue"]["status"] == "degraded"
            assert body["checks"]["dlq"]["status"] == "unhealthy"

    @mock_aws
    def test_degraded_does_not_override_unhealthy(self, mock_dynamodb):
        """Degraded status does not override existing unhealthy."""
        sqs = boto3.client("sqs", region_name="us-east-1")
        main_queue_url = sqs.create_queue(QueueName="test-package-queue")["QueueUrl"]
        dlq_url = sqs.create_queue(QueueName="test-dlq")["QueueUrl"]

        with patch.dict(os.environ, {
            "PACKAGE_QUEUE_URL": main_queue_url,
            "DLQ_URL": dlq_url,
            "API_KEYS_TABLE": "pkgwatch-api-keys",
        }):
            pipeline_health = reload_pipeline_health()

            # Main queue error (sets unhealthy first)
            # DLQ is degraded (50 depth)
            call_count = [0]

            def mock_get_attrs(QueueUrl, AttributeNames):
                call_count[0] += 1
                if call_count[0] == 1:  # Main queue - error
                    raise Exception("Queue not found")
                return {
                    "Attributes": {
                        "ApproximateNumberOfMessages": "50",  # Degraded
                    }
                }

            with patch.object(pipeline_health.sqs, "get_queue_attributes", side_effect=mock_get_attrs):
                with patch.dict(sys.modules, {
                    "package_collector": MagicMock(
                        _get_rate_limit_window_key=lambda: "2024-01-01-12",
                        _get_total_github_calls=lambda k: 100,
                        GITHUB_HOURLY_LIMIT=4000,
                    )
                }):
                    response = pipeline_health.handler({}, {})

        body = json.loads(response["body"])
        # Overall status should remain unhealthy (from main queue error)
        assert body["status"] == "unhealthy"
        assert body["checks"]["main_queue"]["status"] == "error"
        assert body["checks"]["dlq"]["status"] == "degraded"
