"""
CloudWatch Metrics Helper

Provides utilities for emitting custom metrics to CloudWatch.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import boto3

logger = logging.getLogger(__name__)

cloudwatch = boto3.client("cloudwatch")

NAMESPACE = os.environ.get("CLOUDWATCH_NAMESPACE", "DepHealth")


def emit_metric(
    metric_name: str,
    value: float = 1.0,
    unit: str = "Count",
    dimensions: Optional[Dict[str, str]] = None,
) -> None:
    """
    Emit a custom metric to CloudWatch.

    Args:
        metric_name: Name of the metric
        value: Metric value (default: 1.0)
        unit: Unit of measurement (Count, Seconds, Bytes, etc.)
        dimensions: Optional dimensions for filtering metrics

    Example:
        emit_metric("PackagesCollected", dimensions={"Ecosystem": "npm"})
        emit_metric("BatchProcessingTime", 2.5, unit="Seconds")
    """
    try:
        metric_data = {
            "MetricName": metric_name,
            "Value": value,
            "Unit": unit,
            "Timestamp": datetime.now(timezone.utc),
        }

        if dimensions:
            metric_data["Dimensions"] = [
                {"Name": k, "Value": v} for k, v in dimensions.items()
            ]

        cloudwatch.put_metric_data(
            Namespace=NAMESPACE,
            MetricData=[metric_data],
        )

        logger.debug(
            f"Emitted metric: {metric_name}={value} {unit}",
            extra={"dimensions": dimensions},
        )

    except Exception as e:
        # Don't fail the Lambda if metrics fail
        logger.warning(f"Failed to emit metric {metric_name}: {e}")


def emit_batch_metrics(metrics: list[Dict[str, Any]]) -> None:
    """
    Emit multiple metrics in a single API call.

    Args:
        metrics: List of metric dictionaries with keys:
            - metric_name (str)
            - value (float)
            - unit (str, optional)
            - dimensions (dict, optional)

    Example:
        emit_batch_metrics([
            {"metric_name": "Successes", "value": 10},
            {"metric_name": "Failures", "value": 2},
        ])
    """
    try:
        metric_data = []

        for metric in metrics:
            data = {
                "MetricName": metric["metric_name"],
                "Value": metric.get("value", 1.0),
                "Unit": metric.get("unit", "Count"),
                "Timestamp": datetime.now(timezone.utc),
            }

            dimensions = metric.get("dimensions")
            if dimensions:
                data["Dimensions"] = [
                    {"Name": k, "Value": v} for k, v in dimensions.items()
                ]

            metric_data.append(data)

        # CloudWatch allows up to 20 metrics per request
        for i in range(0, len(metric_data), 20):
            batch = metric_data[i : i + 20]
            cloudwatch.put_metric_data(
                Namespace=NAMESPACE,
                MetricData=batch,
            )

        logger.debug(f"Emitted {len(metric_data)} metrics in batch")

    except Exception as e:
        # Don't fail the Lambda if metrics fail
        logger.warning(f"Failed to emit batch metrics: {e}")


def emit_error_metric(
    error_type: str,
    service: Optional[str] = None,
    handler: Optional[str] = None,
) -> None:
    """
    Emit an error metric with standard dimensions.

    Args:
        error_type: Type of error (e.g., 'rate_limit', 'timeout', 'internal')
        service: External service name (e.g., 'github', 'npm')
        handler: Lambda handler name
    """
    dimensions = {"ErrorType": error_type}

    if service:
        dimensions["Service"] = service
    if handler:
        dimensions["Handler"] = handler

    emit_metric("Errors", dimensions=dimensions)


def emit_circuit_breaker_metric(
    circuit_name: str,
    state: str,
) -> None:
    """Emit circuit breaker state change metric."""
    emit_metric(
        "CircuitBreakerStateChange",
        dimensions={
            "CircuitName": circuit_name,
            "State": state,
        }
    )


def emit_dlq_metric(
    action: str,
    package_name: Optional[str] = None,
) -> None:
    """
    Emit DLQ processing metric.

    Args:
        action: 'requeued', 'permanent_failure', 'processed'
        package_name: Name of package (optional)
    """
    dimensions = {"Action": action}
    if package_name:
        dimensions["Package"] = package_name[:50]  # Truncate for dimension limit

    emit_metric("DLQProcessing", dimensions=dimensions)
