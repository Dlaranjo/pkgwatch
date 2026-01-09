"""
Structured logging utilities for CloudWatch Logs Insights.
"""

import json
import logging
import os
from contextvars import ContextVar
from typing import Optional, Any, Dict
import uuid

# Context variable for request correlation
request_id_var: ContextVar[str] = ContextVar("request_id", default="")


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get(""),
            "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME", ""),
        }

        # Add extra fields
        if hasattr(record, "__dict__"):
            for key, value in record.__dict__.items():
                if key not in (
                    "name", "msg", "args", "created", "filename", "funcName",
                    "levelname", "levelno", "lineno", "module", "msecs",
                    "pathname", "process", "processName", "relativeCreated",
                    "stack_info", "exc_info", "exc_text", "thread", "threadName",
                    "message", "asctime",
                ):
                    log_entry[key] = value

        # Add exception info
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


def configure_structured_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Configure structured JSON logging for Lambda.

    Call this at the start of your handler.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add structured handler
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredFormatter())
    root_logger.addHandler(handler)

    return root_logger


def set_request_id(event: dict) -> str:
    """
    Extract or generate request ID and set in context.

    Args:
        event: Lambda event

    Returns:
        Request ID string
    """
    # Try API Gateway request ID
    request_id = event.get("requestContext", {}).get("requestId")

    # Try X-Request-Id header
    if not request_id:
        headers = event.get("headers") or {}
        request_id = headers.get("x-request-id") or headers.get("X-Request-Id")

    # Generate if not present
    if not request_id:
        request_id = str(uuid.uuid4())

    request_id_var.set(request_id)
    return request_id


def log_api_request(
    logger: logging.Logger,
    method: str,
    path: str,
    status_code: int,
    latency_ms: float,
    user_id: Optional[str] = None,
) -> None:
    """Log API request with standard fields."""
    logger.info(
        f"{method} {path} -> {status_code}",
        extra={
            "http_method": method,
            "path": path,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "user_id": user_id or "anonymous",
        }
    )


def log_external_call(
    logger: logging.Logger,
    service: str,
    operation: str,
    success: bool,
    latency_ms: float,
    error: Optional[str] = None,
) -> None:
    """Log external service call."""
    level = logging.INFO if success else logging.WARNING
    logger.log(
        level,
        f"External call to {service}: {operation} -> {'success' if success else 'failed'}",
        extra={
            "service": service,
            "operation": operation,
            "success": success,
            "latency_ms": latency_ms,
            "error": error,
        }
    )
