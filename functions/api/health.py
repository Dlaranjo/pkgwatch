"""
Health Check Endpoint - GET /health

Returns API status and version information.
No authentication required.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone

# Import structured logging utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from shared.logging_utils import configure_structured_logging, set_request_id, log_api_request

# Configure structured logging
logger = configure_structured_logging()


def handler(event, context):
    """
    Lambda handler for health check.

    Returns:
        200 with status information
    """
    start_time = time.time()

    # Set request ID for logging correlation
    set_request_id(event)

    response = {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-cache",
        },
        "body": json.dumps({
            "status": "healthy",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }),
    }

    # Log the request
    latency_ms = (time.time() - start_time) * 1000
    log_api_request(logger, "GET", "/health", 200, latency_ms)

    return response
