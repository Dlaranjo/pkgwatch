"""Shared request utilities for API handlers."""

import logging

logger = logging.getLogger(__name__)


def get_client_ip(event: dict) -> str:
    """Extract client IP from API Gateway's verified source.

    SECURITY: Always use requestContext.identity.sourceIp which is set by
    API Gateway and cannot be spoofed by clients. Never trust X-Forwarded-For
    header for rate limiting as it can be forged.
    """
    # Use API Gateway's verified source IP (cannot be spoofed)
    source_ip = event.get("requestContext", {}).get("identity", {}).get("sourceIp")
    if source_ip:
        return source_ip

    # Log warning if missing (shouldn't happen with proper API Gateway config)
    logger.warning("Missing sourceIp in requestContext - possible misconfiguration")
    return "unknown"
