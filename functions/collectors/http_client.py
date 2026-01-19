"""
Shared HTTP Client with Connection Pooling.

Provides a reusable httpx.AsyncClient that is shared across collectors
to enable connection reuse and reduce connection overhead.

Benefits:
- Connection pooling reduces TLS handshake overhead
- Keep-alive connections improve latency
- Consistent timeout and retry configuration
- Single point of configuration for HTTP behavior

Usage:
    from http_client import get_http_client

    async def my_collector():
        client = get_http_client()
        response = await client.get("https://api.example.com/data")

Testing:
    Set USE_CONNECTION_POOLING=false in test fixtures to disable connection
    pooling. This creates a new client per call for test isolation.

Resource Management:
    - Production (USE_CONNECTION_POOLING=true): A shared client is lazily
      initialized and reused. Connections are managed automatically. The
      client is closed during Lambda execution context cleanup.

    - Tests (USE_CONNECTION_POOLING=false): A new client is created per
      call to get_http_client(). While httpx doesn't require explicit
      cleanup for short-lived clients (connections are released when the
      request completes), pytest may warn about unclosed clients. This is
      acceptable in tests and does not indicate a production resource leak.

    - get_http_client_with_headers(): Always creates a new client with
      custom headers. In Lambda's short execution context, the client is
      cleaned up when the execution context is recycled. For long-running
      processes, use as a context manager:

          async with get_http_client_with_headers(headers) as client:
              response = await client.get(url)
"""

import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Global client instance (lazy-initialized)
_client: Optional[httpx.AsyncClient] = None

# Configuration
DEFAULT_TIMEOUT = httpx.Timeout(
    30.0,  # Total timeout
    connect=10.0,  # Connection timeout
)

DEFAULT_LIMITS = httpx.Limits(
    max_connections=100,  # Max total connections
    max_keepalive_connections=20,  # Max idle connections to keep
    keepalive_expiry=30.0,  # Seconds before closing idle connections
)

def _use_connection_pooling() -> bool:
    """Check if connection pooling is enabled (runtime check)."""
    return os.environ.get("USE_CONNECTION_POOLING", "true").lower() == "true"


def get_http_client() -> httpx.AsyncClient:
    """
    Get an HTTP client for making requests.

    In production (USE_CONNECTION_POOLING=true):
        Returns a shared client with connection pooling for better performance.

    In tests (USE_CONNECTION_POOLING=false):
        Creates a new client per call to allow proper test isolation.

    Returns:
        httpx.AsyncClient configured for the environment
    """
    global _client

    if not _use_connection_pooling():
        # Create new client per call (allows mocking in tests)
        return httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            limits=DEFAULT_LIMITS,
            follow_redirects=True,
            http2=False,
        )

    if _client is None:
        logger.debug("Initializing shared HTTP client with connection pooling")
        _client = httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            limits=DEFAULT_LIMITS,
            follow_redirects=True,
            http2=False,  # HTTP/1.1 for compatibility (some APIs don't support HTTP/2)
        )

    return _client


async def close_http_client() -> None:
    """
    Close the shared HTTP client.

    Should be called during Lambda cleanup if needed, though Lambda's
    execution context cleanup will handle this automatically.
    """
    global _client

    if _client is not None:
        await _client.aclose()
        _client = None
        logger.debug("Closed shared HTTP client")


def get_http_client_with_headers(headers: dict) -> httpx.AsyncClient:
    """
    Get a new HTTP client with custom default headers.

    Use this when you need service-specific headers (e.g., auth tokens).
    The returned client still benefits from connection pooling.

    Args:
        headers: Default headers to include in all requests

    Returns:
        httpx.AsyncClient with custom headers
    """
    return httpx.AsyncClient(
        timeout=DEFAULT_TIMEOUT,
        limits=DEFAULT_LIMITS,
        follow_redirects=True,
        http2=False,
        headers=headers,
    )
