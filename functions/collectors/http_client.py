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

import asyncio
import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Global client instance (lazy-initialized)
_client: Optional[httpx.AsyncClient] = None
_client_loop_id: Optional[int] = None  # Track which event loop the client was created on

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
        The client is recreated if the event loop changes (Lambda creates new
        loops between invocations while reusing execution context).

    In tests (USE_CONNECTION_POOLING=false):
        Creates a new client per call to allow proper test isolation.

    Returns:
        httpx.AsyncClient configured for the environment
    """
    global _client, _client_loop_id

    if not _use_connection_pooling():
        # Create new client per call (allows mocking in tests)
        return httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            limits=DEFAULT_LIMITS,
            follow_redirects=True,
            http2=False,
        )

    # Check if we need to recreate the client due to event loop change
    # Lambda creates a new event loop per invocation but may reuse execution context
    try:
        current_loop_id = id(asyncio.get_running_loop())
    except RuntimeError:
        # No running loop - will be created when async code runs
        current_loop_id = None

    if _client is not None and _client_loop_id != current_loop_id:
        logger.debug("Event loop changed, recreating HTTP client")
        # Don't await close() here as we may not be in async context
        # The old client will be garbage collected
        _client = None

    if _client is None:
        logger.debug("Initializing shared HTTP client with connection pooling")
        _client = httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            limits=DEFAULT_LIMITS,
            follow_redirects=True,
            http2=False,  # HTTP/1.1 for compatibility (some APIs don't support HTTP/2)
        )
        _client_loop_id = current_loop_id

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

    Note: For GitHub API calls, prefer get_github_client() which caches
    clients by token hash for connection reuse across calls.

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


# Cached GitHub clients, keyed by token hash
# This enables connection reuse across GitHub API calls while handling token rotation
_github_clients: dict[str, httpx.AsyncClient] = {}
_github_client_loop_ids: dict[str, int] = {}


def get_github_client(headers: dict) -> httpx.AsyncClient:
    """
    Get a cached HTTP client for GitHub API with connection pooling.

    Unlike get_http_client_with_headers() which creates a new client per call,
    this caches clients by token hash. This enables:
    - Connection reuse across multiple GitHub API calls in the same Lambda invocation
    - Proper handling of token rotation (new token = new client)
    - Reduced TLS handshake overhead

    Args:
        headers: Headers including Authorization token

    Returns:
        httpx.AsyncClient configured for GitHub API
    """
    global _github_clients, _github_client_loop_ids

    if not _use_connection_pooling():
        # In tests, create new client per call for isolation
        return httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            limits=DEFAULT_LIMITS,
            follow_redirects=True,
            http2=False,
            headers=headers,
        )

    # Create a cache key from the Authorization header (or empty string if none)
    # Use hash to avoid storing tokens in memory as plain text
    import hashlib

    auth_header = headers.get("Authorization", "")
    token_hash = hashlib.sha256(auth_header.encode()).hexdigest()[:16]

    # Check if we need to recreate due to event loop change
    try:
        current_loop_id = id(asyncio.get_running_loop())
    except RuntimeError:
        current_loop_id = None

    # Check if existing client is on a different event loop
    if token_hash in _github_clients:
        if _github_client_loop_ids.get(token_hash) != current_loop_id:
            logger.debug("Event loop changed, recreating GitHub client")
            del _github_clients[token_hash]
            del _github_client_loop_ids[token_hash]

    # Create new client if needed
    if token_hash not in _github_clients:
        logger.debug("Creating cached GitHub client")
        _github_clients[token_hash] = httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            limits=DEFAULT_LIMITS,
            follow_redirects=True,
            http2=False,
            headers=headers,
        )
        _github_client_loop_ids[token_hash] = current_loop_id

    return _github_clients[token_hash]
