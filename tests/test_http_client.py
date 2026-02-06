"""
Tests for HTTP client with connection pooling.

Tests cover:
- Connection pooling behavior (enabled/disabled via environment)
- Event loop handling (Lambda reuse scenarios)
- Client configuration (timeouts, limits, redirects)
- close_http_client() cleanup function
- get_http_client_with_headers() custom header support

Run with: PYTHONPATH=functions:. pytest tests/test_http_client.py -v
"""

import asyncio
import os
import sys
from unittest.mock import patch

import httpx
import pytest

# Add functions directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions", "collectors"))


def run_async(coro):
    """Helper to run async functions in sync tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# =============================================================================
# CONNECTION POOLING CONFIGURATION TESTS
# =============================================================================


class TestConnectionPoolingConfiguration:
    """Tests for USE_CONNECTION_POOLING environment variable behavior."""

    def test_pooling_disabled_by_default_in_tests(self):
        """Connection pooling is disabled by conftest.py for test isolation."""
        # conftest.py sets USE_CONNECTION_POOLING=false
        from http_client import _use_connection_pooling

        assert _use_connection_pooling() is False

    def test_pooling_enabled_when_env_true(self):
        """Connection pooling enabled when USE_CONNECTION_POOLING=true."""
        from http_client import _use_connection_pooling

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
            assert _use_connection_pooling() is True

    def test_pooling_enabled_case_insensitive(self):
        """USE_CONNECTION_POOLING check is case insensitive."""
        from http_client import _use_connection_pooling

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "TRUE"}):
            assert _use_connection_pooling() is True
        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "True"}):
            assert _use_connection_pooling() is True

    def test_pooling_disabled_when_env_false(self):
        """Connection pooling disabled when USE_CONNECTION_POOLING=false."""
        from http_client import _use_connection_pooling

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "false"}):
            assert _use_connection_pooling() is False

    def test_pooling_disabled_for_invalid_value(self):
        """Connection pooling disabled for invalid environment values."""
        from http_client import _use_connection_pooling

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "invalid"}):
            assert _use_connection_pooling() is False
        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": ""}):
            assert _use_connection_pooling() is False


# =============================================================================
# CLIENT CREATION TESTS (POOLING DISABLED)
# =============================================================================


class TestGetHttpClientPoolingDisabled:
    """Tests for get_http_client when connection pooling is disabled."""

    def test_creates_new_client_each_call(self):
        """Each call creates a new client when pooling is disabled."""
        from http_client import get_http_client

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "false"}):
            client1 = get_http_client()
            client2 = get_http_client()

            # Different instances
            assert client1 is not client2
            assert isinstance(client1, httpx.AsyncClient)
            assert isinstance(client2, httpx.AsyncClient)

    def test_client_has_correct_timeout(self):
        """Client has correct timeout configuration."""
        from http_client import DEFAULT_TIMEOUT, get_http_client

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "false"}):
            client = get_http_client()
            assert client.timeout.read == DEFAULT_TIMEOUT.read
            assert client.timeout.connect == DEFAULT_TIMEOUT.connect

    def test_client_follows_redirects(self):
        """Client is configured to follow redirects."""
        from http_client import get_http_client

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "false"}):
            client = get_http_client()
            assert client.follow_redirects is True


# =============================================================================
# CLIENT CREATION TESTS (POOLING ENABLED)
# =============================================================================


class TestGetHttpClientPoolingEnabled:
    """Tests for get_http_client when connection pooling is enabled."""

    def setup_method(self):
        """Reset global client state before each test."""
        import http_client

        http_client._client = None
        http_client._client_loop_id = None

    def teardown_method(self):
        """Clean up global client state after each test."""
        import http_client

        http_client._client = None
        http_client._client_loop_id = None

    def test_returns_same_client_within_same_loop(self):
        """Returns same client instance within the same event loop."""
        import http_client

        async def test_coro():
            # Enable pooling for this test
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
                client1 = http_client.get_http_client()
                client2 = http_client.get_http_client()
                return client1, client2

        client1, client2 = run_async(test_coro())
        assert client1 is client2

    def test_creates_new_client_on_event_loop_change(self):
        """Creates new client when event loop changes (Lambda reuse scenario)."""
        import http_client

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
            # First event loop
            async def first_loop():
                return http_client.get_http_client()

            _client1 = run_async(first_loop())
            first_client_id = id(http_client._client)

            # Simulate event loop change by manually setting a different loop ID
            # This mimics what happens when Lambda creates a new event loop
            original_loop_id = http_client._client_loop_id
            http_client._client_loop_id = original_loop_id + 1  # Force mismatch

            async def second_loop():
                return http_client.get_http_client()

            _client2 = run_async(second_loop())
            second_client_id = id(http_client._client)

            # Client should be recreated due to loop ID mismatch
            assert first_client_id != second_client_id

    def test_handles_no_running_loop(self):
        """Handles case when no event loop is running."""
        import http_client

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
            # Reset client state
            http_client._client = None
            http_client._client_loop_id = None

            # Call without running loop - should create client
            # Note: get_http_client() can be called outside async context
            # but the client won't work until used in async context
            client = http_client.get_http_client()
            assert isinstance(client, httpx.AsyncClient)
            # Loop ID should be None since no running loop
            assert http_client._client_loop_id is None

    def test_client_reused_after_creation(self):
        """Client is reused after initial creation in same loop."""
        import http_client

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
                clients = []
                for _ in range(5):
                    clients.append(http_client.get_http_client())
                return clients

        clients = run_async(test_coro())
        # All should be the same instance
        assert all(c is clients[0] for c in clients)


# =============================================================================
# CLOSE HTTP CLIENT TESTS
# =============================================================================


class TestCloseHttpClient:
    """Tests for close_http_client function."""

    def setup_method(self):
        """Reset global client state before each test."""
        import http_client

        http_client._client = None
        http_client._client_loop_id = None

    def teardown_method(self):
        """Clean up global client state after each test."""
        import http_client

        http_client._client = None
        http_client._client_loop_id = None

    def test_closes_existing_client(self):
        """Closes the shared client when it exists."""
        import http_client

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
                # Create client
                _client = http_client.get_http_client()
                assert http_client._client is not None

                # Close it
                await http_client.close_http_client()

                # Should be None after close
                assert http_client._client is None

        run_async(test_coro())

    def test_close_noop_when_no_client(self):
        """close_http_client is a no-op when no client exists."""
        import http_client

        async def test_coro():
            # No client exists
            assert http_client._client is None

            # Should not raise
            await http_client.close_http_client()

            # Still None
            assert http_client._client is None

        run_async(test_coro())

    def test_can_recreate_after_close(self):
        """Can create new client after closing existing one."""
        import http_client

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
                # Create, close, recreate
                _client1 = http_client.get_http_client()
                await http_client.close_http_client()
                client2 = http_client.get_http_client()

                # Should be a new instance
                assert client2 is not None
                assert isinstance(client2, httpx.AsyncClient)

        run_async(test_coro())


# =============================================================================
# GET HTTP CLIENT WITH HEADERS TESTS
# =============================================================================


class TestGetHttpClientWithHeaders:
    """Tests for get_http_client_with_headers function."""

    def test_creates_client_with_custom_headers(self):
        """Creates client with custom default headers."""
        from http_client import get_http_client_with_headers

        headers = {
            "Authorization": "Bearer test-token",
            "X-Custom-Header": "custom-value",
        }
        client = get_http_client_with_headers(headers)

        assert isinstance(client, httpx.AsyncClient)
        assert client.headers.get("Authorization") == "Bearer test-token"
        assert client.headers.get("X-Custom-Header") == "custom-value"

    def test_always_creates_new_client(self):
        """Always creates a new client (no pooling)."""
        from http_client import get_http_client_with_headers

        headers = {"X-Test": "value"}
        client1 = get_http_client_with_headers(headers)
        client2 = get_http_client_with_headers(headers)

        # Always new instances
        assert client1 is not client2

    def test_has_correct_timeout(self):
        """Client has correct timeout configuration."""
        from http_client import DEFAULT_TIMEOUT, get_http_client_with_headers

        client = get_http_client_with_headers({})
        assert client.timeout.read == DEFAULT_TIMEOUT.read
        assert client.timeout.connect == DEFAULT_TIMEOUT.connect

    def test_follows_redirects(self):
        """Client is configured to follow redirects."""
        from http_client import get_http_client_with_headers

        client = get_http_client_with_headers({})
        assert client.follow_redirects is True

    def test_uses_http1(self):
        """Client uses HTTP/1.1 (not HTTP/2)."""
        from http_client import get_http_client_with_headers

        client = get_http_client_with_headers({})
        # HTTP/2 disabled for compatibility
        assert client._transport._pool._http2 is False

    def test_empty_headers_dict(self):
        """Works with empty headers dict."""
        from http_client import get_http_client_with_headers

        client = get_http_client_with_headers({})
        assert isinstance(client, httpx.AsyncClient)


# =============================================================================
# DEFAULT CONFIGURATION TESTS
# =============================================================================


class TestDefaultConfiguration:
    """Tests for default timeout and limits configuration."""

    def test_default_timeout_values(self):
        """Verify default timeout configuration."""
        from http_client import DEFAULT_TIMEOUT

        # Total timeout is 30 seconds
        assert DEFAULT_TIMEOUT.read == 30.0
        # Connect timeout is 10 seconds
        assert DEFAULT_TIMEOUT.connect == 10.0

    def test_default_limits_values(self):
        """Verify default connection limits configuration."""
        from http_client import DEFAULT_LIMITS

        # Max total connections
        assert DEFAULT_LIMITS.max_connections == 100
        # Max keepalive connections
        assert DEFAULT_LIMITS.max_keepalive_connections == 20
        # Keepalive expiry
        assert DEFAULT_LIMITS.keepalive_expiry == 30.0


# =============================================================================
# INTEGRATION-STYLE TESTS (MOCK HTTP)
# =============================================================================


def create_mock_transport(handler):
    """Create a mock transport for httpx that routes requests to handler."""

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        return handler(request)

    return httpx.MockTransport(mock_handler)


class TestHttpClientIntegration:
    """Integration-style tests verifying client works for HTTP calls."""

    def test_successful_get_request(self):
        """Test client makes successful GET request."""
        from http_client import get_http_client

        def mock_handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "GET"
            return httpx.Response(200, json={"status": "ok"})

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "false"}):
                client = get_http_client()
                # Inject mock transport
                client._transport = create_mock_transport(mock_handler)
                response = await client.get("https://api.example.com/test")
                return response

        response = run_async(test_coro())
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_timeout_error_handling(self):
        """Test client properly raises timeout errors."""
        from http_client import get_http_client

        def mock_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Request timed out")

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "false"}):
                client = get_http_client()
                client._transport = create_mock_transport(mock_handler)
                return await client.get("https://api.example.com/timeout")

        with pytest.raises(httpx.ReadTimeout):
            run_async(test_coro())

    def test_connection_error_handling(self):
        """Test client properly raises connection errors."""
        from http_client import get_http_client

        def mock_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection failed")

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "false"}):
                client = get_http_client()
                client._transport = create_mock_transport(mock_handler)
                return await client.get("https://api.example.com/error")

        with pytest.raises(httpx.ConnectError):
            run_async(test_coro())

    def test_4xx_error_response(self):
        """Test client handles 4xx error responses."""
        from http_client import get_http_client

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": "Not found"})

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "false"}):
                client = get_http_client()
                client._transport = create_mock_transport(mock_handler)
                response = await client.get("https://api.example.com/missing")
                return response

        response = run_async(test_coro())
        assert response.status_code == 404

    def test_5xx_error_response(self):
        """Test client handles 5xx error responses."""
        from http_client import get_http_client

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"error": "Internal server error"})

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "false"}):
                client = get_http_client()
                client._transport = create_mock_transport(mock_handler)
                response = await client.get("https://api.example.com/error")
                return response

        response = run_async(test_coro())
        assert response.status_code == 500

    def test_redirect_following(self):
        """Test client follows redirects."""
        from http_client import get_http_client

        redirect_count = [0]

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "original" in url and redirect_count[0] == 0:
                redirect_count[0] += 1
                return httpx.Response(302, headers={"Location": "https://api.example.com/final"})
            return httpx.Response(200, json={"redirected": True})

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "false"}):
                client = get_http_client()
                client._transport = create_mock_transport(mock_handler)
                response = await client.get("https://api.example.com/original")
                return response

        response = run_async(test_coro())
        assert response.status_code == 200
        assert redirect_count[0] == 1

    def test_custom_headers_client(self):
        """Test client with custom headers sends them."""
        from http_client import get_http_client_with_headers

        received_headers = {}

        def mock_handler(request: httpx.Request) -> httpx.Response:
            received_headers.update(dict(request.headers))
            return httpx.Response(200, json={"ok": True})

        async def test_coro():
            client = get_http_client_with_headers(
                {
                    "Authorization": "Bearer secret-token",
                    "X-API-Key": "api-key-123",
                }
            )
            client._transport = create_mock_transport(mock_handler)
            response = await client.get("https://api.example.com/auth")
            return response

        response = run_async(test_coro())
        assert response.status_code == 200
        assert received_headers.get("authorization") == "Bearer secret-token"
        assert received_headers.get("x-api-key") == "api-key-123"


# =============================================================================
# CONCURRENT REQUEST TESTS
# =============================================================================


class TestConcurrentRequests:
    """Tests for concurrent request handling."""

    def test_multiple_concurrent_requests(self):
        """Test client handles multiple concurrent requests."""
        from http_client import get_http_client

        request_count = [0]

        def mock_handler(request: httpx.Request) -> httpx.Response:
            request_count[0] += 1
            return httpx.Response(200, json={"request": request_count[0]})

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "false"}):
                client = get_http_client()
                client._transport = create_mock_transport(mock_handler)

                # Make 5 concurrent requests
                tasks = [client.get(f"https://api.example.com/request/{i}") for i in range(5)]
                responses = await asyncio.gather(*tasks)
                return responses

        responses = run_async(test_coro())
        assert len(responses) == 5
        assert all(r.status_code == 200 for r in responses)
        assert request_count[0] == 5

    def test_pooled_client_concurrent_requests(self):
        """Test pooled client handles concurrent requests from same loop."""
        import http_client

        # Reset state
        http_client._client = None
        http_client._client_loop_id = None

        request_count = [0]

        def mock_handler(request: httpx.Request) -> httpx.Response:
            request_count[0] += 1
            return httpx.Response(200, json={"request": request_count[0]})

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
                client = http_client.get_http_client()
                client._transport = create_mock_transport(mock_handler)

                # Make concurrent requests - all should use same pooled client
                tasks = [client.get(f"https://api.example.com/request/{i}") for i in range(3)]
                responses = await asyncio.gather(*tasks)

                # Verify same client is returned
                client2 = http_client.get_http_client()
                assert client is client2

                return responses

        try:
            responses = run_async(test_coro())
            assert len(responses) == 3
            assert all(r.status_code == 200 for r in responses)
        finally:
            # Cleanup
            http_client._client = None
            http_client._client_loop_id = None


# =============================================================================
# EVENT LOOP EDGE CASES
# =============================================================================


class TestEventLoopEdgeCases:
    """Tests for event loop handling edge cases."""

    def setup_method(self):
        """Reset global client state before each test."""
        import http_client

        http_client._client = None
        http_client._client_loop_id = None

    def teardown_method(self):
        """Clean up global client state after each test."""
        import http_client

        http_client._client = None
        http_client._client_loop_id = None

    def test_loop_id_tracked_correctly(self):
        """Loop ID is tracked correctly when client is created."""
        import http_client

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
                client = http_client.get_http_client()
                loop = asyncio.get_running_loop()
                assert http_client._client_loop_id == id(loop)
                return client

        run_async(test_coro())

    def test_client_recreated_on_loop_mismatch(self):
        """Client is recreated when loop ID doesn't match."""
        import http_client

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
            # Simulate first invocation
            async def first_invocation():
                return http_client.get_http_client()

            _client1 = run_async(first_invocation())
            first_client = http_client._client

            # Simulate Lambda reuse - new invocation with new loop
            # Manually force loop ID mismatch (simulates what Lambda does)
            original_loop_id = http_client._client_loop_id
            http_client._client_loop_id = original_loop_id + 12345  # Different loop

            async def second_invocation():
                return http_client.get_http_client()

            _client2 = run_async(second_invocation())
            second_client = http_client._client

            # Client should be different since loop ID changed
            assert first_client is not second_client

    def test_client_none_when_loop_changes_outside_async(self):
        """Client is set to None when detected loop change outside async context."""
        import http_client

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
            # Create client in one loop
            async def create_client():
                return http_client.get_http_client()

            _client1 = run_async(create_client())

            # Now simulate getting client when loop doesn't exist
            # (RuntimeError when getting running loop)
            # The module handles this by setting current_loop_id to None
            # If _client exists and _client_loop_id != None, client is recreated

            # This simulates calling get_http_client outside async context
            # when pooling is enabled and client exists from different loop
            client2 = http_client.get_http_client()  # No running loop

            # Should have created new client since loop_id is None
            assert isinstance(client2, httpx.AsyncClient)


# =============================================================================
# GITHUB CLIENT CACHING TESTS (lines 203-232)
# =============================================================================


class TestGetGitHubClient:
    """Tests for get_github_client with connection pooling enabled."""

    def setup_method(self):
        """Reset GitHub client cache state before each test."""
        import http_client

        http_client._github_clients.clear()
        http_client._github_client_loop_ids.clear()

    def teardown_method(self):
        """Clean up GitHub client cache state after each test."""
        import http_client

        http_client._github_clients.clear()
        http_client._github_client_loop_ids.clear()

    def test_creates_new_client_when_pooling_disabled(self):
        """When pooling disabled, always creates new client."""
        from http_client import get_github_client

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "false"}):
            headers = {"Authorization": "Bearer ghp_test_token"}
            client1 = get_github_client(headers)
            client2 = get_github_client(headers)

            # Different instances when pooling disabled
            assert client1 is not client2
            assert isinstance(client1, httpx.AsyncClient)

    def test_caches_client_by_token_hash_when_pooling_enabled(self):
        """Same token should return same cached client when pooling enabled."""
        import http_client

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
                headers = {"Authorization": "Bearer ghp_test_token_123"}
                client1 = http_client.get_github_client(headers)
                client2 = http_client.get_github_client(headers)
                return client1, client2

        client1, client2 = run_async(test_coro())
        assert client1 is client2

    def test_different_tokens_get_different_clients(self):
        """Different tokens should produce different cached clients."""
        import http_client

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
                headers1 = {"Authorization": "Bearer ghp_token_aaa"}
                headers2 = {"Authorization": "Bearer ghp_token_bbb"}
                client1 = http_client.get_github_client(headers1)
                client2 = http_client.get_github_client(headers2)
                return client1, client2

        client1, client2 = run_async(test_coro())
        assert client1 is not client2

    def test_no_auth_header_uses_empty_string_hash(self):
        """Headers without Authorization should use empty string for token hash."""
        import http_client

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
                headers = {"Accept": "application/json"}
                client1 = http_client.get_github_client(headers)
                client2 = http_client.get_github_client(headers)
                return client1, client2

        client1, client2 = run_async(test_coro())
        assert client1 is client2

    def test_recreates_client_on_event_loop_change(self):
        """Client should be recreated when event loop changes (Lambda reuse)."""
        import http_client

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
            headers = {"Authorization": "Bearer ghp_test_reuse"}

            # First event loop
            async def first_loop():
                return http_client.get_github_client(headers)

            client1 = run_async(first_loop())
            first_client_id = id(client1)

            # Manually force loop ID mismatch for all cached entries
            for key in list(http_client._github_client_loop_ids.keys()):
                http_client._github_client_loop_ids[key] = (
                    http_client._github_client_loop_ids[key] + 99999
                    if http_client._github_client_loop_ids[key] is not None
                    else 99999
                )

            # Second event loop
            async def second_loop():
                return http_client.get_github_client(headers)

            client2 = run_async(second_loop())
            second_client_id = id(client2)

            # Client should be different due to loop change
            assert first_client_id != second_client_id

    def test_handles_no_running_loop(self):
        """Should handle RuntimeError when no event loop is running."""
        import http_client

        with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
            headers = {"Authorization": "Bearer ghp_test_no_loop"}
            # Called outside async context
            client = http_client.get_github_client(headers)
            assert isinstance(client, httpx.AsyncClient)

    def test_client_has_correct_config(self):
        """Cached GitHub client should have correct config (timeout, limits, headers)."""
        import http_client
        from http_client import DEFAULT_TIMEOUT

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
                headers = {
                    "Authorization": "Bearer ghp_test",
                    "Accept": "application/vnd.github.v3+json",
                }
                client = http_client.get_github_client(headers)
                return client

        client = run_async(test_coro())
        assert client.timeout.read == DEFAULT_TIMEOUT.read
        assert client.timeout.connect == DEFAULT_TIMEOUT.connect
        assert client.headers.get("Authorization") == "Bearer ghp_test"
        assert client.headers.get("Accept") == "application/vnd.github.v3+json"

    def test_token_hash_is_deterministic(self):
        """Same token always produces the same cache key."""
        import http_client

        async def test_coro():
            with patch.dict(os.environ, {"USE_CONNECTION_POOLING": "true"}):
                headers = {"Authorization": "Bearer ghp_deterministic_test"}
                client1 = http_client.get_github_client(headers)
                # Verify only one entry in cache
                assert len(http_client._github_clients) == 1
                # Get again - still one entry
                client2 = http_client.get_github_client(headers)
                assert len(http_client._github_clients) == 1
                return client1, client2

        client1, client2 = run_async(test_coro())
        assert client1 is client2
