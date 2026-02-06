"""
Tests for PyPI Downloads Collector.

Tests the batch download fetching from pypistats.org with incremental DynamoDB writes
and adaptive backoff on rate limiting.
"""

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import boto3
import httpx
from botocore.exceptions import ClientError
from moto import mock_aws

# Set environment before imports
os.environ.setdefault("PACKAGES_TABLE", "pkgwatch-packages")

from conftest import create_dynamodb_tables


class MockContext:
    """Mock Lambda context for testing timeout handling."""

    def __init__(self, remaining_ms=300_000):  # Default 5 minutes
        self._remaining_ms = remaining_ms

    def get_remaining_time_in_millis(self):
        return self._remaining_ms


class TestHandler:
    """Tests for the handler function."""

    @mock_aws
    def test_handler_success(self):
        """Test successful handler execution with download fetching."""
        # Setup DynamoDB
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add packages needing refresh (no downloads_fetched_at)
        table.put_item(
            Item={
                "pk": "pypi#requests",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "requests",
            }
        )
        table.put_item(
            Item={
                "pk": "pypi#flask",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "flask",
            }
        )

        # Mock HTTP client
        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "requests" in url:
                return httpx.Response(200, json={"data": {"last_week": 50000000}})
            elif "flask" in url:
                return httpx.Response(200, json={"data": {"last_week": 10000000}})
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.pypi_downloads_collector.time.sleep"):
                from collectors.pypi_downloads_collector import handler

                result = handler({}, MockContext())

        assert result["packages_updated"] == 2
        assert result["total_processed"] == 2

        # Verify DynamoDB was updated
        item = table.get_item(Key={"pk": "pypi#requests", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 50000000
        assert item["downloads_source"] == "pypistats"
        assert "downloads_fetched_at" in item

    @mock_aws
    def test_handler_empty_packages(self):
        """Test handler when no packages need refresh."""
        # Setup DynamoDB with no PyPI packages
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)

        from collectors.pypi_downloads_collector import handler

        result = handler({}, MockContext())

        assert result["packages_updated"] == 0
        assert result["total_processed"] == 0

    @mock_aws
    def test_handler_404_marks_package(self):
        """Test that 404 from pypistats marks package correctly."""
        # Setup DynamoDB
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add package that will 404
        table.put_item(
            Item={
                "pk": "pypi#nonexistent-pkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "nonexistent-pkg",
            }
        )

        # Mock HTTP client to return 404
        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.pypi_downloads_collector.time.sleep"):
                from collectors.pypi_downloads_collector import handler

                result = handler({}, MockContext())

        assert result["total_processed"] == 1

        # Verify package was marked with 404 source
        item = table.get_item(Key={"pk": "pypi#nonexistent-pkg", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 0
        assert item["downloads_source"] == "pypistats_404"
        assert "downloads_fetched_at" in item

    @mock_aws
    def test_handler_429_retries_then_continues(self):
        """Test that a single 429 triggers retry and continues the batch."""
        # Setup DynamoDB
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add multiple packages
        for i in range(5):
            table.put_item(
                Item={
                    "pk": f"pypi#pkg{i}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": f"pkg{i}",
                }
            )

        # Mock HTTP client - 2 successes, then 429 (retry succeeds), then 2 more successes
        call_count = [0]

        def mock_handler(request: httpx.Request) -> httpx.Response:
            call_count[0] += 1
            if call_count[0] <= 2:
                return httpx.Response(200, json={"data": {"last_week": 1000}})
            elif call_count[0] == 3:
                return httpx.Response(429)  # First 429
            elif call_count[0] == 4:
                return httpx.Response(200, json={"data": {"last_week": 2000}})  # Retry succeeds
            else:
                return httpx.Response(200, json={"data": {"last_week": 3000}})

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.pypi_downloads_collector.time.sleep"):
                from collectors.pypi_downloads_collector import handler

                result = handler({}, MockContext())

        # All 5 packages should be processed (429 retried and succeeded)
        assert result["total_processed"] == 5
        assert result["packages_updated"] == 5
        assert result["rate_limited_count"] == 1

    @mock_aws
    def test_handler_consecutive_429s_abort(self):
        """Test that 3 consecutive 429s abort the batch."""
        # Setup DynamoDB
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add 10 packages
        for i in range(10):
            table.put_item(
                Item={
                    "pk": f"pypi#pkg{i}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": f"pkg{i}",
                }
            )

        # Mock HTTP client - 2 successes, then all 429s (retries also fail)
        call_count = [0]

        def mock_handler(request: httpx.Request) -> httpx.Response:
            call_count[0] += 1
            if call_count[0] <= 2:
                return httpx.Response(200, json={"data": {"last_week": 1000}})
            return httpx.Response(429)  # All subsequent requests fail

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.pypi_downloads_collector.time.sleep"):
                from collectors.pypi_downloads_collector import handler

                result = handler({}, MockContext())

        # 2 successes + 3 rate-limited (abort on 3rd consecutive)
        assert result["packages_updated"] == 2
        assert result["total_processed"] == 5  # 2 success + 3 rate-limited
        assert result["rate_limited_count"] >= 3

    @mock_aws
    def test_handler_timeout_guard(self):
        """Test that handler breaks from loop when Lambda has low remaining time."""
        # Setup DynamoDB
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add many packages
        for i in range(20):
            table.put_item(
                Item={
                    "pk": f"pypi#pkg{i}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": f"pkg{i}",
                }
            )

        # Mock HTTP client
        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {"last_week": 1000}})

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        # Context with very low remaining time — should break immediately
        context = MockContext(remaining_ms=30_000)  # 30s < 45s threshold

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.pypi_downloads_collector.time.sleep"):
                from collectors.pypi_downloads_collector import handler

                result = handler({}, context)

        # Should have processed 0 because timeout guard fires at start of loop
        assert result["total_processed"] == 0

    @mock_aws
    def test_handler_http_error_continues(self):
        """Test that HTTP errors (5xx) don't stop batch processing."""
        # Setup DynamoDB
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add packages
        table.put_item(
            Item={
                "pk": "pypi#pkg1",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "pkg1",
            }
        )
        table.put_item(
            Item={
                "pk": "pypi#pkg2",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "pkg2",
            }
        )

        # Mock HTTP client - first fails, second succeeds
        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "pkg1" in url:
                return httpx.Response(500)
            return httpx.Response(200, json={"data": {"last_week": 5000}})

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.pypi_downloads_collector.time.sleep"):
                from collectors.pypi_downloads_collector import handler

                result = handler({}, MockContext())

        # Both should be processed (one failed, one succeeded)
        assert result["total_processed"] == 2
        assert result["packages_updated"] == 1  # Only the successful one


class TestGetPackagesNeedingRefresh:
    """Tests for _get_packages_needing_refresh function."""

    @mock_aws
    def test_phase1_only_unfetched_packages(self):
        """Test Phase 1: Returns packages missing downloads_fetched_at first."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add unfetched packages (no downloads_fetched_at)
        for i in range(3):
            table.put_item(
                Item={
                    "pk": f"pypi#unfetched{i}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": f"unfetched{i}",
                }
            )

        # Add already fetched packages
        for i in range(2):
            table.put_item(
                Item={
                    "pk": f"pypi#fetched{i}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": f"fetched{i}",
                    "downloads_fetched_at": datetime.now(timezone.utc).isoformat(),
                }
            )

        from collectors.pypi_downloads_collector import _get_packages_needing_refresh

        # Request exactly 3 (same as unfetched count) - should only get unfetched
        packages = _get_packages_needing_refresh(table, limit=3, context=None)

        # Should get exactly 3 unfetched packages
        assert len(packages) == 3
        assert all(pkg.startswith("unfetched") for pkg in packages)

    @mock_aws
    def test_phase2_fallback_oldest(self):
        """Test Phase 2: When Phase 1 insufficient, fills with oldest packages."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add 2 unfetched packages (not enough for limit=5)
        for i in range(2):
            table.put_item(
                Item={
                    "pk": f"pypi#unfetched{i}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": f"unfetched{i}",
                }
            )

        # Add fetched packages with varying ages
        now = datetime.now(timezone.utc)
        for i, days_ago in enumerate([30, 10, 20]):  # Various ages
            table.put_item(
                Item={
                    "pk": f"pypi#old{i}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": f"old{i}",
                    "downloads_fetched_at": (now - timedelta(days=days_ago)).isoformat(),
                }
            )

        from collectors.pypi_downloads_collector import _get_packages_needing_refresh

        packages = _get_packages_needing_refresh(table, limit=5, context=None)

        # Should get 2 unfetched + 3 oldest fetched = 5 total
        assert len(packages) == 5
        # First 2 should be unfetched
        unfetched = [p for p in packages if p.startswith("unfetched")]
        assert len(unfetched) == 2

    @mock_aws
    def test_timeout_handling_stops_early(self):
        """Test that scan stops when Lambda timeout approaches."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add many packages
        for i in range(20):
            table.put_item(
                Item={
                    "pk": f"pypi#pkg{i}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": f"pkg{i}",
                }
            )

        # Mock context with low remaining time (less than MIN_REMAINING_MS)
        context = MockContext(remaining_ms=100_000)  # 100s < 120s threshold

        from collectors.pypi_downloads_collector import _get_packages_needing_refresh

        packages = _get_packages_needing_refresh(table, limit=100, context=context)

        # Should have stopped early due to timeout
        # (exact count depends on page size, but should be < 20)
        assert len(packages) < 100

    @mock_aws
    def test_deduplication_phase1_phase2(self):
        """Test that Phase 2 doesn't include packages from Phase 1."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add packages - some unfetched, some with downloads_fetched_at
        table.put_item(
            Item={
                "pk": "pypi#shared",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "shared",
                # No downloads_fetched_at - will be in Phase 1
            }
        )

        # Add fetched packages for Phase 2
        now = datetime.now(timezone.utc)
        for i in range(3):
            table.put_item(
                Item={
                    "pk": f"pypi#fetched{i}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": f"fetched{i}",
                    "downloads_fetched_at": (now - timedelta(days=i + 1)).isoformat(),
                }
            )

        from collectors.pypi_downloads_collector import _get_packages_needing_refresh

        packages = _get_packages_needing_refresh(table, limit=10, context=None)

        # Should have no duplicates
        assert len(packages) == len(set(packages))
        assert "shared" in packages

    @mock_aws
    def test_dynamodb_error_returns_empty(self):
        """Test that DynamoDB ClientError returns empty list."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Mock scan to raise ClientError
        from botocore.exceptions import ClientError

        with patch.object(
            table,
            "scan",
            side_effect=ClientError(
                {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Rate exceeded"}}, "Scan"
            ),
        ):
            from collectors.pypi_downloads_collector import _get_packages_needing_refresh

            packages = _get_packages_needing_refresh(table, limit=10, context=None)

        assert packages == []


class TestWriteUpdates:
    """Tests for _write_updates function."""

    @mock_aws
    def test_write_updates_success(self):
        """Test successful batch write to DynamoDB."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add initial package
        table.put_item(
            Item={
                "pk": "pypi#requests",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "requests",
            }
        )

        updates = [{"name": "requests", "weekly_downloads": 50000000, "downloads_source": "pypistats"}]

        from collectors.pypi_downloads_collector import _write_updates

        _write_updates(table, updates)

        # Verify update
        item = table.get_item(Key={"pk": "pypi#requests", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 50000000
        assert item["downloads_source"] == "pypistats"
        assert "downloads_fetched_at" in item

    @mock_aws
    def test_write_updates_partial_failure(self):
        """Test that write continues despite individual item errors."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add packages
        table.put_item(
            Item={
                "pk": "pypi#good",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "good",
            }
        )

        updates = [
            {"name": "bad", "weekly_downloads": 1000, "downloads_source": "pypistats"},  # No existing item
            {"name": "good", "weekly_downloads": 2000, "downloads_source": "pypistats"},
        ]

        from collectors.pypi_downloads_collector import _write_updates

        # Should not raise - continues despite "bad" potentially failing
        _write_updates(table, updates)

        # Good item should be updated
        item = table.get_item(Key={"pk": "pypi#good", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 2000


class TestIncrementalWrites:
    """Tests for incremental write behavior."""

    @mock_aws
    def test_incremental_writes_every_batch_size(self):
        """Test that writes happen every WRITE_BATCH_SIZE packages."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add 15 packages (should trigger 2 incremental writes at 10 and 15)
        for i in range(15):
            table.put_item(
                Item={
                    "pk": f"pypi#pkg{i}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": f"pkg{i}",
                }
            )

        # Mock HTTP client
        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {"last_week": 1000}})

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        write_call_count = [0]
        original_write_updates = None

        def mock_write_updates(table, updates):
            write_call_count[0] += 1
            original_write_updates(table, updates)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.pypi_downloads_collector.time.sleep"):
                from collectors import pypi_downloads_collector

                original_write_updates = pypi_downloads_collector._write_updates

                with patch.object(pypi_downloads_collector, "_write_updates", mock_write_updates):
                    result = pypi_downloads_collector.handler({}, MockContext())

        # Should have called _write_updates twice (at 10 and at end with 5)
        assert write_call_count[0] == 2
        assert result["total_processed"] == 15


class TestCircuitBreakerOpen:
    """Tests for circuit breaker open path (lines 49-50)."""

    @mock_aws
    def test_handler_returns_early_when_circuit_open(self):
        """Test that handler returns immediately when pypistats circuit breaker is open."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)

        with patch("collectors.pypi_downloads_collector.PYPISTATS_CIRCUIT") as mock_circuit:
            mock_circuit.can_execute.return_value = False

            from collectors.pypi_downloads_collector import handler

            result = handler({}, MockContext())

        assert result == {"packages_updated": 0, "total_processed": 0, "circuit_open": True}


class TestTimeoutGuardBreak:
    """Tests for Lambda timeout guard break in main loop (lines 76-80)."""

    @mock_aws
    def test_handler_timeout_guard_breaks_mid_batch(self):
        """Test that handler breaks mid-batch when remaining time drops below threshold."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add multiple packages
        for i in range(5):
            table.put_item(
                Item={
                    "pk": f"pypi#pkg{i}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": f"pkg{i}",
                }
            )

        # Mock HTTP client
        def mock_http_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {"last_week": 1000}})

        transport = httpx.MockTransport(mock_http_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        # Context that starts with enough time for scan + first 2 loop iterations,
        # then drops below threshold on the 3rd iteration.
        # Calls happen at:
        #   - _get_packages_needing_refresh: Phase 1 scan loop check (1 call),
        #     Phase 2 scan loop check (1 call) = ~2 scan calls
        #   - Main handler loop: 1 call per package at line 75
        # We allow enough "high" calls for scanning + 2 packages, then trigger break.
        call_count = [0]

        class DecreasingTimeContext:
            def get_remaining_time_in_millis(self):
                call_count[0] += 1
                # First 4 calls (2 scan + 2 loop) get plenty of time
                if call_count[0] <= 4:
                    return 300_000  # 5 min
                return 30_000  # 30s < 45s MIN_REMAINING_MS - triggers break

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.pypi_downloads_collector.time.sleep"):
                from collectors.pypi_downloads_collector import handler

                result = handler({}, DecreasingTimeContext())

        # Should have processed exactly 2 (broke on 3rd iteration)
        assert result["total_processed"] == 2


class TestRetryAfterHeaderParsing:
    """Tests for Retry-After header parsing (lines 131-134)."""

    @mock_aws
    def test_429_with_valid_retry_after_header(self):
        """Test that valid Retry-After header sets the backoff delay (line 132)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "pypi#testpkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "testpkg",
            }
        )

        call_count = [0]

        def mock_http_handler(request: httpx.Request) -> httpx.Response:
            call_count[0] += 1
            if call_count[0] == 1:
                # First call: 429 with Retry-After header
                return httpx.Response(429, headers={"Retry-After": "5.0"})
            # Retry succeeds
            return httpx.Response(200, json={"data": {"last_week": 999}})

        transport = httpx.MockTransport(mock_http_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        sleep_calls = []

        def mock_sleep(seconds):
            sleep_calls.append(seconds)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.pypi_downloads_collector.time.sleep", side_effect=mock_sleep):
                from collectors.pypi_downloads_collector import handler

                result = handler({}, MockContext())

        assert result["total_processed"] == 1
        # The Retry-After value of 5.0 should have been used as the delay
        assert 5.0 in sleep_calls

    @mock_aws
    def test_429_with_invalid_retry_after_header(self):
        """Test that invalid Retry-After header falls back to doubling delay (lines 133-134)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "pypi#testpkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "testpkg",
            }
        )

        call_count = [0]

        def mock_http_handler(request: httpx.Request) -> httpx.Response:
            call_count[0] += 1
            if call_count[0] == 1:
                # 429 with non-numeric Retry-After header
                return httpx.Response(429, headers={"Retry-After": "not-a-number"})
            return httpx.Response(200, json={"data": {"last_week": 500}})

        transport = httpx.MockTransport(mock_http_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        sleep_calls = []

        def mock_sleep(seconds):
            sleep_calls.append(seconds)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.pypi_downloads_collector.time.sleep", side_effect=mock_sleep):
                from collectors.pypi_downloads_collector import handler

                result = handler({}, MockContext())

        assert result["total_processed"] == 1
        # Invalid Retry-After should result in doubling: 2.5 * 2 = 5.0
        assert 5.0 in sleep_calls


class TestGenericExceptionHandler:
    """Tests for generic Exception handler in main loop (lines 208-218)."""

    @mock_aws
    def test_handler_generic_exception_continues_batch(self):
        """Test that a non-HTTP exception is caught and processing continues."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "pypi#badpkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "badpkg",
            }
        )
        table.put_item(
            Item={
                "pk": "pypi#goodpkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "goodpkg",
            }
        )

        call_count = [0]

        def mock_http_handler(request: httpx.Request) -> httpx.Response:
            call_count[0] += 1
            url = str(request.url)
            if "badpkg" in url:
                raise ConnectionError("Connection refused")
            return httpx.Response(200, json={"data": {"last_week": 1000}})

        transport = httpx.MockTransport(mock_http_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.pypi_downloads_collector.time.sleep"):
                from collectors.pypi_downloads_collector import handler

                result = handler({}, MockContext())

        # Both should be processed (one with error, one success)
        assert result["total_processed"] == 2
        assert result["packages_updated"] == 1  # Only goodpkg

        # Check that badpkg was marked with error status
        item = table.get_item(Key={"pk": "pypi#badpkg", "sk": "LATEST"})["Item"]
        assert item["downloads_status"] == "error"
        assert "ConnectionError" in item["downloads_source"]


class TestMetricsEmissionFailure:
    """Tests for failed metrics emission (lines 241-242)."""

    @mock_aws
    def test_handler_continues_when_metrics_fail(self):
        """Test that handler returns result even when emit_batch_metrics raises."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "pypi#metricspkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "metricspkg",
            }
        )

        def mock_http_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {"last_week": 5000}})

        transport = httpx.MockTransport(mock_http_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.pypi_downloads_collector.time.sleep"):
                with patch(
                    "shared.metrics.emit_batch_metrics",
                    side_effect=Exception("CloudWatch unavailable"),
                ):
                    from collectors.pypi_downloads_collector import handler

                    result = handler({}, MockContext())

        # Handler should still return success even though metrics failed
        assert result["packages_updated"] == 1
        assert result["total_processed"] == 1


class TestPhase1PaginationAndLimitBreak:
    """Tests for Phase 1 pagination and inner limit break (lines 290, 295)."""

    @mock_aws
    def test_phase1_breaks_when_limit_reached_mid_page(self):
        """Test that Phase 1 stops collecting when limit is reached mid-page (line 290)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add more unfetched packages than the limit
        for i in range(10):
            table.put_item(
                Item={
                    "pk": f"pypi#unfetched{i}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": f"unfetched{i}",
                }
            )

        from collectors.pypi_downloads_collector import _get_packages_needing_refresh

        # Request fewer than available: limit=3 but 10 exist
        packages = _get_packages_needing_refresh(table, limit=3, context=None)

        assert len(packages) == 3
        assert all(pkg.startswith("unfetched") for pkg in packages)

    @mock_aws
    def test_phase1_pagination_with_last_evaluated_key(self):
        """Test that Phase 1 scan follows pagination (line 295)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # We need enough items to force DynamoDB to paginate.
        # With moto, we can patch the scan to simulate pagination.

        call_count = [0]

        def paginated_scan(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1 and "ExclusiveStartKey" not in kwargs:
                # First page returns 2 items with a LastEvaluatedKey
                return {
                    "Items": [{"name": "pkg-page1a"}, {"name": "pkg-page1b"}],
                    "LastEvaluatedKey": {"pk": "pypi#pkg-page1b", "sk": "LATEST"},
                }
            elif call_count[0] == 2:
                # Second page returns 1 item, no more pages
                return {
                    "Items": [{"name": "pkg-page2a"}],
                }
            return {"Items": []}

        with patch.object(table, "scan", side_effect=paginated_scan):
            from collectors.pypi_downloads_collector import _get_packages_needing_refresh

            packages = _get_packages_needing_refresh(table, limit=10, context=None)

        # Should have gotten items from both pages
        assert "pkg-page1a" in packages
        assert "pkg-page1b" in packages
        assert "pkg-page2a" in packages
        assert call_count[0] >= 2  # Confirms pagination happened


class TestPhase2Pagination:
    """Tests for Phase 2 pagination (line 329)."""

    @mock_aws
    def test_phase2_pagination_with_last_evaluated_key(self):
        """Test that Phase 2 scan follows pagination (line 329)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # No unfetched packages (Phase 1 returns nothing)
        # Phase 2 needs to paginate
        call_count = [0]

        def paginated_scan(**kwargs):
            call_count[0] += 1
            filter_expr = kwargs.get("FilterExpression", "")

            # Phase 1: no unfetched packages
            if "attribute_not_exists(downloads_fetched_at)" in filter_expr:
                return {"Items": []}

            # Phase 2: paginate fetched packages
            if "attribute_exists(downloads_fetched_at)" in filter_expr:
                if "ExclusiveStartKey" not in kwargs:
                    return {
                        "Items": [
                            {"name": "old-page1", "downloads_fetched_at": "2024-01-01T00:00:00Z"},
                            {"name": "old-page1b", "downloads_fetched_at": "2024-01-02T00:00:00Z"},
                        ],
                        "LastEvaluatedKey": {"pk": "pypi#old-page1b", "sk": "LATEST"},
                    }
                else:
                    return {
                        "Items": [
                            {"name": "old-page2", "downloads_fetched_at": "2024-01-03T00:00:00Z"},
                        ],
                    }

            return {"Items": []}

        with patch.object(table, "scan", side_effect=paginated_scan):
            from collectors.pypi_downloads_collector import _get_packages_needing_refresh

            packages = _get_packages_needing_refresh(table, limit=10, context=None)

        # Should have items from both Phase 2 pages, sorted by oldest first
        assert "old-page1" in packages
        assert "old-page1b" in packages
        assert "old-page2" in packages
        # Oldest should be first
        assert packages[0] == "old-page1"


class TestWriteUpdatesClientError:
    """Tests for ClientError catch in _write_updates (lines 379-380)."""

    @mock_aws
    def test_write_updates_continues_on_client_error(self):
        """Test that _write_updates catches ClientError per-item and continues."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add two packages
        table.put_item(
            Item={
                "pk": "pypi#failpkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "failpkg",
            }
        )
        table.put_item(
            Item={
                "pk": "pypi#successpkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "successpkg",
            }
        )

        updates = [
            {
                "name": "failpkg",
                "weekly_downloads": 100,
                "downloads_source": "pypistats",
                "downloads_status": "collected",
            },
            {
                "name": "successpkg",
                "weekly_downloads": 200,
                "downloads_source": "pypistats",
                "downloads_status": "collected",
            },
        ]

        original_update_item = table.update_item
        call_count = [0]

        def failing_update_item(**kwargs):
            call_count[0] += 1
            key = kwargs.get("Key", {})
            if "failpkg" in key.get("pk", ""):
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Condition not met"}},
                    "UpdateItem",
                )
            return original_update_item(**kwargs)

        with patch.object(table, "update_item", side_effect=failing_update_item):
            from collectors.pypi_downloads_collector import _write_updates

            # Should NOT raise despite first item failing
            _write_updates(table, updates)

        # Both items should have been attempted
        assert call_count[0] == 2

    @mock_aws
    def test_write_updates_rate_limited_status_only_updates_status(self):
        """Test that rate_limited status only updates status fields, not weekly_downloads."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add package with existing downloads
        table.put_item(
            Item={
                "pk": "pypi#ratepkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "ratepkg",
                "weekly_downloads": 50000,
            }
        )

        updates = [
            {"name": "ratepkg", "downloads_status": "rate_limited", "downloads_source": "pypistats_429"},
        ]

        from collectors.pypi_downloads_collector import _write_updates

        _write_updates(table, updates)

        # Verify existing weekly_downloads was preserved
        item = table.get_item(Key={"pk": "pypi#ratepkg", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 50000
        assert item["downloads_status"] == "rate_limited"
        assert item["downloads_source"] == "pypistats_429"
        assert "downloads_fetched_at" in item
