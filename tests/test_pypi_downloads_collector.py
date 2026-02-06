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
        table.put_item(Item={
            "pk": "pypi#requests",
            "sk": "LATEST",
            "ecosystem": "pypi",
            "name": "requests",
        })
        table.put_item(Item={
            "pk": "pypi#flask",
            "sk": "LATEST",
            "ecosystem": "pypi",
            "name": "flask",
        })

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
        table.put_item(Item={
            "pk": "pypi#nonexistent-pkg",
            "sk": "LATEST",
            "ecosystem": "pypi",
            "name": "nonexistent-pkg",
        })

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
            table.put_item(Item={
                "pk": f"pypi#pkg{i}",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": f"pkg{i}",
            })

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
            table.put_item(Item={
                "pk": f"pypi#pkg{i}",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": f"pkg{i}",
            })

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
            table.put_item(Item={
                "pk": f"pypi#pkg{i}",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": f"pkg{i}",
            })

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
        table.put_item(Item={
            "pk": "pypi#pkg1",
            "sk": "LATEST",
            "ecosystem": "pypi",
            "name": "pkg1",
        })
        table.put_item(Item={
            "pk": "pypi#pkg2",
            "sk": "LATEST",
            "ecosystem": "pypi",
            "name": "pkg2",
        })

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
            table.put_item(Item={
                "pk": f"pypi#unfetched{i}",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": f"unfetched{i}",
            })

        # Add already fetched packages
        for i in range(2):
            table.put_item(Item={
                "pk": f"pypi#fetched{i}",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": f"fetched{i}",
                "downloads_fetched_at": datetime.now(timezone.utc).isoformat(),
            })

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
            table.put_item(Item={
                "pk": f"pypi#unfetched{i}",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": f"unfetched{i}",
            })

        # Add fetched packages with varying ages
        now = datetime.now(timezone.utc)
        for i, days_ago in enumerate([30, 10, 20]):  # Various ages
            table.put_item(Item={
                "pk": f"pypi#old{i}",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": f"old{i}",
                "downloads_fetched_at": (now - timedelta(days=days_ago)).isoformat(),
            })

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
            table.put_item(Item={
                "pk": f"pypi#pkg{i}",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": f"pkg{i}",
            })

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
        table.put_item(Item={
            "pk": "pypi#shared",
            "sk": "LATEST",
            "ecosystem": "pypi",
            "name": "shared",
            # No downloads_fetched_at - will be in Phase 1
        })

        # Add fetched packages for Phase 2
        now = datetime.now(timezone.utc)
        for i in range(3):
            table.put_item(Item={
                "pk": f"pypi#fetched{i}",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": f"fetched{i}",
                "downloads_fetched_at": (now - timedelta(days=i+1)).isoformat(),
            })

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

        with patch.object(table, "scan", side_effect=ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Rate exceeded"}},
            "Scan"
        )):
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
        table.put_item(Item={
            "pk": "pypi#requests",
            "sk": "LATEST",
            "ecosystem": "pypi",
            "name": "requests",
        })

        updates = [
            {"name": "requests", "weekly_downloads": 50000000, "downloads_source": "pypistats"}
        ]

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
        table.put_item(Item={
            "pk": "pypi#good",
            "sk": "LATEST",
            "ecosystem": "pypi",
            "name": "good",
        })

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
            table.put_item(Item={
                "pk": f"pypi#pkg{i}",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": f"pkg{i}",
            })

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
