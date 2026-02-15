"""
Tests for npm Downloads Collector.

Tests the batch download fetching from npm API with bulk endpoint for unscoped
packages, individual fetches for scoped packages, incremental DynamoDB writes,
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
        """Test successful handler with bulk API multi-package response format."""
        # Setup DynamoDB
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add unscoped npm packages needing refresh (no downloads_fetched_at)
        table.put_item(
            Item={
                "pk": "npm#express",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "express",
            }
        )
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "lodash",
            }
        )

        # Mock HTTP client — bulk endpoint returns multi-package format
        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "api.npmjs.org/downloads/point/last-week/" in url:
                return httpx.Response(
                    200,
                    json={
                        "express": {"downloads": 30000000, "package": "express"},
                        "lodash": {"downloads": 50000000, "package": "lodash"},
                    },
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.npm_downloads_collector.time.sleep"):
                from collectors.npm_downloads_collector import handler

                result = handler({}, MockContext())

        assert result["packages_updated"] == 2
        assert result["total_processed"] == 2

        # Verify DynamoDB was updated with correct downloads/source/status
        item = table.get_item(Key={"pk": "npm#express", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 30000000
        assert item["downloads_source"] == "npm"
        assert item["downloads_status"] == "collected"
        assert "downloads_fetched_at" in item

        item = table.get_item(Key={"pk": "npm#lodash", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 50000000
        assert item["downloads_source"] == "npm"
        assert item["downloads_status"] == "collected"
        assert "downloads_fetched_at" in item

    @mock_aws
    def test_handler_empty_packages(self):
        """Test handler when no npm packages exist in table."""
        # Setup DynamoDB with no npm packages
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)

        from collectors.npm_downloads_collector import handler

        result = handler({}, MockContext())

        assert result["packages_updated"] == 0
        assert result["total_processed"] == 0

    @mock_aws
    def test_handler_circuit_open(self):
        """Test handler returns early when NPM_DOWNLOADS_CIRCUIT is open."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)

        with patch("collectors.npm_downloads_collector.NPM_DOWNLOADS_CIRCUIT") as mock_circuit:
            mock_circuit.can_execute.return_value = False

            from collectors.npm_downloads_collector import handler

            result = handler({}, MockContext())

        assert result == {"packages_updated": 0, "total_processed": 0, "circuit_open": True}

    @mock_aws
    def test_handler_429_abort(self):
        """Test that 3 consecutive 429s on bulk endpoint cause abort with rate_limited status."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add 10 packages. Reduce BULK_MAX to 3 so we get 4 bulk batches (3+3+3+1),
        # enough to trigger CONSECUTIVE_429_ABORT=3 on the 3rd batch.
        for i in range(10):
            table.put_item(
                Item={
                    "pk": f"npm#pkg{i}",
                    "sk": "LATEST",
                    "ecosystem": "npm",
                    "name": f"pkg{i}",
                }
            )

        # Mock HTTP client — always return 429
        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429)

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.npm_downloads_collector.time.sleep"):
                with patch("collectors.npm_downloads_collector.BULK_MAX", 3):
                    from collectors.npm_downloads_collector import handler

                    result = handler({}, MockContext())

        # First 2 batches (3 pkgs each) get 429 and continue; 3rd batch hits
        # CONSECUTIVE_429_ABORT=3 and breaks. Total rate_limited = 3+3+3 = 9.
        assert result["rate_limited_count"] == 9
        # Processed = rate_limited packages from all 3 batches
        assert result["total_processed"] == 9
        assert result["packages_updated"] == 0

    @mock_aws
    def test_handler_scoped_packages(self):
        """Test that scoped packages (@scope/name) are fetched individually with correct URL encoding."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add scoped packages
        table.put_item(
            Item={
                "pk": "npm#@angular/core",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "@angular/core",
            }
        )
        table.put_item(
            Item={
                "pk": "npm#@types/node",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "@types/node",
            }
        )

        # Track URLs requested to verify encoding
        requested_urls = []

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            requested_urls.append(url)
            if "%2F" in url:
                # Scoped package individual fetch
                return httpx.Response(
                    200,
                    json={"downloads": 5000000, "package": "@angular/core"},
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.npm_downloads_collector.time.sleep"):
                from collectors.npm_downloads_collector import handler

                result = handler({}, MockContext())

        assert result["total_processed"] == 2

        # Verify scoped packages used URL encoding (@scope%2Fname)
        scoped_urls = [u for u in requested_urls if "%2F" in u]
        assert len(scoped_urls) == 2
        assert any("@angular%2Fcore" in u for u in scoped_urls)
        assert any("@types%2Fnode" in u for u in scoped_urls)

    @mock_aws
    def test_handler_single_package_response_format(self):
        """Test that single-package bulk response format {downloads: N, package: name} is handled."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add a single unscoped package
        table.put_item(
            Item={
                "pk": "npm#express",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "express",
            }
        )

        # Mock HTTP client — single package format
        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "api.npmjs.org/downloads/point/last-week/" in url:
                # Single package in bulk request returns flat format
                return httpx.Response(
                    200,
                    json={"downloads": 25000000, "package": "express"},
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.npm_downloads_collector.time.sleep"):
                from collectors.npm_downloads_collector import handler

                result = handler({}, MockContext())

        assert result["packages_updated"] == 1
        assert result["total_processed"] == 1

        # Verify DynamoDB updated correctly
        item = table.get_item(Key={"pk": "npm#express", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 25000000
        assert item["downloads_source"] == "npm"
        assert item["downloads_status"] == "collected"

    @mock_aws
    def test_handler_timeout_guard(self):
        """Test that handler breaks from loop when Lambda has low remaining time."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add many packages
        for i in range(20):
            table.put_item(
                Item={
                    "pk": f"npm#pkg{i}",
                    "sk": "LATEST",
                    "ecosystem": "npm",
                    "name": f"pkg{i}",
                }
            )

        # Mock HTTP client
        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={f"pkg{i}": {"downloads": 1000} for i in range(20)},
            )

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        # Context with very low remaining time — should break immediately
        context = MockContext(remaining_ms=30_000)  # 30s < 45s threshold

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.npm_downloads_collector.time.sleep"):
                from collectors.npm_downloads_collector import handler

                result = handler({}, context)

        # Should have processed 0 because timeout guard fires at start of bulk loop
        assert result["total_processed"] == 0


class TestWriteUpdates:
    """Tests for _write_updates function."""

    @mock_aws
    def test_write_updates_collected(self):
        """Test that collected status writes weekly_downloads, downloads_source, downloads_status, downloads_fetched_at."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add initial package
        table.put_item(
            Item={
                "pk": "npm#express",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "express",
            }
        )

        updates = [
            {
                "name": "express",
                "weekly_downloads": 30000000,
                "downloads_source": "npm",
                "downloads_status": "collected",
            }
        ]

        from collectors.npm_downloads_collector import _write_updates

        _write_updates(table, updates)

        # Verify all fields updated
        item = table.get_item(Key={"pk": "npm#express", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 30000000
        assert item["downloads_source"] == "npm"
        assert item["downloads_status"] == "collected"
        assert "downloads_fetched_at" in item

    @mock_aws
    def test_write_updates_rate_limited(self):
        """Test that rate_limited does NOT update downloads_fetched_at (preserves queue position)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add package with existing downloads
        table.put_item(
            Item={
                "pk": "npm#ratepkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "ratepkg",
                "weekly_downloads": 50000,
            }
        )

        updates = [
            {"name": "ratepkg", "downloads_status": "rate_limited", "downloads_source": "npm_429"},
        ]

        from collectors.npm_downloads_collector import _write_updates

        _write_updates(table, updates)

        # Verify existing weekly_downloads preserved and downloads_fetched_at NOT set
        item = table.get_item(Key={"pk": "npm#ratepkg", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 50000
        assert item["downloads_status"] == "rate_limited"
        assert item["downloads_source"] == "npm_429"
        assert "downloads_fetched_at" not in item

    @mock_aws
    def test_write_updates_error(self):
        """Test that error status DOES update downloads_fetched_at to prevent rapid retry loops."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add package
        table.put_item(
            Item={
                "pk": "npm#errorpkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "errorpkg",
            }
        )

        updates = [
            {
                "name": "errorpkg",
                "downloads_status": "error",
                "downloads_source": "npm_http_500",
            },
        ]

        from collectors.npm_downloads_collector import _write_updates

        _write_updates(table, updates)

        # Verify error status DOES set downloads_fetched_at
        item = table.get_item(Key={"pk": "npm#errorpkg", "sk": "LATEST"})["Item"]
        assert item["downloads_status"] == "error"
        assert item["downloads_source"] == "npm_http_500"
        assert "downloads_fetched_at" in item


class TestGetPackagesNeedingRefresh:
    """Tests for _get_packages_needing_refresh function."""

    @mock_aws
    def test_phase1_missing_downloads(self):
        """Test Phase 1: Packages without downloads_fetched_at come first."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add unfetched packages (no downloads_fetched_at)
        for i in range(3):
            table.put_item(
                Item={
                    "pk": f"npm#unfetched{i}",
                    "sk": "LATEST",
                    "ecosystem": "npm",
                    "name": f"unfetched{i}",
                }
            )

        # Add already fetched packages
        for i in range(2):
            table.put_item(
                Item={
                    "pk": f"npm#fetched{i}",
                    "sk": "LATEST",
                    "ecosystem": "npm",
                    "name": f"fetched{i}",
                    "downloads_fetched_at": datetime.now(timezone.utc).isoformat(),
                }
            )

        from collectors.npm_downloads_collector import _get_packages_needing_refresh

        # Request exactly 3 (same as unfetched count) — should only get unfetched
        packages = _get_packages_needing_refresh(table, limit=3, context=None)

        # Should get exactly 3 unfetched packages
        assert len(packages) == 3
        assert all(pkg.startswith("unfetched") for pkg in packages)

    @mock_aws
    def test_phase2_oldest_first(self):
        """Test Phase 2: After Phase 1, packages sorted by oldest downloads_fetched_at."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add 2 unfetched packages (not enough for limit=5)
        for i in range(2):
            table.put_item(
                Item={
                    "pk": f"npm#unfetched{i}",
                    "sk": "LATEST",
                    "ecosystem": "npm",
                    "name": f"unfetched{i}",
                }
            )

        # Add fetched packages with varying ages
        now = datetime.now(timezone.utc)
        for i, days_ago in enumerate([30, 10, 20]):  # Various ages
            table.put_item(
                Item={
                    "pk": f"npm#old{i}",
                    "sk": "LATEST",
                    "ecosystem": "npm",
                    "name": f"old{i}",
                    "downloads_fetched_at": (now - timedelta(days=days_ago)).isoformat(),
                }
            )

        from collectors.npm_downloads_collector import _get_packages_needing_refresh

        packages = _get_packages_needing_refresh(table, limit=5, context=None)

        # Should get 2 unfetched + 3 oldest fetched = 5 total
        assert len(packages) == 5
        # First 2 should be unfetched
        unfetched = [p for p in packages if p.startswith("unfetched")]
        assert len(unfetched) == 2

        # Phase 2 packages should be sorted oldest first
        fetched = [p for p in packages if p.startswith("old")]
        assert len(fetched) == 3
        # old0 = 30 days ago (oldest), old2 = 20 days ago, old1 = 10 days ago (newest)
        assert fetched[0] == "old0"
        assert fetched[1] == "old2"
        assert fetched[2] == "old1"


class TestScopedPackageEncoding:
    """Tests for _encode_scoped_package function."""

    def test_encode_scoped_package(self):
        """Test that @scope/name is encoded to @scope%2Fname."""
        from collectors.npm_downloads_collector import _encode_scoped_package

        assert _encode_scoped_package("@scope/name") == "@scope%2Fname"
        assert _encode_scoped_package("@angular/core") == "@angular%2Fcore"
        assert _encode_scoped_package("@types/node") == "@types%2Fnode"

    def test_non_scoped_not_encoded(self):
        """Test that regular package names are left as-is."""
        from collectors.npm_downloads_collector import _encode_scoped_package

        assert _encode_scoped_package("express") == "express"
        assert _encode_scoped_package("lodash") == "lodash"
        assert _encode_scoped_package("some-package-name") == "some-package-name"
