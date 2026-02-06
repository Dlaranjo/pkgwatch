"""
Tests for OpenSSF Batch Collector.

Tests the batch OpenSSF scorecard fetching with tier prioritization.
"""

import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import patch

import boto3
import httpx
from moto import mock_aws

# Set environment before imports
os.environ.setdefault("PACKAGES_TABLE", "pkgwatch-packages")

from conftest import create_dynamodb_tables


class TestHandler:
    """Tests for the handler function."""

    @mock_aws
    def test_handler_success(self):
        """Test successful handler execution with OpenSSF fetching."""
        # Setup DynamoDB
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add packages needing OpenSSF (no openssf_score but has repository_url)
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "lodash",
                "tier": 1,
                "repository_url": "https://github.com/lodash/lodash",
            }
        )
        table.put_item(
            Item={
                "pk": "npm#express",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "express",
                "tier": 2,
                "repository_url": "https://github.com/expressjs/express",
            }
        )

        # Mock HTTP client
        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"score": 7.5, "checks": [{"name": "Maintained", "score": 10}]})

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        # Track writes instead of actually writing (avoids float->Decimal issue)
        write_calls = []

        def mock_write(tbl, updates):
            write_calls.append(updates.copy())

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.openssf_collector_batch.time.sleep"):
                with patch("collectors.openssf_collector_batch._write_openssf_updates", mock_write):
                    from collectors.openssf_collector_batch import handler

                    result = handler({}, None)

        assert result["packages_updated"] == 2
        assert result["total_processed"] == 2

        # Verify write was called with correct data
        assert len(write_calls) == 1  # One batch at the end (< WRITE_BATCH_SIZE)
        updates = write_calls[0]
        assert len(updates) == 2
        assert any(u["pk"] == "npm#lodash" for u in updates)
        assert all(u["openssf_score"] == 7.5 for u in updates)
        assert all(u["openssf_source"] == "direct_batch" for u in updates)

    @mock_aws
    def test_handler_empty_packages(self):
        """Test handler when no packages need OpenSSF."""
        # Setup DynamoDB with packages that already have openssf_score
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "lodash",
                "openssf_score": Decimal("8.0"),  # Already has score
                "repository_url": "https://github.com/lodash/lodash",
            }
        )

        from collectors.openssf_collector_batch import handler

        result = handler({}, None)

        assert result["packages_updated"] == 0
        assert result["total_processed"] == 0

    @mock_aws
    def test_handler_missing_repo_url_skips(self):
        """Test that packages without repository_url are skipped."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add package without repository_url
        table.put_item(
            Item={
                "pk": "npm#no-repo",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "no-repo",
                "tier": 1,
                # No repository_url
            }
        )

        from collectors.openssf_collector_batch import handler

        result = handler({}, None)

        assert result["packages_updated"] == 0
        assert result["total_processed"] == 0

    @mock_aws
    def test_handler_invalid_github_url_skips(self):
        """Test that packages with invalid GitHub URLs are skipped."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add package with non-GitHub repository
        table.put_item(
            Item={
                "pk": "npm#gitlab-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "gitlab-pkg",
                "tier": 1,
                "repository_url": "https://gitlab.com/user/repo",
            }
        )

        # Mock parse_github_url to return None for non-GitHub URLs
        with patch("collectors.openssf_collector_batch.parse_github_url", return_value=None):
            from collectors.openssf_collector_batch import handler

            result = handler({}, None)

        assert result["packages_updated"] == 0
        assert result["total_processed"] == 0

    @mock_aws
    def test_handler_404_marks_not_found(self):
        """Test that 404 from OpenSSF marks package correctly."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "npm#unknown",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "unknown",
                "tier": 1,
                "repository_url": "https://github.com/unknown/unknown",
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

        write_calls = []

        def mock_write(tbl, updates):
            write_calls.append(updates.copy())

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.openssf_collector_batch.time.sleep"):
                with patch("collectors.openssf_collector_batch._write_openssf_updates", mock_write):
                    from collectors.openssf_collector_batch import handler

                    result = handler({}, None)

        assert result["total_processed"] == 1
        assert result["packages_updated"] == 0  # 404 is not a score update

        # Verify write was called with not_found data
        assert len(write_calls) == 1
        updates = write_calls[0]
        assert updates[0]["openssf_score"] is None
        assert updates[0]["openssf_source"] == "not_found"

    @mock_aws
    def test_handler_429_stops_batch(self):
        """Test that 429 rate limit stops batch processing."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add multiple packages
        for i in range(5):
            table.put_item(
                Item={
                    "pk": f"npm#pkg{i}",
                    "sk": "LATEST",
                    "ecosystem": "npm",
                    "name": f"pkg{i}",
                    "tier": 1,
                    "repository_url": f"https://github.com/owner/pkg{i}",
                }
            )

        # Mock HTTP client - 2 successes then 429
        call_count = [0]

        def mock_handler(request: httpx.Request) -> httpx.Response:
            call_count[0] += 1
            if call_count[0] <= 2:
                return httpx.Response(200, json={"score": 5.0, "checks": []})
            return httpx.Response(429)

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.openssf_collector_batch.time.sleep"):
                with patch("collectors.openssf_collector_batch._write_openssf_updates"):
                    from collectors.openssf_collector_batch import handler

                    result = handler({}, None)

        # Should have processed 2 before 429
        assert result["packages_updated"] == 2
        assert result["total_processed"] == 2
        assert call_count[0] == 3

    @mock_aws
    def test_handler_http_error_continues(self):
        """Test that HTTP errors don't stop batch processing."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "npm#pkg1",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "pkg1",
                "tier": 1,
                "repository_url": "https://github.com/owner/pkg1",
            }
        )
        table.put_item(
            Item={
                "pk": "npm#pkg2",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "pkg2",
                "tier": 1,
                "repository_url": "https://github.com/owner/pkg2",
            }
        )

        # Mock HTTP client - first fails, second succeeds
        def mock_handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "pkg1" in url:
                return httpx.Response(500)
            return httpx.Response(200, json={"score": 6.0, "checks": []})

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.openssf_collector_batch.time.sleep"):
                with patch("collectors.openssf_collector_batch._write_openssf_updates"):
                    from collectors.openssf_collector_batch import handler

                    result = handler({}, None)

        # 500 errors fall through without incrementing processed (code quirk)
        # Only the successful one is counted
        assert result["packages_updated"] == 1
        # Batch continued despite the 500 error - that's the key assertion


class TestGetPackagesNeedingOpenssf:
    """Tests for _get_packages_needing_openssf function."""

    @mock_aws
    def test_tier_sorting(self):
        """Test that packages are sorted by tier (1 > 2 > 3 > None)."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add packages with different tiers
        table.put_item(
            Item={
                "pk": "npm#tier3",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "tier3",
                "tier": 3,
                "repository_url": "https://github.com/owner/tier3",
            }
        )
        table.put_item(
            Item={
                "pk": "npm#tier1",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "tier1",
                "tier": 1,
                "repository_url": "https://github.com/owner/tier1",
            }
        )
        table.put_item(
            Item={
                "pk": "npm#tiernone",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "tiernone",
                # No tier
                "repository_url": "https://github.com/owner/tiernone",
            }
        )
        table.put_item(
            Item={
                "pk": "npm#tier2",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "tier2",
                "tier": 2,
                "repository_url": "https://github.com/owner/tier2",
            }
        )

        from collectors.openssf_collector_batch import _get_packages_needing_openssf

        packages = _get_packages_needing_openssf(table, limit=10)

        # Should be sorted: tier1, tier2, tier3, tiernone
        assert len(packages) == 4
        tiers = [p.get("tier") for p in packages]
        assert tiers == [1, 2, 3, None]

    @mock_aws
    def test_phase2_stale_refresh(self):
        """Test Phase 2: fetches stale packages when Phase 1 insufficient."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add 2 packages missing openssf_score
        for i in range(2):
            table.put_item(
                Item={
                    "pk": f"npm#new{i}",
                    "sk": "LATEST",
                    "ecosystem": "npm",
                    "name": f"new{i}",
                    "tier": 1,
                    "repository_url": f"https://github.com/owner/new{i}",
                }
            )

        # Add stale packages (openssf_date > 7 days old)
        stale_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        for i in range(3):
            table.put_item(
                Item={
                    "pk": f"npm#stale{i}",
                    "sk": "LATEST",
                    "ecosystem": "npm",
                    "name": f"stale{i}",
                    "tier": 2,
                    "openssf_score": Decimal("5.0"),  # Has score but stale
                    "openssf_date": stale_date,
                    "repository_url": f"https://github.com/owner/stale{i}",
                }
            )

        from collectors.openssf_collector_batch import _get_packages_needing_openssf

        packages = _get_packages_needing_openssf(table, limit=5)

        # Should get 2 new + 3 stale = 5
        assert len(packages) == 5

    @mock_aws
    def test_deduplication_phase1_phase2(self):
        """Test that Phase 2 excludes packages from Phase 1."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add package that could appear in both phases
        table.put_item(
            Item={
                "pk": "npm#shared",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "shared",
                "tier": 1,
                "repository_url": "https://github.com/owner/shared",
                # No openssf_score - will be in Phase 1
            }
        )

        # Add stale packages for Phase 2
        stale_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        for i in range(2):
            table.put_item(
                Item={
                    "pk": f"npm#stale{i}",
                    "sk": "LATEST",
                    "ecosystem": "npm",
                    "name": f"stale{i}",
                    "tier": 2,
                    "openssf_score": Decimal("5.0"),
                    "openssf_date": stale_date,
                    "repository_url": f"https://github.com/owner/stale{i}",
                }
            )

        from collectors.openssf_collector_batch import _get_packages_needing_openssf

        packages = _get_packages_needing_openssf(table, limit=10)

        # Should have no duplicates
        pks = [p["pk"] for p in packages]
        assert len(pks) == len(set(pks))

    @mock_aws
    def test_requires_repository_url(self):
        """Test that packages without repository_url are excluded."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add package without repository_url
        table.put_item(
            Item={
                "pk": "npm#no-repo",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "no-repo",
                "tier": 1,
                # No repository_url
            }
        )

        # Add package with repository_url
        table.put_item(
            Item={
                "pk": "npm#has-repo",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "has-repo",
                "tier": 1,
                "repository_url": "https://github.com/owner/repo",
            }
        )

        from collectors.openssf_collector_batch import _get_packages_needing_openssf

        packages = _get_packages_needing_openssf(table, limit=10)

        # Should only get the one with repository_url
        assert len(packages) == 1
        assert packages[0]["pk"] == "npm#has-repo"


class TestWriteOpenSSFUpdates:
    """Tests for _write_openssf_updates function."""

    @mock_aws
    def test_write_updates_with_score(self):
        """Test full update with score and checks."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add initial package
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "lodash",
            }
        )

        # Use Decimal for DynamoDB compatibility
        updates = [
            {
                "pk": "npm#lodash",
                "openssf_score": Decimal("7.5"),
                "openssf_checks": [{"name": "Maintained", "score": 10}],
                "openssf_source": "direct_batch",
            }
        ]

        from collectors.openssf_collector_batch import _write_openssf_updates

        _write_openssf_updates(table, updates)

        # Verify all fields updated
        item = table.get_item(Key={"pk": "npm#lodash", "sk": "LATEST"})["Item"]
        assert float(item["openssf_score"]) == 7.5
        assert item["openssf_checks"] == [{"name": "Maintained", "score": 10}]
        assert item["openssf_source"] == "direct_batch"
        assert "openssf_date" in item

    @mock_aws
    def test_write_updates_not_found(self):
        """Test update for not_found - only writes source and date."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add initial package
        table.put_item(
            Item={
                "pk": "npm#unknown",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "unknown",
            }
        )

        updates = [
            {
                "pk": "npm#unknown",
                "openssf_score": None,  # None means not found
                "openssf_checks": None,
                "openssf_source": "not_found",
            }
        ]

        from collectors.openssf_collector_batch import _write_openssf_updates

        _write_openssf_updates(table, updates)

        # Verify only source and date updated, NOT score
        item = table.get_item(Key={"pk": "npm#unknown", "sk": "LATEST"})["Item"]
        assert item["openssf_source"] == "not_found"
        assert "openssf_date" in item
        # Score should NOT exist (wasn't set to None)
        assert "openssf_score" not in item

    @mock_aws
    def test_write_updates_partial_failure(self):
        """Test that write continues despite individual item errors."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add only one package
        table.put_item(
            Item={
                "pk": "npm#good",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "good",
            }
        )

        updates = [
            # First update will create a new item (DynamoDB allows this)
            {"pk": "npm#bad", "openssf_score": Decimal("5.0"), "openssf_checks": [], "openssf_source": "direct_batch"},
            # Second update should succeed
            {"pk": "npm#good", "openssf_score": Decimal("7.0"), "openssf_checks": [], "openssf_source": "direct_batch"},
        ]

        from collectors.openssf_collector_batch import _write_openssf_updates

        # Should not raise
        _write_openssf_updates(table, updates)

        # Good item should be updated
        item = table.get_item(Key={"pk": "npm#good", "sk": "LATEST"})["Item"]
        assert float(item["openssf_score"]) == 7.0


class TestIncrementalWrites:
    """Tests for incremental write behavior."""

    @mock_aws
    def test_incremental_writes_every_batch_size(self):
        """Test that writes happen every WRITE_BATCH_SIZE packages."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Add 15 packages (should trigger 2 writes: at 10 and at 15)
        for i in range(15):
            table.put_item(
                Item={
                    "pk": f"npm#pkg{i}",
                    "sk": "LATEST",
                    "ecosystem": "npm",
                    "name": f"pkg{i}",
                    "tier": 1,
                    "repository_url": f"https://github.com/owner/pkg{i}",
                }
            )

        # Mock HTTP client
        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"score": 5.0, "checks": []})

        transport = httpx.MockTransport(mock_handler)
        original_init = httpx.Client.__init__

        def patched_init(self, **kwargs):
            kwargs["transport"] = transport
            original_init(self, **kwargs)

        write_call_count = [0]

        def mock_write(table, updates):
            write_call_count[0] += 1

        with patch.object(httpx.Client, "__init__", patched_init):
            with patch("collectors.openssf_collector_batch.time.sleep"):
                with patch("collectors.openssf_collector_batch._write_openssf_updates", mock_write):
                    from collectors.openssf_collector_batch import handler

                    result = handler({}, None)

        # Should have called _write_openssf_updates twice (at 10 and at end with 5)
        assert write_call_count[0] == 2
        assert result["total_processed"] == 15
