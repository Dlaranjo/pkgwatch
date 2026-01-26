"""
Tests for publish_top_packages.py - Publish top packages Lambda.

Coverage targets:
- Handler configuration validation
- DynamoDB queries (downloads-index GSI)
- Pagination handling
- S3 uploads (main file and top-100)
- JSON output format
- Decimal conversion
- Error handling (DynamoDB, S3)
- Metrics emission
"""

import json
import os
import sys
from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws


@pytest.fixture
def setup_s3_public_bucket():
    """Set up S3 bucket for public data."""
    import boto3

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="pkgwatch-public")
    os.environ["PUBLIC_BUCKET"] = "pkgwatch-public"
    return "pkgwatch-public"


class TestHandlerConfiguration:
    """Tests for handler configuration and validation."""

    @mock_aws
    def test_returns_500_without_public_bucket(self, mock_dynamodb):
        """Should return 500 when PUBLIC_BUCKET is not configured."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ.pop("PUBLIC_BUCKET", None)

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 500
        assert "PUBLIC_BUCKET not configured" in result.get("error", "")

    @mock_aws
    def test_returns_500_with_empty_public_bucket(self, mock_dynamodb):
        """Should return 500 when PUBLIC_BUCKET is empty string."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = ""

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 500
        assert "PUBLIC_BUCKET not configured" in result.get("error", "")

    @mock_aws
    def test_uses_default_packages_table_name(self, mock_dynamodb):
        """Should use default table name when PACKAGES_TABLE not set."""
        os.environ.pop("PACKAGES_TABLE", None)
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        assert module.PACKAGES_TABLE == "pkgwatch-packages"


class TestDynamoDBQueries:
    """Tests for DynamoDB query operations."""

    @mock_aws
    def test_returns_zero_when_no_packages(self, mock_dynamodb):
        """Should return zero when no packages exist."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        with patch.object(module, "s3"):
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["published"] == 0

    @mock_aws
    def test_queries_npm_ecosystem(self, mock_dynamodb):
        """Should query packages from npm ecosystem."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "name": "lodash",
                "ecosystem": "npm",
                "weekly_downloads": 5000000,
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        with patch.object(module, "s3") as mock_s3:
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["published"] == 1

    @mock_aws
    def test_handles_query_exception(self, mock_dynamodb):
        """Should return 500 when DynamoDB query fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        mock_table = MagicMock()
        mock_table.query.side_effect = Exception("DynamoDB error")

        with patch.object(module.dynamodb, "Table", return_value=mock_table):
            result = module.handler({}, None)

            assert result["statusCode"] == 500
            assert "DynamoDB error" in result.get("error", "")

    @mock_aws
    def test_skips_packages_without_downloads(self, mock_dynamodb):
        """Should skip packages missing weekly_downloads field."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Package without weekly_downloads
        table.put_item(
            Item={
                "pk": "npm#no-downloads",
                "sk": "LATEST",
                "name": "no-downloads",
                "ecosystem": "npm",
                "health_score": 50,
            }
        )

        # Package with weekly_downloads
        table.put_item(
            Item={
                "pk": "npm#with-downloads",
                "sk": "LATEST",
                "name": "with-downloads",
                "ecosystem": "npm",
                "weekly_downloads": 1000,
                "health_score": 60,
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        with patch.object(module, "s3") as mock_s3:
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["published"] == 1  # Only the one with downloads

    @mock_aws
    def test_skips_packages_with_none_downloads(self, mock_dynamodb):
        """Should skip packages with None weekly_downloads."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        mock_table = MagicMock()
        mock_table.query.return_value = {
            "Items": [
                {
                    "pk": "npm#null-downloads",
                    "name": "null-downloads",
                    "ecosystem": "npm",
                    "weekly_downloads": None,
                },
                {
                    "pk": "npm#valid-downloads",
                    "name": "valid-downloads",
                    "ecosystem": "npm",
                    "weekly_downloads": 1000,
                },
            ]
        }

        with patch.object(module.dynamodb, "Table", return_value=mock_table):
            with patch.object(module, "s3") as mock_s3:
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["published"] == 1


class TestPagination:
    """Tests for DynamoDB pagination handling."""

    @mock_aws
    def test_handles_pagination(self, mock_dynamodb):
        """Should paginate through large result sets."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        # Mock paginated responses
        first_page = {
            "Items": [
                {
                    "pk": "npm#pkg1",
                    "name": "pkg1",
                    "ecosystem": "npm",
                    "weekly_downloads": 1000,
                }
            ],
            "LastEvaluatedKey": {"pk": "npm#pkg1"},
        }
        second_page = {
            "Items": [
                {
                    "pk": "npm#pkg2",
                    "name": "pkg2",
                    "ecosystem": "npm",
                    "weekly_downloads": 500,
                }
            ],
        }

        mock_table = MagicMock()
        mock_table.query.side_effect = [first_page, second_page]

        with patch.object(module.dynamodb, "Table", return_value=mock_table):
            with patch.object(module, "s3") as mock_s3:
                result = module.handler({}, None)

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["published"] == 2

                # Verify query was called twice (pagination)
                assert mock_table.query.call_count == 2

    @mock_aws
    def test_respects_max_packages_limit(self, mock_dynamodb):
        """Should stop pagination when MAX_PACKAGES is reached."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        # Create paginated responses that exceed MAX_PACKAGES
        page_with_continuation = {
            "Items": [
                {"pk": f"npm#pkg-{i}", "name": f"pkg-{i}", "ecosystem": "npm", "weekly_downloads": 1000}
                for i in range(1000)
            ],
            "LastEvaluatedKey": {"pk": "npm#pkg-999"},
        }

        mock_table = MagicMock()
        # Return same page repeatedly
        mock_table.query.return_value = page_with_continuation

        with patch.object(module.dynamodb, "Table", return_value=mock_table):
            with patch.object(module, "s3"):
                result = module.handler({}, None)

                # Should succeed without infinite loop
                assert result["statusCode"] == 200

    @mock_aws
    def test_passes_exclusive_start_key(self, mock_dynamodb):
        """Should pass ExclusiveStartKey for pagination."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        first_page = {
            "Items": [{"pk": "npm#pkg1", "name": "pkg1", "ecosystem": "npm", "weekly_downloads": 1000}],
            "LastEvaluatedKey": {"pk": "npm#pkg1", "sk": "LATEST"},
        }
        second_page = {
            "Items": [{"pk": "npm#pkg2", "name": "pkg2", "ecosystem": "npm", "weekly_downloads": 500}],
        }

        mock_table = MagicMock()
        mock_table.query.side_effect = [first_page, second_page]

        with patch.object(module.dynamodb, "Table", return_value=mock_table):
            with patch.object(module, "s3"):
                module.handler({}, None)

                # Check second call has ExclusiveStartKey
                call_args_list = mock_table.query.call_args_list
                assert len(call_args_list) == 2
                second_call = call_args_list[1]
                assert "ExclusiveStartKey" in second_call.kwargs


class TestS3Uploads:
    """Tests for S3 upload operations."""

    @mock_aws
    def test_uploads_main_file(self, mock_dynamodb, setup_s3_public_bucket):
        """Should upload main packages file to S3."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_public_bucket

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "name": "lodash",
                "ecosystem": "npm",
                "weekly_downloads": 5000000,
                "health_score": 90,
                "risk_level": "LOW",
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200

        # Verify file was uploaded
        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.get_object(Bucket=bucket, Key="data/top-npm-packages.json")
        data = json.loads(response["Body"].read())

        assert "last_update" in data
        assert "query" in data
        assert data["query"]["ecosystem"] == "npm"
        assert len(data["rows"]) == 1
        assert data["rows"][0]["project"] == "lodash"

    @mock_aws
    def test_uploads_top_100_file(self, mock_dynamodb, setup_s3_public_bucket):
        """Should upload top-100 file to S3."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_public_bucket

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "name": "lodash",
                "ecosystem": "npm",
                "weekly_downloads": 5000000,
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200

        # Verify top-100 file was uploaded
        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.get_object(Bucket=bucket, Key="data/top-100-npm-packages.json")
        data = json.loads(response["Body"].read())

        assert data["query"]["limit"] == 100

    @mock_aws
    def test_handles_s3_upload_error(self, mock_dynamodb):
        """Should return 500 when main S3 upload fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "LATEST",
                "name": "test-pkg",
                "ecosystem": "npm",
                "weekly_downloads": 1000,
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = Exception("S3 upload failed")

        with patch.object(module, "s3", mock_s3):
            result = module.handler({}, None)

            assert result["statusCode"] == 500
            assert "S3 upload failed" in result.get("error", "")

    @mock_aws
    def test_handles_top100_upload_error(self, mock_dynamodb):
        """Should succeed even when top-100 upload fails."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "LATEST",
                "name": "test-pkg",
                "ecosystem": "npm",
                "weekly_downloads": 1000,
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        call_count = [0]

        def side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 2:  # Second call is top-100
                raise Exception("Top-100 upload failed")
            return {}

        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = side_effect

        with patch.object(module, "s3", mock_s3):
            result = module.handler({}, None)

            # Should still succeed since main file was uploaded
            assert result["statusCode"] == 200

    @mock_aws
    def test_sets_correct_content_type(self, mock_dynamodb, setup_s3_public_bucket):
        """Should set application/json content type."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_public_bucket

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "name": "lodash",
                "ecosystem": "npm",
                "weekly_downloads": 1000,
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200

        # Verify content type
        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.head_object(Bucket=bucket, Key="data/top-npm-packages.json")
        assert response["ContentType"] == "application/json"

    @mock_aws
    def test_sets_cache_control(self, mock_dynamodb, setup_s3_public_bucket):
        """Should set 1 hour cache control."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_public_bucket

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "name": "lodash",
                "ecosystem": "npm",
                "weekly_downloads": 1000,
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200

        # Verify cache control
        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.head_object(Bucket=bucket, Key="data/top-npm-packages.json")
        assert response["CacheControl"] == "max-age=3600"


class TestJSONOutputFormat:
    """Tests for JSON output format."""

    @mock_aws
    def test_output_format_matches_specification(self, mock_dynamodb, setup_s3_public_bucket):
        """Should match hugovk's top-pypi-packages format."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_public_bucket

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "name": "lodash",
                "ecosystem": "npm",
                "weekly_downloads": 5000000,
                "health_score": 90,
                "risk_level": "LOW",
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200

        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.get_object(Bucket=bucket, Key="data/top-npm-packages.json")
        data = json.loads(response["Body"].read())

        # Check structure
        assert "last_update" in data
        assert "query" in data
        assert "rows" in data

        # Check query metadata
        assert data["query"]["ecosystem"] == "npm"
        assert data["query"]["sorted_by"] == "weekly_downloads"
        assert data["query"]["limit"] == 10000

        # Check row format
        row = data["rows"][0]
        assert row["project"] == "lodash"
        assert row["download_count"] == 5000000
        assert row["health_score"] == 90
        assert row["risk_level"] == "LOW"

    @mock_aws
    def test_handles_null_health_score(self, mock_dynamodb, setup_s3_public_bucket):
        """Should handle packages without health_score."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_public_bucket

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#no-health",
                "sk": "LATEST",
                "name": "no-health",
                "ecosystem": "npm",
                "weekly_downloads": 1000,
                # No health_score
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200

        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.get_object(Bucket=bucket, Key="data/top-npm-packages.json")
        data = json.loads(response["Body"].read())

        row = data["rows"][0]
        assert row["health_score"] is None

    @mock_aws
    def test_handles_null_risk_level(self, mock_dynamodb, setup_s3_public_bucket):
        """Should handle packages without risk_level."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_public_bucket

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#no-risk",
                "sk": "LATEST",
                "name": "no-risk",
                "ecosystem": "npm",
                "weekly_downloads": 1000,
                # No risk_level
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200

        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.get_object(Bucket=bucket, Key="data/top-npm-packages.json")
        data = json.loads(response["Body"].read())

        row = data["rows"][0]
        assert row["risk_level"] is None

    @mock_aws
    def test_top_100_has_correct_limit(self, mock_dynamodb, setup_s3_public_bucket):
        """Should limit top-100 file to 100 entries."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_public_bucket

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Add 150 packages
        for i in range(150):
            table.put_item(
                Item={
                    "pk": f"npm#pkg-{i}",
                    "sk": "LATEST",
                    "name": f"pkg-{i}",
                    "ecosystem": "npm",
                    "weekly_downloads": 1000 - i,  # Decreasing downloads
                }
            )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200

        s3 = boto3.client("s3", region_name="us-east-1")

        # Main file should have all 150
        main_response = s3.get_object(Bucket=bucket, Key="data/top-npm-packages.json")
        main_data = json.loads(main_response["Body"].read())
        assert len(main_data["rows"]) == 150

        # Top-100 should have only 100
        top100_response = s3.get_object(Bucket=bucket, Key="data/top-100-npm-packages.json")
        top100_data = json.loads(top100_response["Body"].read())
        assert len(top100_data["rows"]) == 100


class TestDecimalConversion:
    """Tests for Decimal to int conversion."""

    @mock_aws
    def test_converts_decimal_health_score(self, mock_dynamodb, setup_s3_public_bucket):
        """Should convert Decimal health_score to int."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_public_bucket

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#decimal-pkg",
                "sk": "LATEST",
                "name": "decimal-pkg",
                "ecosystem": "npm",
                "weekly_downloads": Decimal("5000"),
                "health_score": Decimal("85"),
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200

        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.get_object(Bucket=bucket, Key="data/top-npm-packages.json")
        data = json.loads(response["Body"].read())

        row = data["rows"][0]
        assert row["health_score"] == 85
        assert isinstance(row["health_score"], int)

    @mock_aws
    def test_converts_decimal_weekly_downloads(self, mock_dynamodb, setup_s3_public_bucket):
        """Should convert Decimal weekly_downloads to int."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_public_bucket

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#decimal-downloads",
                "sk": "LATEST",
                "name": "decimal-downloads",
                "ecosystem": "npm",
                "weekly_downloads": Decimal("1234567"),
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200

        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.get_object(Bucket=bucket, Key="data/top-npm-packages.json")
        data = json.loads(response["Body"].read())

        row = data["rows"][0]
        assert row["download_count"] == 1234567
        assert isinstance(row["download_count"], int)


class TestMetricsEmission:
    """Tests for CloudWatch metrics emission."""

    @mock_aws
    def test_emits_metrics_on_success(self, mock_dynamodb):
        """Should emit CloudWatch metrics on successful publish."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#metrics-pkg",
                "sk": "LATEST",
                "name": "metrics-pkg",
                "ecosystem": "npm",
                "weekly_downloads": 1000,
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        mock_metrics = MagicMock()

        with patch.object(module, "s3"):
            with patch.dict(sys.modules, {"shared.metrics": mock_metrics}):
                result = module.handler({}, None)

                assert result["statusCode"] == 200

    @mock_aws
    def test_continues_when_metrics_not_available(self, mock_dynamodb):
        """Should not fail when metrics module is not available."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        with patch.object(module, "s3"):
            with patch.dict(sys.modules, {"shared.metrics": None}):
                result = module.handler({}, None)

                assert result["statusCode"] == 200


class TestConstants:
    """Tests for module constants."""

    def test_max_packages_constant(self):
        """Should have MAX_PACKAGES set to 10000."""
        import discovery.publish_top_packages as module

        assert module.MAX_PACKAGES == 10000


class TestReturnValue:
    """Tests for handler return value."""

    @mock_aws
    def test_returns_bucket_and_key_on_success(self, mock_dynamodb):
        """Should return bucket and key in response."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "my-public-bucket"

        table = mock_dynamodb.Table("pkgwatch-packages")
        table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "LATEST",
                "name": "test-pkg",
                "ecosystem": "npm",
                "weekly_downloads": 1000,
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        with patch.object(module, "s3"):
            result = module.handler({}, None)

            assert result["statusCode"] == 200
            body = json.loads(result["body"])
            assert body["bucket"] == "my-public-bucket"
            assert body["key"] == "data/top-npm-packages.json"

    @mock_aws
    def test_returns_published_count(self, mock_dynamodb):
        """Should return correct published count."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["PUBLIC_BUCKET"] = "test-bucket"

        table = mock_dynamodb.Table("pkgwatch-packages")

        for i in range(5):
            table.put_item(
                Item={
                    "pk": f"npm#pkg-{i}",
                    "sk": "LATEST",
                    "name": f"pkg-{i}",
                    "ecosystem": "npm",
                    "weekly_downloads": 1000,
                }
            )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        with patch.object(module, "s3"):
            result = module.handler({}, None)

            body = json.loads(result["body"])
            assert body["published"] == 5


class TestIntegration:
    """Integration tests for end-to-end publish flow."""

    @mock_aws
    def test_full_publish_flow(self, mock_dynamodb, setup_s3_public_bucket):
        """Should complete full publish flow successfully."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_public_bucket

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Add various packages
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "name": "lodash",
                "ecosystem": "npm",
                "weekly_downloads": 5000000,
                "health_score": Decimal("90"),
                "risk_level": "LOW",
            }
        )
        table.put_item(
            Item={
                "pk": "npm#express",
                "sk": "LATEST",
                "name": "express",
                "ecosystem": "npm",
                "weekly_downloads": 3000000,
                "health_score": Decimal("85"),
                "risk_level": "LOW",
            }
        )
        table.put_item(
            Item={
                "pk": "npm#no-health",
                "sk": "LATEST",
                "name": "no-health",
                "ecosystem": "npm",
                "weekly_downloads": 1000000,
                # No health_score or risk_level
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["published"] == 3

        # Verify main file
        s3 = boto3.client("s3", region_name="us-east-1")
        main_response = s3.get_object(Bucket=bucket, Key="data/top-npm-packages.json")
        main_data = json.loads(main_response["Body"].read())

        assert len(main_data["rows"]) == 3
        assert main_data["query"]["ecosystem"] == "npm"

        # Verify top-100 file
        top100_response = s3.get_object(Bucket=bucket, Key="data/top-100-npm-packages.json")
        top100_data = json.loads(top100_response["Body"].read())

        assert len(top100_data["rows"]) == 3  # Only 3 packages
        assert top100_data["query"]["limit"] == 100

    @mock_aws
    def test_handles_empty_database(self, mock_dynamodb, setup_s3_public_bucket):
        """Should handle empty database gracefully."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        setup_s3_public_bucket

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["published"] == 0

    @mock_aws
    def test_handles_mixed_valid_invalid_packages(self, mock_dynamodb, setup_s3_public_bucket):
        """Should handle mix of valid and invalid packages."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        bucket = setup_s3_public_bucket

        table = mock_dynamodb.Table("pkgwatch-packages")

        # Valid package
        table.put_item(
            Item={
                "pk": "npm#valid",
                "sk": "LATEST",
                "name": "valid",
                "ecosystem": "npm",
                "weekly_downloads": 1000,
            }
        )

        # Package without weekly_downloads (will be skipped)
        table.put_item(
            Item={
                "pk": "npm#no-downloads",
                "sk": "LATEST",
                "name": "no-downloads",
                "ecosystem": "npm",
            }
        )

        import importlib
        import discovery.publish_top_packages as module

        importlib.reload(module)

        result = module.handler({}, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["published"] == 1

        s3 = boto3.client("s3", region_name="us-east-1")
        response = s3.get_object(Bucket=bucket, Key="data/top-npm-packages.json")
        data = json.loads(response["Body"].read())

        assert len(data["rows"]) == 1
        assert data["rows"][0]["project"] == "valid"
