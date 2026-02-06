"""
Tests for PyPI Downloads BigQuery Collector.

Tests the batch download fetching from Google BigQuery with DynamoDB writes,
retry logic for transient errors, and credential management.
"""

import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

# Set environment before imports
os.environ.setdefault("PACKAGES_TABLE", "pkgwatch-packages")

from conftest import create_dynamodb_tables

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bq_row(package_name: str, weekly_downloads: int):
    """Create a mock BigQuery Row-like object with attribute access."""
    return SimpleNamespace(package_name=package_name, weekly_downloads=weekly_downloads)


def _fake_credentials():
    """Return a minimal fake GCP service account dict."""
    return {
        "type": "service_account",
        "project_id": "test-project",
        "private_key_id": "key123",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n",
        "client_email": "test@test-project.iam.gserviceaccount.com",
        "client_id": "123456",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    }


def _install_fake_google_modules(mock_bq_module, mock_sa_module):
    """Install fake google.cloud.bigquery and google.oauth2 modules in sys.modules.

    The source does ``from google.cloud import bigquery`` and
    ``from google.oauth2 import service_account`` inside the function body,
    so we need these importable at call time.

    Returns a list of keys that were injected (for cleanup).
    """
    google_mod = MagicMock()
    google_cloud_mod = MagicMock()
    google_cloud_mod.bigquery = mock_bq_module
    google_mod.cloud = google_cloud_mod

    google_oauth2_mod = MagicMock()
    google_oauth2_mod.service_account = mock_sa_module
    google_mod.oauth2 = google_oauth2_mod

    entries = {
        "google": google_mod,
        "google.cloud": google_cloud_mod,
        "google.cloud.bigquery": mock_bq_module,
        "google.oauth2": google_oauth2_mod,
        "google.oauth2.service_account": mock_sa_module,
    }
    return entries


def _setup_bq_mocks(rows, total_bytes_billed=1024**3):
    """Set up mocked google.cloud.bigquery and google.oauth2 modules.

    Returns (mock_bigquery_module, mock_service_account_module, mock_client_instance).
    """
    # Mock query job
    mock_job = MagicMock()
    mock_job.result.return_value = rows
    mock_job.total_bytes_billed = total_bytes_billed

    # Mock BigQuery client
    mock_client_instance = MagicMock()
    mock_client_instance.query.return_value = mock_job

    # Mock bigquery module
    mock_bq_module = MagicMock()
    mock_bq_module.Client.return_value = mock_client_instance

    # Mock service_account module
    mock_sa_module = MagicMock()
    mock_sa_creds = MagicMock()
    mock_sa_module.Credentials.from_service_account_info.return_value = mock_sa_creds

    return mock_bq_module, mock_sa_module, mock_client_instance


@pytest.fixture(autouse=True)
def _clean_google_modules():
    """Remove any injected google.* modules after each test to prevent leakage."""
    yield
    keys_to_remove = [k for k in sys.modules if k.startswith("google")]
    for k in keys_to_remove:
        del sys.modules[k]


# ---------------------------------------------------------------------------
# _is_retryable_error
# ---------------------------------------------------------------------------


class TestIsRetryableError:
    """Tests for _is_retryable_error helper."""

    def test_service_unavailable_is_retryable(self):
        from collectors.pypi_downloads_bigquery_collector import _is_retryable_error

        assert _is_retryable_error(Exception("503 ServiceUnavailable")) is True

    def test_internal_server_error_is_retryable(self):
        from collectors.pypi_downloads_bigquery_collector import _is_retryable_error

        assert _is_retryable_error(Exception("500 InternalServerError")) is True

    def test_too_many_requests_is_retryable(self):
        from collectors.pypi_downloads_bigquery_collector import _is_retryable_error

        assert _is_retryable_error(Exception("429 TooManyRequests")) is True

    def test_bad_gateway_is_retryable(self):
        from collectors.pypi_downloads_bigquery_collector import _is_retryable_error

        assert _is_retryable_error(Exception("502 BadGateway")) is True

    def test_timeout_is_retryable(self):
        from collectors.pypi_downloads_bigquery_collector import _is_retryable_error

        assert _is_retryable_error(Exception("Timeout")) is True

    def test_deadline_exceeded_is_retryable(self):
        from collectors.pypi_downloads_bigquery_collector import _is_retryable_error

        assert _is_retryable_error(Exception("DeadlineExceeded")) is True

    def test_permission_denied_is_not_retryable(self):
        from collectors.pypi_downloads_bigquery_collector import _is_retryable_error

        assert _is_retryable_error(Exception("403 PermissionDenied")) is False

    def test_not_found_is_not_retryable(self):
        from collectors.pypi_downloads_bigquery_collector import _is_retryable_error

        assert _is_retryable_error(Exception("404 NotFound")) is False

    def test_syntax_error_is_not_retryable(self):
        from collectors.pypi_downloads_bigquery_collector import _is_retryable_error

        assert _is_retryable_error(Exception("Syntax error in SQL query")) is False

    def test_empty_error_is_not_retryable(self):
        from collectors.pypi_downloads_bigquery_collector import _is_retryable_error

        assert _is_retryable_error(Exception("")) is False


# ---------------------------------------------------------------------------
# _get_gcp_credentials
# ---------------------------------------------------------------------------


class TestGetGcpCredentials:
    """Tests for _get_gcp_credentials fetching from Secrets Manager."""

    @mock_aws
    def test_returns_parsed_credentials(self):
        """Successful retrieval returns parsed JSON dict."""
        sm = boto3.client("secretsmanager", region_name="us-east-1")
        creds = _fake_credentials()
        sm.create_secret(
            Name="pkgwatch/gcp-bigquery-credentials",
            SecretString=json.dumps(creds),
        )

        from collectors.pypi_downloads_bigquery_collector import _get_gcp_credentials

        result = _get_gcp_credentials()

        assert result is not None
        assert result["project_id"] == "test-project"
        assert result["type"] == "service_account"

    @mock_aws
    def test_returns_none_when_secret_not_found(self):
        """Returns None when the secret does not exist in Secrets Manager."""
        from collectors.pypi_downloads_bigquery_collector import _get_gcp_credentials

        result = _get_gcp_credentials()

        assert result is None

    @mock_aws
    def test_returns_none_on_other_client_error(self):
        """Returns None on non-ResourceNotFoundException ClientError."""
        from collectors.pypi_downloads_bigquery_collector import _get_gcp_credentials

        with patch("collectors.pypi_downloads_bigquery_collector.boto3.client") as mock_boto_client:
            mock_sm = MagicMock()
            mock_sm.get_secret_value.side_effect = ClientError(
                {"Error": {"Code": "InternalServiceError", "Message": "AWS error"}},
                "GetSecretValue",
            )
            mock_boto_client.return_value = mock_sm

            result = _get_gcp_credentials()

        assert result is None

    @mock_aws
    def test_returns_none_on_invalid_json(self):
        """Returns None when SecretString is not valid JSON."""
        sm = boto3.client("secretsmanager", region_name="us-east-1")
        sm.create_secret(
            Name="pkgwatch/gcp-bigquery-credentials",
            SecretString="this is not valid json {{{",
        )

        from collectors.pypi_downloads_bigquery_collector import _get_gcp_credentials

        result = _get_gcp_credentials()

        assert result is None


# ---------------------------------------------------------------------------
# _get_pypi_packages
# ---------------------------------------------------------------------------


class TestGetPypiPackages:
    """Tests for _get_pypi_packages scanning DynamoDB."""

    @mock_aws
    def test_returns_pypi_package_names(self):
        """Returns names of all PyPI packages in the table via low-level paginator."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        # Seed packages at resource level
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
        # npm package should be excluded
        table.put_item(
            Item={
                "pk": "npm#lodash",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "lodash",
            }
        )

        from collectors.pypi_downloads_bigquery_collector import _get_pypi_packages

        # The function uses the low-level paginator which in real AWS returns
        # wire-format items like {"name": {"S": "requests"}}. Mock the paginator
        # to return the expected wire format.
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Items": [
                    {"name": {"S": "requests"}},
                    {"name": {"S": "flask"}},
                ]
            }
        ]

        with patch.object(table.meta.client, "get_paginator", return_value=mock_paginator):
            packages = _get_pypi_packages(table)

        assert sorted(packages) == ["flask", "requests"]

    @mock_aws
    def test_returns_empty_list_when_no_pypi_packages(self):
        """Returns empty list when no items match the filter."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        from collectors.pypi_downloads_bigquery_collector import _get_pypi_packages

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Items": []}]

        with patch.object(table.meta.client, "get_paginator", return_value=mock_paginator):
            packages = _get_pypi_packages(table)

        assert packages == []

    @mock_aws
    def test_handles_items_without_name_field(self):
        """Skips items that are missing the name field."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        from collectors.pypi_downloads_bigquery_collector import _get_pypi_packages

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Items": [
                    {"name": {"S": "good-pkg"}},
                    {"other_field": {"S": "no-name"}},  # missing name
                    {},  # empty item
                ]
            }
        ]

        with patch.object(table.meta.client, "get_paginator", return_value=mock_paginator):
            packages = _get_pypi_packages(table)

        assert packages == ["good-pkg"]

    @mock_aws
    def test_handles_multiple_pages(self):
        """Correctly aggregates packages across multiple paginator pages."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        from collectors.pypi_downloads_bigquery_collector import _get_pypi_packages

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Items": [{"name": {"S": "requests"}}]},
            {"Items": [{"name": {"S": "flask"}}]},
            {"Items": [{"name": {"S": "django"}}]},
        ]

        with patch.object(table.meta.client, "get_paginator", return_value=mock_paginator):
            packages = _get_pypi_packages(table)

        assert sorted(packages) == ["django", "flask", "requests"]

    @mock_aws
    def test_returns_empty_list_on_dynamodb_error(self):
        """Returns empty list when DynamoDB scan fails."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        from collectors.pypi_downloads_bigquery_collector import _get_pypi_packages

        with patch.object(
            table.meta.client,
            "get_paginator",
            side_effect=ClientError(
                {
                    "Error": {
                        "Code": "ProvisionedThroughputExceededException",
                        "Message": "Rate exceeded",
                    }
                },
                "Scan",
            ),
        ):
            packages = _get_pypi_packages(table)

        assert packages == []


# ---------------------------------------------------------------------------
# _query_bigquery_downloads
# ---------------------------------------------------------------------------


class TestQueryBigqueryDownloads:
    """Tests for _query_bigquery_downloads with mocked BigQuery client."""

    def test_happy_path_returns_matched_downloads(self):
        """Returns download counts only for tracked packages."""
        rows = [
            _make_bq_row("requests", 5000000),
            _make_bq_row("flask", 2000000),
            _make_bq_row("untracked-pkg", 100),
        ]
        mock_bq, mock_sa, _ = _setup_bq_mocks(rows)
        fake_modules = _install_fake_google_modules(mock_bq, mock_sa)

        with patch.dict("sys.modules", fake_modules):
            from collectors.pypi_downloads_bigquery_collector import (
                _query_bigquery_downloads,
            )

            result = _query_bigquery_downloads(
                _fake_credentials(),
                package_names={"requests", "flask"},
            )

        assert result == {"requests": 5000000, "flask": 2000000}

    def test_filters_out_untracked_packages(self):
        """Packages not in the tracking set are excluded from results."""
        rows = [
            _make_bq_row("requests", 5000000),
            _make_bq_row("unknown-lib", 999),
        ]
        mock_bq, mock_sa, _ = _setup_bq_mocks(rows)
        fake_modules = _install_fake_google_modules(mock_bq, mock_sa)

        with patch.dict("sys.modules", fake_modules):
            from collectors.pypi_downloads_bigquery_collector import (
                _query_bigquery_downloads,
            )

            result = _query_bigquery_downloads(
                _fake_credentials(),
                package_names={"requests"},
            )

        assert "unknown-lib" not in result
        assert result == {"requests": 5000000}

    def test_empty_results_returns_empty_dict(self):
        """Empty BigQuery result set returns empty dict."""
        mock_bq, mock_sa, _ = _setup_bq_mocks(rows=[])
        fake_modules = _install_fake_google_modules(mock_bq, mock_sa)

        with patch.dict("sys.modules", fake_modules):
            from collectors.pypi_downloads_bigquery_collector import (
                _query_bigquery_downloads,
            )

            result = _query_bigquery_downloads(
                _fake_credentials(),
                package_names={"requests", "flask"},
            )

        assert result == {}

    def test_no_matching_packages_returns_empty_dict(self):
        """When BigQuery rows exist but none match tracked packages, returns empty."""
        rows = [
            _make_bq_row("untracked-a", 100),
            _make_bq_row("untracked-b", 200),
        ]
        mock_bq, mock_sa, _ = _setup_bq_mocks(rows)
        fake_modules = _install_fake_google_modules(mock_bq, mock_sa)

        with patch.dict("sys.modules", fake_modules):
            from collectors.pypi_downloads_bigquery_collector import (
                _query_bigquery_downloads,
            )

            result = _query_bigquery_downloads(
                _fake_credentials(),
                package_names={"requests"},
            )

        assert result == {}

    def test_import_error_returns_empty_dict(self):
        """Returns empty dict if google-cloud-bigquery is not installed."""
        from collectors.pypi_downloads_bigquery_collector import (
            _query_bigquery_downloads,
        )

        original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        def fail_import(name, *args, **kwargs):
            if "google.cloud" in name or "google.oauth2" in name:
                raise ImportError(f"No module named '{name}'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fail_import):
            result = _query_bigquery_downloads(
                _fake_credentials(),
                package_names={"requests"},
            )

        assert result == {}

    def test_non_retryable_error_returns_empty_dict_no_retry(self):
        """Non-retryable BigQuery error returns empty dict without retry."""
        mock_bq, mock_sa, mock_client = _setup_bq_mocks(rows=[])
        mock_client.query.side_effect = Exception("403 PermissionDenied: Access denied")
        fake_modules = _install_fake_google_modules(mock_bq, mock_sa)

        with patch.dict("sys.modules", fake_modules):
            from collectors.pypi_downloads_bigquery_collector import (
                _query_bigquery_downloads,
            )

            result = _query_bigquery_downloads(
                _fake_credentials(),
                package_names={"requests"},
            )

        assert result == {}
        assert mock_client.query.call_count == 1

    def test_retryable_error_retries_then_succeeds(self):
        """Retryable error triggers retry and succeeds on second attempt."""
        rows = [_make_bq_row("requests", 5000000)]
        mock_bq, mock_sa, mock_client = _setup_bq_mocks(rows)

        mock_job_success = MagicMock()
        mock_job_success.result.return_value = rows
        mock_job_success.total_bytes_billed = 1024**3

        mock_client.query.side_effect = [
            Exception("503 ServiceUnavailable: try again"),
            mock_job_success,
        ]
        fake_modules = _install_fake_google_modules(mock_bq, mock_sa)

        with patch.dict("sys.modules", fake_modules):
            with patch("collectors.pypi_downloads_bigquery_collector.time.sleep"):
                from collectors.pypi_downloads_bigquery_collector import (
                    _query_bigquery_downloads,
                )

                result = _query_bigquery_downloads(
                    _fake_credentials(),
                    package_names={"requests"},
                )

        assert result == {"requests": 5000000}
        assert mock_client.query.call_count == 2

    def test_all_retries_exhausted_returns_empty_dict(self):
        """Returns empty dict when all retry attempts are exhausted."""
        mock_bq, mock_sa, mock_client = _setup_bq_mocks(rows=[])
        mock_client.query.side_effect = Exception("503 ServiceUnavailable: down")
        fake_modules = _install_fake_google_modules(mock_bq, mock_sa)

        with patch.dict("sys.modules", fake_modules):
            with patch("collectors.pypi_downloads_bigquery_collector.time.sleep"):
                from collectors.pypi_downloads_bigquery_collector import (
                    _query_bigquery_downloads,
                )

                result = _query_bigquery_downloads(
                    _fake_credentials(),
                    package_names={"requests"},
                )

        assert result == {}
        assert mock_client.query.call_count == 3  # MAX_QUERY_RETRIES

    def test_retry_uses_exponential_backoff_with_jitter(self):
        """Verify retry delays use exponential backoff with jitter."""
        mock_bq, mock_sa, mock_client = _setup_bq_mocks(rows=[])
        mock_client.query.side_effect = Exception("503 ServiceUnavailable")
        fake_modules = _install_fake_google_modules(mock_bq, mock_sa)

        with patch.dict("sys.modules", fake_modules):
            with patch("collectors.pypi_downloads_bigquery_collector.time.sleep") as mock_sleep:
                with patch(
                    "collectors.pypi_downloads_bigquery_collector.random.uniform",
                    return_value=0.5,
                ):
                    from collectors.pypi_downloads_bigquery_collector import (
                        _query_bigquery_downloads,
                    )

                    _query_bigquery_downloads(
                        _fake_credentials(),
                        package_names={"requests"},
                    )

        # Sleep called twice (after attempt 0 and 1; not after final attempt 2)
        assert mock_sleep.call_count == 2
        # First retry: QUERY_RETRY_BASE_DELAY * 2^0 + 0.5 = 5 * 1 + 0.5 = 5.5
        first_delay = mock_sleep.call_args_list[0][0][0]
        assert 5.0 <= first_delay <= 6.0
        # Second retry: QUERY_RETRY_BASE_DELAY * 2^1 + 0.5 = 5 * 2 + 0.5 = 10.5
        second_delay = mock_sleep.call_args_list[1][0][0]
        assert 10.0 <= second_delay <= 11.0

    def test_limit_parameter_appended_to_query(self):
        """When limit > 0, a LIMIT clause is appended to the SQL query."""
        rows = [_make_bq_row("requests", 5000000)]
        mock_bq, mock_sa, mock_client = _setup_bq_mocks(rows)
        fake_modules = _install_fake_google_modules(mock_bq, mock_sa)

        with patch.dict("sys.modules", fake_modules):
            from collectors.pypi_downloads_bigquery_collector import (
                _query_bigquery_downloads,
            )

            _query_bigquery_downloads(
                _fake_credentials(),
                package_names={"requests"},
                limit=100,
            )

        query_arg = mock_client.query.call_args[0][0]
        assert "LIMIT 100" in query_arg

    def test_no_limit_clause_when_limit_is_zero(self):
        """When limit is 0 (default), no LIMIT clause is added."""
        rows = [_make_bq_row("requests", 5000000)]
        mock_bq, mock_sa, mock_client = _setup_bq_mocks(rows)
        fake_modules = _install_fake_google_modules(mock_bq, mock_sa)

        with patch.dict("sys.modules", fake_modules):
            from collectors.pypi_downloads_bigquery_collector import (
                _query_bigquery_downloads,
            )

            _query_bigquery_downloads(
                _fake_credentials(),
                package_names={"requests"},
                limit=0,
            )

        query_arg = mock_client.query.call_args[0][0]
        assert "LIMIT" not in query_arg

    def test_null_total_bytes_billed_handled_gracefully(self):
        """Handles None total_bytes_billed without raising."""
        rows = [_make_bq_row("requests", 5000000)]
        mock_bq, mock_sa, _ = _setup_bq_mocks(rows, total_bytes_billed=None)
        fake_modules = _install_fake_google_modules(mock_bq, mock_sa)

        with patch.dict("sys.modules", fake_modules):
            from collectors.pypi_downloads_bigquery_collector import (
                _query_bigquery_downloads,
            )

            result = _query_bigquery_downloads(
                _fake_credentials(),
                package_names={"requests"},
            )

        assert result == {"requests": 5000000}

    def test_uses_correct_gcp_scopes_and_project(self):
        """Verifies credentials are created with correct scopes and project."""
        rows = [_make_bq_row("requests", 100)]
        mock_bq, mock_sa, _ = _setup_bq_mocks(rows)
        fake_modules = _install_fake_google_modules(mock_bq, mock_sa)
        creds = _fake_credentials()

        with patch.dict("sys.modules", fake_modules):
            from collectors.pypi_downloads_bigquery_collector import (
                _query_bigquery_downloads,
            )

            _query_bigquery_downloads(creds, package_names={"requests"})

        # Check service account was created with correct args
        mock_sa.Credentials.from_service_account_info.assert_called_once_with(
            creds,
            scopes=["https://www.googleapis.com/auth/bigquery.readonly"],
        )

        # Check BigQuery client was created with correct project
        mock_bq.Client.assert_called_once()
        _, kwargs = mock_bq.Client.call_args
        assert kwargs["project"] == "test-project"


# ---------------------------------------------------------------------------
# _write_downloads_batch
# ---------------------------------------------------------------------------


class TestWriteDownloadsBatch:
    """Tests for _write_downloads_batch DynamoDB update logic."""

    @mock_aws
    def test_writes_download_counts_to_dynamodb(self):
        """Successfully writes download counts and metadata to DynamoDB."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

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

        downloads = {"requests": 5000000, "flask": 2000000}

        from collectors.pypi_downloads_bigquery_collector import _write_downloads_batch

        success, errors = _write_downloads_batch(table, downloads)

        assert success == 2
        assert errors == 0

        # Verify DynamoDB content
        item = table.get_item(Key={"pk": "pypi#requests", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 5000000
        assert item["downloads_source"] == "bigquery"
        assert item["downloads_status"] == "collected"
        assert "downloads_fetched_at" in item

        item2 = table.get_item(Key={"pk": "pypi#flask", "sk": "LATEST"})["Item"]
        assert item2["weekly_downloads"] == 2000000
        assert item2["downloads_source"] == "bigquery"

    @mock_aws
    def test_dry_run_does_not_write(self):
        """dry_run=True counts successes but does not update DynamoDB."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "pypi#requests",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "requests",
            }
        )

        downloads = {"requests": 5000000}

        from collectors.pypi_downloads_bigquery_collector import _write_downloads_batch

        success, errors = _write_downloads_batch(table, downloads, dry_run=True)

        assert success == 1
        assert errors == 0

        # Verify item was NOT updated
        item = table.get_item(Key={"pk": "pypi#requests", "sk": "LATEST"})["Item"]
        assert "weekly_downloads" not in item
        assert "downloads_source" not in item

    @mock_aws
    def test_partial_failure_continues_processing(self):
        """Individual DynamoDB update failures are counted but processing continues."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "pypi#good-pkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "good-pkg",
            }
        )

        downloads = {"good-pkg": 1000, "fail-pkg": 2000}

        from collectors.pypi_downloads_bigquery_collector import _write_downloads_batch

        original_update = table.update_item

        def failing_update(**kwargs):
            if "fail-pkg" in kwargs["Key"]["pk"]:
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Failed"}},
                    "UpdateItem",
                )
            return original_update(**kwargs)

        with patch.object(table, "update_item", side_effect=failing_update):
            success, errors = _write_downloads_batch(table, downloads)

        assert success == 1
        assert errors == 1

    @mock_aws
    def test_empty_downloads_dict(self):
        """Empty downloads dict produces zero counts."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        from collectors.pypi_downloads_bigquery_collector import _write_downloads_batch

        success, errors = _write_downloads_batch(table, {})

        assert success == 0
        assert errors == 0

    @mock_aws
    def test_respects_batch_size(self):
        """Verifies items are processed in batches of WRITE_BATCH_SIZE."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        downloads = {}
        for i in range(5):
            name = f"pkg{i}"
            table.put_item(
                Item={
                    "pk": f"pypi#{name}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": name,
                }
            )
            downloads[name] = (i + 1) * 1000

        from collectors.pypi_downloads_bigquery_collector import _write_downloads_batch

        with patch("collectors.pypi_downloads_bigquery_collector.WRITE_BATCH_SIZE", 2):
            success, errors = _write_downloads_batch(table, downloads)

        assert success == 5
        assert errors == 0


# ---------------------------------------------------------------------------
# _mark_packages_not_found
# ---------------------------------------------------------------------------


class TestMarkPackagesNotFound:
    """Tests for _mark_packages_not_found DynamoDB updates."""

    @mock_aws
    def test_marks_packages_with_zero_downloads_and_bigquery_not_found_source(self):
        """Packages not found get 0 downloads and 'bigquery_not_found' source."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "pypi#new-pkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "new-pkg",
            }
        )

        from collectors.pypi_downloads_bigquery_collector import _mark_packages_not_found

        success, errors = _mark_packages_not_found(table, {"new-pkg"})

        assert success == 1
        assert errors == 0

        item = table.get_item(Key={"pk": "pypi#new-pkg", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 0
        assert item["downloads_source"] == "bigquery_not_found"
        assert item["downloads_status"] == "collected"
        assert "downloads_fetched_at" in item

    @mock_aws
    def test_dry_run_does_not_write(self):
        """dry_run=True counts but does not update DynamoDB."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "pypi#new-pkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "new-pkg",
            }
        )

        from collectors.pypi_downloads_bigquery_collector import _mark_packages_not_found

        success, errors = _mark_packages_not_found(table, {"new-pkg"}, dry_run=True)

        assert success == 1
        assert errors == 0

        item = table.get_item(Key={"pk": "pypi#new-pkg", "sk": "LATEST"})["Item"]
        assert "downloads_source" not in item

    @mock_aws
    def test_handles_update_error_gracefully(self):
        """DynamoDB errors for individual packages are counted as errors."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        from collectors.pypi_downloads_bigquery_collector import _mark_packages_not_found

        with patch.object(
            table,
            "update_item",
            side_effect=ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Boom"}},
                "UpdateItem",
            ),
        ):
            success, errors = _mark_packages_not_found(table, {"pkg-a", "pkg-b"})

        assert success == 0
        assert errors == 2

    @mock_aws
    def test_empty_set_returns_zero_counts(self):
        """Empty package set produces zero counts."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        from collectors.pypi_downloads_bigquery_collector import _mark_packages_not_found

        success, errors = _mark_packages_not_found(table, set())

        assert success == 0
        assert errors == 0


# ---------------------------------------------------------------------------
# handler (integration-level tests with mocks)
# ---------------------------------------------------------------------------


class TestHandler:
    """Tests for the Lambda handler function.

    These tests mock _get_gcp_credentials, _query_bigquery_downloads, and
    _get_pypi_packages to isolate handler logic from external dependencies
    and moto's low-level paginator quirks.
    """

    def _mock_handler_deps(self, package_names, downloads_map, credentials=None):
        """Create context-manager patches for the handler's three dependencies.

        Args:
            package_names: list of package names _get_pypi_packages returns
            downloads_map: dict _query_bigquery_downloads returns
            credentials: dict or None for _get_gcp_credentials
        """
        if credentials is None:
            credentials = _fake_credentials()

        return (
            patch(
                "collectors.pypi_downloads_bigquery_collector._get_gcp_credentials",
                return_value=credentials,
            ),
            patch(
                "collectors.pypi_downloads_bigquery_collector._get_pypi_packages",
                return_value=package_names,
            ),
            patch(
                "collectors.pypi_downloads_bigquery_collector._query_bigquery_downloads",
                return_value=downloads_map,
            ),
        )

    @mock_aws
    def test_happy_path_end_to_end(self):
        """Full successful flow: credentials -> packages -> BigQuery -> DynamoDB."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

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

        creds_p, pkgs_p, bq_p = self._mock_handler_deps(
            package_names=["requests", "flask"],
            downloads_map={"requests": 5000000, "flask": 2000000},
        )

        with creds_p, pkgs_p, bq_p:
            from collectors.pypi_downloads_bigquery_collector import handler

            result = handler({}, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["packages_tracked"] == 2
        assert body["packages_found_in_bigquery"] == 2
        assert body["packages_not_found"] == 0
        assert body["packages_updated"] == 2
        assert body["errors"] == 0
        assert body["coverage_percent"] == 100.0

        # Verify DynamoDB was updated
        item = table.get_item(Key={"pk": "pypi#requests", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 5000000
        assert item["downloads_source"] == "bigquery"

    @mock_aws
    def test_returns_500_when_credentials_unavailable(self):
        """Returns 500 error when GCP credentials cannot be retrieved."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)

        with patch(
            "collectors.pypi_downloads_bigquery_collector._get_gcp_credentials",
            return_value=None,
        ):
            from collectors.pypi_downloads_bigquery_collector import handler

            result = handler({}, None)

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert "GCP credentials not available" in body["error"]
        assert "Configure" in body["message"]

    @mock_aws
    def test_returns_200_with_zero_when_no_pypi_packages(self):
        """Returns 200 with zero updates when no PyPI packages exist."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)

        creds_p, pkgs_p, bq_p = self._mock_handler_deps(
            package_names=[],
            downloads_map={},
        )

        with creds_p, pkgs_p, bq_p:
            from collectors.pypi_downloads_bigquery_collector import handler

            result = handler({}, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["packages_updated"] == 0
        assert body["message"] == "No PyPI packages found in database"

    @mock_aws
    def test_returns_500_when_bigquery_returns_empty(self):
        """Returns 500 when BigQuery query returns no results at all."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "pypi#requests",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "requests",
            }
        )

        creds_p, pkgs_p, bq_p = self._mock_handler_deps(
            package_names=["requests"],
            downloads_map={},
        )

        with creds_p, pkgs_p, bq_p:
            from collectors.pypi_downloads_bigquery_collector import handler

            result = handler({}, None)

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert "BigQuery query returned no results" in body["error"]

    @mock_aws
    def test_marks_not_found_packages(self):
        """Packages tracked but not found in BigQuery are marked as not_found."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

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
                "pk": "pypi#new-pkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "new-pkg",
            }
        )

        creds_p, pkgs_p, bq_p = self._mock_handler_deps(
            package_names=["requests", "new-pkg"],
            downloads_map={"requests": 5000000},
        )

        with creds_p, pkgs_p, bq_p:
            from collectors.pypi_downloads_bigquery_collector import handler

            result = handler({}, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["packages_found_in_bigquery"] == 1
        assert body["packages_not_found"] == 1
        assert body["packages_updated"] == 2

        # Verify not-found package was marked correctly
        item = table.get_item(Key={"pk": "pypi#new-pkg", "sk": "LATEST"})["Item"]
        assert item["weekly_downloads"] == 0
        assert item["downloads_source"] == "bigquery_not_found"

    @mock_aws
    def test_dry_run_mode(self):
        """dry_run=True counts operations but doesn't write to DynamoDB."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "pypi#requests",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "requests",
            }
        )

        creds_p, pkgs_p, bq_p = self._mock_handler_deps(
            package_names=["requests"],
            downloads_map={"requests": 5000000},
        )

        with creds_p, pkgs_p, bq_p:
            from collectors.pypi_downloads_bigquery_collector import handler

            result = handler({"dry_run": True}, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["dry_run"] is True
        assert body["packages_updated"] == 1

        # Verify DynamoDB was NOT updated
        item = table.get_item(Key={"pk": "pypi#requests", "sk": "LATEST"})["Item"]
        assert "weekly_downloads" not in item

    @mock_aws
    def test_limit_parameter_passed_to_bigquery(self):
        """Limit parameter from event is forwarded to _query_bigquery_downloads."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "pypi#requests",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "requests",
            }
        )

        with patch(
            "collectors.pypi_downloads_bigquery_collector._get_gcp_credentials",
            return_value=_fake_credentials(),
        ):
            with patch(
                "collectors.pypi_downloads_bigquery_collector._get_pypi_packages",
                return_value=["requests"],
            ):
                with patch(
                    "collectors.pypi_downloads_bigquery_collector._query_bigquery_downloads",
                    return_value={"requests": 1000},
                ) as mock_bq:
                    from collectors.pypi_downloads_bigquery_collector import handler

                    handler({"limit": 50}, None)

        # Verify limit=50 was passed
        mock_bq.assert_called_once()
        call_args = mock_bq.call_args
        # Third positional arg is limit
        assert call_args[0][2] == 50

    @mock_aws
    def test_coverage_calculation(self):
        """Coverage percentage is correctly calculated in the response."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        for name in ["pkg-a", "pkg-b", "pkg-c", "pkg-d"]:
            table.put_item(
                Item={
                    "pk": f"pypi#{name}",
                    "sk": "LATEST",
                    "ecosystem": "pypi",
                    "name": name,
                }
            )

        # 3 out of 4 found (75% coverage), pkg-c has 0 downloads
        creds_p, pkgs_p, bq_p = self._mock_handler_deps(
            package_names=["pkg-a", "pkg-b", "pkg-c", "pkg-d"],
            downloads_map={"pkg-a": 1000, "pkg-b": 2000, "pkg-c": 0},
        )

        with creds_p, pkgs_p, bq_p:
            from collectors.pypi_downloads_bigquery_collector import handler

            result = handler({}, None)

        body = json.loads(result["body"])
        assert body["coverage_percent"] == 75.0
        assert body["packages_with_downloads"] == 2  # pkg-c has 0 downloads
        assert body["packages_not_found"] == 1  # pkg-d not in BigQuery

    @mock_aws
    def test_default_event_parameters(self):
        """Handler defaults dry_run=False and limit=0 when not in event."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "pypi#requests",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "requests",
            }
        )

        with patch(
            "collectors.pypi_downloads_bigquery_collector._get_gcp_credentials",
            return_value=_fake_credentials(),
        ):
            with patch(
                "collectors.pypi_downloads_bigquery_collector._get_pypi_packages",
                return_value=["requests"],
            ):
                with patch(
                    "collectors.pypi_downloads_bigquery_collector._query_bigquery_downloads",
                    return_value={"requests": 1000},
                ) as mock_bq:
                    from collectors.pypi_downloads_bigquery_collector import handler

                    result = handler({}, None)

        body = json.loads(result["body"])
        assert body["dry_run"] is False

        # Verify limit=0 was passed (third positional arg)
        assert mock_bq.call_args[0][2] == 0

    @mock_aws
    def test_all_packages_not_found_in_bigquery(self):
        """When BigQuery returns data but none match tracked packages, returns 500."""
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        table = dynamodb.Table("pkgwatch-packages")

        table.put_item(
            Item={
                "pk": "pypi#my-pkg",
                "sk": "LATEST",
                "ecosystem": "pypi",
                "name": "my-pkg",
            }
        )

        # _query_bigquery_downloads filters by tracked packages, so if none match
        # it returns {}. The handler interprets {} as "no results" and returns 500.
        creds_p, pkgs_p, bq_p = self._mock_handler_deps(
            package_names=["my-pkg"],
            downloads_map={},  # No matches
        )

        with creds_p, pkgs_p, bq_p:
            from collectors.pypi_downloads_bigquery_collector import handler

            result = handler({}, None)

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert "BigQuery query returned no results" in body["error"]
