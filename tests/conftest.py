"""
Shared pytest fixtures for PkgWatch tests.
"""

import os
import sys
from decimal import Decimal

import boto3
import pytest
from moto import mock_aws

# Add functions directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions"))


def pytest_configure(config):
    """Set AWS credentials before test collection.

    This runs before test collection starts, ensuring boto3 resource
    creation during imports doesn't fail with NoRegionError.
    """
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("AWS_REGION", "us-east-1")

    # Disable HTTP client connection pooling in tests to allow proper mocking
    # Each test creates fresh clients, allowing httpx.MockTransport to work
    os.environ["USE_CONNECTION_POOLING"] = "false"

    # Disable distributed circuit breaker in tests to use in-memory version
    os.environ.setdefault("USE_DISTRIBUTED_CIRCUIT_BREAKER", "false")


@pytest.fixture(autouse=True)
def aws_credentials():
    """Set fake AWS credentials for all tests."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["AWS_REGION"] = "us-east-1"


@pytest.fixture(autouse=True)
def reset_aws_clients():
    """Reset shared AWS client singletons between tests."""
    yield
    try:
        from shared.aws_clients import reset_clients
        reset_clients()
    except ImportError:
        pass


@pytest.fixture(autouse=True)
def reset_circuit_breakers():
    """Reset all circuit breaker states between tests to prevent pollution.

    This fixture ensures that circuit breaker state from one test doesn't
    affect subsequent tests.
    """
    # Reset BEFORE test as well
    _reset_circuits()

    yield  # Let the test run

    # Reset AFTER test
    _reset_circuits()


def _reset_circuits():
    """Helper to reset all circuit breaker states."""
    try:
        from shared.circuit_breaker import (
            GITHUB_CIRCUIT, NPM_CIRCUIT, DEPSDEV_CIRCUIT, BUNDLEPHOBIA_CIRCUIT,
            PYPI_CIRCUIT, DYNAMODB_CIRCUIT, CircuitBreakerState
        )
        GITHUB_CIRCUIT._state = CircuitBreakerState()
        NPM_CIRCUIT._state = CircuitBreakerState()
        DEPSDEV_CIRCUIT._state = CircuitBreakerState()
        BUNDLEPHOBIA_CIRCUIT._state = CircuitBreakerState()
        PYPI_CIRCUIT._state = CircuitBreakerState()
        DYNAMODB_CIRCUIT._state = CircuitBreakerState()
    except ImportError:
        pass  # Circuit breakers not imported yet


@pytest.fixture(autouse=True)
def reset_session_secret_cache():
    """Reset the session secret cache between tests to prevent pollution.

    This ensures that cached session secrets from one test don't affect
    subsequent tests that may need different mock secrets.
    """
    yield  # Let the test run

    # Reset AFTER test
    try:
        import api.auth_callback as auth_callback
        auth_callback._session_secret_cache = None
        auth_callback._session_secret_cache_time = 0.0
    except ImportError:
        pass  # Module not imported yet


def create_dynamodb_tables(dynamodb):
    """Create all DynamoDB tables with their GSIs.

    This is a shared helper used by both unit test fixtures (mock_dynamodb)
    and integration test fixtures (mock_aws_services) to ensure consistent
    table definitions and avoid duplication.

    Args:
        dynamodb: boto3 DynamoDB resource
    """
    # API keys table with GSIs
    dynamodb.create_table(
        TableName="pkgwatch-api-keys",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "key_hash", "AttributeType": "S"},
            {"AttributeName": "email", "AttributeType": "S"},
            {"AttributeName": "stripe_customer_id", "AttributeType": "S"},
            {"AttributeName": "verification_token", "AttributeType": "S"},
            {"AttributeName": "magic_token", "AttributeType": "S"},
            {"AttributeName": "referral_code", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "key-hash-index",
                "KeySchema": [{"AttributeName": "key_hash", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "email-index",
                "KeySchema": [{"AttributeName": "email", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "stripe-customer-index",
                "KeySchema": [{"AttributeName": "stripe_customer_id", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "verification-token-index",
                "KeySchema": [{"AttributeName": "verification_token", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "KEYS_ONLY"},
            },
            {
                "IndexName": "magic-token-index",
                "KeySchema": [{"AttributeName": "magic_token", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "KEYS_ONLY"},
            },
            {
                "IndexName": "referral-code-index",
                "KeySchema": [{"AttributeName": "referral_code", "KeyType": "HASH"}],
                "Projection": {
                    "ProjectionType": "INCLUDE",
                    "NonKeyAttributes": ["pk", "email"],
                },
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    # Packages table with GSIs
    dynamodb.create_table(
        TableName="pkgwatch-packages",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "tier", "AttributeType": "N"},
            {"AttributeName": "risk_level", "AttributeType": "S"},
            {"AttributeName": "last_updated", "AttributeType": "S"},
            {"AttributeName": "data_status", "AttributeType": "S"},
            {"AttributeName": "next_retry_at", "AttributeType": "S"},
            {"AttributeName": "ecosystem", "AttributeType": "S"},
            {"AttributeName": "weekly_downloads", "AttributeType": "N"},
            {"AttributeName": "source", "AttributeType": "S"},
            {"AttributeName": "created_at", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "tier-index",
                "KeySchema": [
                    {"AttributeName": "tier", "KeyType": "HASH"},
                    {"AttributeName": "last_updated", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "KEYS_ONLY"},
            },
            {
                "IndexName": "risk-level-index",
                "KeySchema": [
                    {"AttributeName": "risk_level", "KeyType": "HASH"},
                    {"AttributeName": "last_updated", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "data-status-index-v2",  # Matches production GSI name
                "KeySchema": [
                    {"AttributeName": "data_status", "KeyType": "HASH"},
                    {"AttributeName": "next_retry_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "downloads-index",
                "KeySchema": [
                    {"AttributeName": "ecosystem", "KeyType": "HASH"},
                    {"AttributeName": "weekly_downloads", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "INCLUDE", "NonKeyAttributes": ["name", "health_score", "risk_level"]},
            },
            {
                "IndexName": "source-index",
                "KeySchema": [
                    {"AttributeName": "source", "KeyType": "HASH"},
                    {"AttributeName": "created_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "KEYS_ONLY"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    # Billing events table for webhook audit trail
    dynamodb.create_table(
        TableName="pkgwatch-billing-events",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},   # event_id
            {"AttributeName": "sk", "KeyType": "RANGE"},  # event_type
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "customer_id", "AttributeType": "S"},
            {"AttributeName": "processed_at", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "customer-index",
                "KeySchema": [
                    {"AttributeName": "customer_id", "KeyType": "HASH"},
                    {"AttributeName": "processed_at", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )

    # Referral events table for tracking referral relationships and rewards
    dynamodb.create_table(
        TableName="pkgwatch-referral-events",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},   # referrer_id
            {"AttributeName": "sk", "KeyType": "RANGE"},  # referred_id#event_type
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "needs_retention_check", "AttributeType": "S"},
            {"AttributeName": "retention_check_date", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "retention-due-index",
                "KeySchema": [
                    {"AttributeName": "needs_retention_check", "KeyType": "HASH"},
                    {"AttributeName": "retention_check_date", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@pytest.fixture
def mock_dynamodb():
    """Provide mocked DynamoDB with tables."""
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)
        yield dynamodb


@pytest.fixture
def seeded_api_keys_table(mock_dynamodb):
    """API keys table with a test user."""
    import hashlib

    table = mock_dynamodb.Table("pkgwatch-api-keys")

    # Create a test API key
    test_key = "pw_test1234567890abcdef"
    key_hash = hashlib.sha256(test_key.encode()).hexdigest()

    table.put_item(
        Item={
            "pk": "user_test123",
            "sk": key_hash,
            "key_hash": key_hash,
            "email": "test@example.com",
            "tier": "free",
            "requests_this_month": 0,
            "created_at": "2024-01-01T00:00:00Z",
            "email_verified": True,
        }
    )

    return table, test_key


@pytest.fixture
def seeded_packages_table(mock_dynamodb, sample_healthy_package):
    """Packages table with test data."""
    table = mock_dynamodb.Table("pkgwatch-packages")

    # Add a healthy package
    table.put_item(
        Item={
            "pk": "npm#lodash",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "lodash",
            "health_score": 85,
            "risk_level": "LOW",
            "abandonment_risk": {"probability": 15, "risk_level": "LOW"},
            "last_updated": "2024-01-01T00:00:00Z",
            "latest_version": "4.17.21",
            "data_status": "complete",
            "queryable": True,  # Required for API to return 200
            **sample_healthy_package,
        }
    )

    # Add a risky package
    table.put_item(
        Item={
            "pk": "npm#abandoned-pkg",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "abandoned-pkg",
            "health_score": 25,
            "risk_level": "HIGH",
            "abandonment_risk": {"probability": 85, "risk_level": "HIGH"},
            "last_updated": "2024-01-01T00:00:00Z",
            "days_since_last_commit": 400,
            "active_contributors_90d": 0,
            "weekly_downloads": 50,
            "latest_version": "1.0.0",
            "data_status": "complete",
            "queryable": True,  # Required for API to return 200
        }
    )

    # Add a PyPI package
    table.put_item(
        Item={
            "pk": "pypi#requests",
            "sk": "LATEST",
            "ecosystem": "pypi",
            "name": "requests",
            "health_score": 90,
            "risk_level": "LOW",
            "abandonment_risk": {"probability": 10, "risk_level": "LOW"},
            "last_updated": "2024-01-01T00:00:00Z",
            "days_since_last_commit": 14,
            "active_contributors_90d": 8,
            "weekly_downloads": 5_000_000,
            "latest_version": "2.31.0",
            "data_status": "complete",
            "queryable": True,  # Required for API to return 200
        }
    )

    # Add a risky PyPI package
    table.put_item(
        Item={
            "pk": "pypi#old-flask-lib",
            "sk": "LATEST",
            "ecosystem": "pypi",
            "name": "old-flask-lib",
            "health_score": 30,
            "risk_level": "HIGH",
            "abandonment_risk": {"probability": 80, "risk_level": "HIGH"},
            "last_updated": "2024-01-01T00:00:00Z",
            "days_since_last_commit": 500,
            "active_contributors_90d": 0,
            "weekly_downloads": 100,
            "latest_version": "0.9.0",
            "data_status": "complete",
            "queryable": True,  # Required for API to return 200
        }
    )

    return table


@pytest.fixture
def api_gateway_event():
    """Base API Gateway event for Lambda handler tests."""
    return {
        "httpMethod": "GET",
        "headers": {},
        "pathParameters": {},
        "queryStringParameters": {},
        "body": None,
        "requestContext": {
            "identity": {"sourceIp": "127.0.0.1"},
        },
    }


@pytest.fixture
def sample_healthy_package():
    """Sample data for a healthy, well-maintained package."""
    return {
        "days_since_last_commit": 7,
        "active_contributors_90d": 5,
        "weekly_downloads": 1_000_000,
        "dependents_count": 5000,
        "stars": 10000,
        "commits_90d": 25,
        "last_published": "2026-01-01T00:00:00Z",
        "created_at": "2020-01-01T00:00:00Z",
        "total_contributors": 50,
        "openssf_score": Decimal("7.5"),  # DynamoDB requires Decimal
        "advisories": [],
    }


@pytest.fixture
def sample_abandoned_package():
    """Sample data for an abandoned package."""
    return {
        "days_since_last_commit": 400,
        "active_contributors_90d": 0,
        "weekly_downloads": 50,
        "dependents_count": 10,
        "stars": 100,
        "commits_90d": 0,
        "last_published": "2022-01-01T00:00:00Z",
        "created_at": "2018-01-01T00:00:00Z",
        "archived": True,
        "is_deprecated": False,
    }


@pytest.fixture
def sample_deprecated_package():
    """Sample data for a deprecated package."""
    return {
        "days_since_last_commit": 200,
        "active_contributors_90d": 0,
        "weekly_downloads": 100,
        "dependents_count": 50,
        "stars": 500,
        "commits_90d": 0,
        "last_published": "2023-01-01T00:00:00Z",
        "created_at": "2019-01-01T00:00:00Z",
        "is_deprecated": True,
        "archived": False,
    }
