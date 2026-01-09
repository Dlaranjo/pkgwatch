"""
Shared pytest fixtures for DepHealth tests.
"""

import os
import sys
from decimal import Decimal

import boto3
import pytest
from moto import mock_aws

# Add functions directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions"))


@pytest.fixture(autouse=True)
def aws_credentials():
    """Set fake AWS credentials for all tests."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["AWS_REGION"] = "us-east-1"


@pytest.fixture
def mock_dynamodb():
    """Provide mocked DynamoDB with tables."""
    with mock_aws():
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

        # API keys table with GSIs
        dynamodb.create_table(
            TableName="dephealth-api-keys",
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
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        # Packages table with GSIs
        dynamodb.create_table(
            TableName="dephealth-packages",
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
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        yield dynamodb


@pytest.fixture
def seeded_api_keys_table(mock_dynamodb):
    """API keys table with a test user."""
    import hashlib

    table = mock_dynamodb.Table("dephealth-api-keys")

    # Create a test API key
    test_key = "dh_test1234567890abcdef"
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
    table = mock_dynamodb.Table("dephealth-packages")

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
