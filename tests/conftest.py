"""
Shared pytest fixtures for DepHealth tests.
"""

import os
import sys

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

        # API keys table with GSI
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
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "key-hash-index",
                    "KeySchema": [{"AttributeName": "key_hash", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        yield dynamodb


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
        "openssf_score": 7.5,
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
