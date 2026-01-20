"""
Integration tests for PkgWatch end-to-end user flows.

These tests verify complete user journeys through the system,
using moto for full AWS mocking.

Run with: PYTHONPATH=functions python3 -m pytest tests/integration/
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

# Add functions directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "functions"))

# Import shared table creation helper from conftest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from conftest import create_dynamodb_tables


# =============================================================================
# Fixtures for Integration Tests
# =============================================================================


@pytest.fixture(autouse=True)
def aws_credentials():
    """Set fake AWS credentials for all tests."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["AWS_REGION"] = "us-east-1"


@pytest.fixture(autouse=True)
def reset_module_caches():
    """Reset module-level caches before and after each test.

    This prevents cache leakage between tests for modules that cache
    secrets or other configuration at module level.
    """
    # Reset BEFORE test to ensure fresh state
    _reset_caches()

    yield

    # Reset AFTER test to clean up
    _reset_caches()


def _reset_caches():
    """Helper to reset all module-level caches."""
    # Reset auth_callback session secret cache
    try:
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
    except (ImportError, AttributeError):
        pass

    # Reset stripe_webhook secrets cache, boto3 clients, and env-based constants
    try:
        import api.stripe_webhook as webhook_module
        webhook_module._stripe_secrets_cache = (None, None)
        webhook_module._stripe_secrets_cache_time = 0.0
        webhook_module._secretsmanager = None
        webhook_module._dynamodb = None
        # Re-read env vars that were captured at import time
        webhook_module.STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")
        webhook_module.STRIPE_WEBHOOK_SECRET_ARN = os.environ.get("STRIPE_WEBHOOK_SECRET_ARN")
        # Rebuild PRICE_TO_TIER from current env vars
        webhook_module.PRICE_TO_TIER = {
            (os.environ.get("STRIPE_PRICE_STARTER") or "price_starter"): "starter",
            (os.environ.get("STRIPE_PRICE_PRO") or "price_pro"): "pro",
            (os.environ.get("STRIPE_PRICE_BUSINESS") or "price_business"): "business",
        }
    except (ImportError, AttributeError):
        pass

    # Reset auth module's DynamoDB resource
    try:
        import shared.auth as auth_module
        auth_module._dynamodb = None
    except (ImportError, AttributeError):
        pass


@pytest.fixture
def mock_aws_services():
    """Provide all mocked AWS services needed for integration tests.

    Uses create_dynamodb_tables() from conftest.py to ensure table definitions
    stay in sync between unit and integration tests.
    """
    with mock_aws():
        # Create DynamoDB tables using shared helper
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        create_dynamodb_tables(dynamodb)

        # Set up SES for email sending
        ses = boto3.client("ses", region_name="us-east-1")
        ses.verify_email_identity(EmailAddress="noreply@pkgwatch.dev")

        # Set up Secrets Manager for session secret
        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-session-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions-1234567890"}'
        )

        # Set environment variables
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["BASE_URL"] = "https://test.pkgwatch.example.com"
        os.environ["SESSION_SECRET_ARN"] = "test-session-secret"

        yield {
            "dynamodb": dynamodb,
            "ses": ses,
            "secretsmanager": secretsmanager,
        }


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
def packages_table_with_data(mock_aws_services):
    """Seed packages table with test data."""
    table = mock_aws_services["dynamodb"].Table("pkgwatch-packages")

    # Add multiple packages with varying health scores
    packages = [
        {
            "pk": "npm#lodash",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "lodash",
            "health_score": 85,
            "risk_level": "LOW",
            "abandonment_risk": {"probability": 15, "risk_level": "LOW"},
            "weekly_downloads": 50000000,
            "dependents_count": 100000,
            "stars": 55000,
            "days_since_last_commit": 7,
            "commits_90d": 25,
            "active_contributors_90d": 5,
            "maintainer_count": 3,
            "is_deprecated": False,
            "archived": False,
            "openssf_score": Decimal("8.5"),
            "latest_version": "4.17.21",
            "last_published": "2024-01-15T00:00:00Z",
            "last_updated": "2024-01-15T00:00:00Z",
        },
        {
            "pk": "npm#express",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "express",
            "health_score": 90,
            "risk_level": "LOW",
            "abandonment_risk": {"probability": 10, "risk_level": "LOW"},
            "weekly_downloads": 30000000,
            "dependents_count": 80000,
            "stars": 60000,
            "days_since_last_commit": 3,
            "commits_90d": 50,
            "active_contributors_90d": 10,
            "maintainer_count": 5,
            "is_deprecated": False,
            "archived": False,
            "openssf_score": Decimal("9.0"),
            "latest_version": "4.18.2",
            "last_published": "2024-01-20T00:00:00Z",
            "last_updated": "2024-01-20T00:00:00Z",
        },
        {
            "pk": "npm#abandoned-pkg",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "abandoned-pkg",
            "health_score": 25,
            "risk_level": "HIGH",
            "abandonment_risk": {"probability": 85, "risk_level": "HIGH"},
            "weekly_downloads": 100,
            "dependents_count": 5,
            "stars": 50,
            "days_since_last_commit": 400,
            "commits_90d": 0,
            "active_contributors_90d": 0,
            "maintainer_count": 1,
            "is_deprecated": False,
            "archived": True,
            "openssf_score": Decimal("2.0"),
            "latest_version": "1.0.0",
            "last_published": "2022-01-01T00:00:00Z",
            "last_updated": "2024-01-01T00:00:00Z",
        },
        {
            "pk": "npm#react",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "react",
            "health_score": 95,
            "risk_level": "LOW",
            "abandonment_risk": {"probability": 5, "risk_level": "LOW"},
            "weekly_downloads": 20000000,
            "dependents_count": 150000,
            "stars": 200000,
            "days_since_last_commit": 1,
            "commits_90d": 100,
            "active_contributors_90d": 20,
            "maintainer_count": 10,
            "is_deprecated": False,
            "archived": False,
            "openssf_score": Decimal("9.5"),
            "latest_version": "18.2.0",
            "last_published": "2024-01-25T00:00:00Z",
            "last_updated": "2024-01-25T00:00:00Z",
        },
    ]

    for pkg in packages:
        table.put_item(Item=pkg)

    return table


def create_session_token(user_id: str, email: str, tier: str = "free") -> str:
    """Create a valid session token for testing."""
    session_secret = "test-secret-key-for-signing-sessions-1234567890"
    session_expires = datetime.now(timezone.utc) + timedelta(days=7)
    session_data = {
        "user_id": user_id,
        "email": email,
        "tier": tier,
        "exp": int(session_expires.timestamp()),
    }
    payload = base64.urlsafe_b64encode(json.dumps(session_data).encode()).decode()
    signature = hmac.new(
        session_secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{payload}.{signature}"


# =============================================================================
# Test 1: New User Signup Flow
# =============================================================================


class TestNewUserSignupFlow:
    """
    End-to-end test for new user signup:
    1. POST /signup with email
    2. Receive magic link (verification token created)
    3. GET /verify with token
    4. API key is created
    5. GET /api-keys returns the key
    6. POST /api-keys creates additional key
    """

    def test_complete_signup_flow(self, mock_aws_services, api_gateway_event):
        """Test the complete signup flow from email to API key."""
        # Step 1: POST /signup with email
        from api.signup import handler as signup_handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "newuser@example.com"})

        result = signup_handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Response no longer includes email to prevent enumeration
        assert "message" in body
        assert "verification" in body["message"].lower() or "email" in body["message"].lower()

        # Verify pending user was created
        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")
        from boto3.dynamodb.conditions import Key
        response = table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("newuser@example.com"),
        )
        assert len(response["Items"]) == 1
        pending_user = response["Items"][0]
        assert pending_user["sk"] == "PENDING"
        verification_token = pending_user["verification_token"]

        # Step 2: GET /verify with token (simulates clicking email link)
        from api.verify_email import handler as verify_handler

        verify_event = {
            "httpMethod": "GET",
            "headers": {},
            "pathParameters": {},
            "queryStringParameters": {"token": verification_token},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = verify_handler(verify_event, {})

        assert result["statusCode"] == 302
        location = result["headers"]["Location"]
        assert "dashboard" in location
        assert "verified=true" in location
        # Session cookie is set so user can access dashboard and retrieve their API key
        assert "Set-Cookie" in result["headers"]
        cookie = result["headers"]["Set-Cookie"]
        assert "session=" in cookie
        assert "HttpOnly" in cookie
        assert "Secure" in cookie

        # API key is stored in PENDING_DISPLAY for one-time retrieval
        pending_display = table.get_item(
            Key={"pk": pending_user["pk"], "sk": "PENDING_DISPLAY"}
        )
        assert "Item" in pending_display
        api_key = pending_display["Item"]["api_key"]
        assert api_key.startswith("pw_")

        # Verify PENDING record was deleted
        response = table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("newuser@example.com"),
        )
        # Now we should have an API key record (not PENDING)
        assert len(response["Items"]) == 1
        user_record = response["Items"][0]
        assert user_record["sk"] != "PENDING"
        user_id = user_record["pk"]

        # Step 3: Validate the generated API key works
        from shared.auth import validate_api_key

        user = validate_api_key(api_key)
        assert user is not None
        assert user["email"] == "newuser@example.com"
        assert user["tier"] == "free"

        # Step 4: GET /api-keys with session returns the key
        # First, create a session token (normally set by auth callback)
        session_token = create_session_token(user_id, "newuser@example.com", "free")

        from api.get_api_keys import handler as get_keys_handler

        get_keys_event = {
            "httpMethod": "GET",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = get_keys_handler(get_keys_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert len(body["api_keys"]) == 1
        assert body["api_keys"][0]["tier"] == "free"

        # Step 5: POST /api-keys creates a second key
        from api.create_api_key import handler as create_key_handler

        create_key_event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = create_key_handler(create_key_event, {})

        assert result["statusCode"] == 201
        body = json.loads(result["body"])
        second_key = body["api_key"]
        assert second_key.startswith("pw_")
        assert second_key != api_key  # Different key

        # Verify both keys work
        user1 = validate_api_key(api_key)
        user2 = validate_api_key(second_key)
        assert user1 is not None
        assert user2 is not None

    def test_signup_prevents_email_enumeration_for_existing_user(
        self, mock_aws_services, api_gateway_event
    ):
        """Test that signup returns same response for existing and new emails (security).

        Security: Returning different responses for existing vs non-existing emails
        would allow attackers to enumerate valid email addresses. The signup endpoint
        must return the same 200 response regardless of email existence.
        """
        # First, create a verified user
        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_existing_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_existing123",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "existing@example.com",
                "tier": "free",
                "email_verified": True,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.signup import handler as signup_handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "existing@example.com"})

        result = signup_handler(api_gateway_event, {})

        # Should return 200 (same as new signup) to prevent email enumeration
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Generic message that doesn't reveal email existence
        assert "message" in body
        assert "verification" in body["message"].lower() or "email" in body["message"].lower()


# =============================================================================
# Test 2: Package Lookup Flow
# =============================================================================


class TestPackageLookupFlow:
    """
    End-to-end test for package lookup:
    1. GET /v1/packages/npm/{name} with API key
    2. Usage counter increments
    3. Response includes health score
    4. Second request works (within limit)
    """

    def test_complete_package_lookup_flow(
        self, mock_aws_services, packages_table_with_data, api_gateway_event
    ):
        """Test the complete package lookup flow with API key."""
        # Create a user with API key
        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")

        from shared.auth import generate_api_key

        api_key = generate_api_key(
            user_id="user_lookup_test",
            tier="free",
            email="lookup@example.com"
        )

        # Reload the auth module to pick up new key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        # Step 1: GET /v1/packages/npm/lodash with API key
        from api.get_package import handler as get_package_handler

        api_gateway_event["httpMethod"] = "GET"
        api_gateway_event["headers"] = {"x-api-key": api_key}
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}

        result = get_package_handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        # Verify response contains health data
        assert body["package"] == "lodash"
        assert body["ecosystem"] == "npm"
        assert body["health_score"] == 85
        assert body["risk_level"] == "LOW"
        assert "signals" in body
        assert body["signals"]["weekly_downloads"] == 50000000

        # Verify rate limit headers
        assert "X-RateLimit-Limit" in result["headers"]
        assert result["headers"]["X-RateLimit-Limit"] == "5000"  # Free tier limit

        # Step 2: Verify usage counter incremented
        response = table.get_item(
            Key={"pk": "user_lookup_test", "sk": key_hash}
        )
        assert response["Item"]["requests_this_month"] == 1

        # Step 3: Make a second request
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "express"}

        result = get_package_handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "express"
        assert body["health_score"] == 90

        # Verify usage counter is now 2
        response = table.get_item(
            Key={"pk": "user_lookup_test", "sk": key_hash}
        )
        assert response["Item"]["requests_this_month"] == 2

        # Verify remaining count in headers
        assert result["headers"]["X-RateLimit-Remaining"] == "4998"

    def test_rate_limit_exceeded(
        self, mock_aws_services, packages_table_with_data, api_gateway_event
    ):
        """Test that requests are blocked when rate limit is exceeded."""
        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")

        from shared.auth import generate_api_key

        api_key = generate_api_key(
            user_id="user_rate_limited",
            tier="free",
            email="ratelimited@example.com"
        )
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        # Set user to be at limit (per-key for analytics)
        table.update_item(
            Key={"pk": "user_rate_limited", "sk": key_hash},
            UpdateExpression="SET requests_this_month = :val",
            ExpressionAttributeValues={":val": 5000},
        )

        # Set USER_META.requests_this_month to limit (rate limiting is user-level)
        table.put_item(
            Item={
                "pk": "user_rate_limited",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 5000,
            }
        )

        from api.get_package import handler as get_package_handler

        api_gateway_event["httpMethod"] = "GET"
        api_gateway_event["headers"] = {"x-api-key": api_key}
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}

        result = get_package_handler(api_gateway_event, {})

        assert result["statusCode"] == 429
        body = json.loads(result["body"])
        assert body["error"]["code"] == "rate_limit_exceeded"
        assert "Retry-After" in result["headers"]

    def test_package_not_found(
        self, mock_aws_services, packages_table_with_data, api_gateway_event
    ):
        """Test response for non-existent package."""
        from shared.auth import generate_api_key

        api_key = generate_api_key(
            user_id="user_notfound_test",
            tier="free",
            email="notfound@example.com"
        )

        from api.get_package import handler as get_package_handler

        api_gateway_event["httpMethod"] = "GET"
        api_gateway_event["headers"] = {"x-api-key": api_key}
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "nonexistent-pkg-xyz"}

        result = get_package_handler(api_gateway_event, {})

        assert result["statusCode"] == 404
        body = json.loads(result["body"])
        assert body["error"]["code"] == "package_not_found"


# =============================================================================
# Test 3: Bulk Scan Flow
# =============================================================================


class TestBulkScanFlow:
    """
    End-to-end test for bulk scan:
    1. POST /v1/scan with package list
    2. All packages are scored
    3. Usage is tracked correctly
    """

    def test_complete_bulk_scan_flow(
        self, mock_aws_services, packages_table_with_data, api_gateway_event
    ):
        """Test the complete bulk scan flow."""
        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")

        from shared.auth import generate_api_key

        api_key = generate_api_key(
            user_id="user_scan_test",
            tier="pro",  # Pro tier for higher limit
            email="scan@example.com"
        )
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        from api.post_scan import handler as scan_handler

        # Scan multiple packages
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"] = {"x-api-key": api_key}
        api_gateway_event["body"] = json.dumps({
            "dependencies": {
                "lodash": "^4.17.21",
                "express": "^4.18.0",
                "react": "^18.2.0",
            }
        })

        result = scan_handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        # Verify all packages are scored
        assert body["total"] == 3
        assert len(body["packages"]) == 3
        assert len(body["not_found"]) == 0

        # Verify package data is correct
        packages_by_name = {p["package"]: p for p in body["packages"]}
        assert "lodash" in packages_by_name
        assert "express" in packages_by_name
        assert "react" in packages_by_name

        assert packages_by_name["lodash"]["health_score"] == 85
        assert packages_by_name["react"]["health_score"] == 95

        # Verify risk level counts
        assert body["low"] == 3  # All three are LOW risk

        # Verify usage tracked correctly (3 packages = 3 requests)
        response = table.get_item(
            Key={"pk": "user_scan_test", "sk": key_hash}
        )
        assert response["Item"]["requests_this_month"] == 3

    def test_bulk_scan_with_package_json_content(
        self, mock_aws_services, packages_table_with_data, api_gateway_event
    ):
        """Test bulk scan with package.json content string."""
        from shared.auth import generate_api_key

        api_key = generate_api_key(
            user_id="user_scan_json_test",
            tier="free",
            email="scanjson@example.com"
        )

        from api.post_scan import handler as scan_handler

        package_json = json.dumps({
            "name": "test-app",
            "dependencies": {
                "lodash": "^4.17.21",
                "express": "^4.18.0",
            },
            "devDependencies": {
                "react": "^18.2.0",
            }
        })

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"] = {"x-api-key": api_key}
        api_gateway_event["body"] = json.dumps({"content": package_json})

        result = scan_handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 3

    def test_bulk_scan_handles_not_found_packages(
        self, mock_aws_services, packages_table_with_data, api_gateway_event
    ):
        """Test that bulk scan handles packages not in database."""
        from shared.auth import generate_api_key

        api_key = generate_api_key(
            user_id="user_scan_notfound_test",
            tier="free",
            email="scannotfound@example.com"
        )

        from api.post_scan import handler as scan_handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"] = {"x-api-key": api_key}
        api_gateway_event["body"] = json.dumps({
            "dependencies": {
                "lodash": "^4.17.21",
                "unknown-package-xyz": "^1.0.0",
            }
        })

        result = scan_handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["total"] == 2
        assert len(body["packages"]) == 1  # Only lodash found
        assert "unknown-package-xyz" in body["not_found"]


# =============================================================================
# Test 4: Billing Upgrade Flow
# =============================================================================


class TestBillingUpgradeFlow:
    """
    End-to-end test for billing upgrade:
    1. User on free tier
    2. Stripe checkout webhook
    3. User tier updated to pro
    4. Rate limits increased
    """

    def test_complete_billing_upgrade_flow(
        self, mock_aws_services, packages_table_with_data, api_gateway_event
    ):
        """Test the complete billing upgrade flow via Stripe webhook."""
        # Skip if stripe module is not installed
        pytest.importorskip("stripe")

        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")

        # Step 1: Create a free tier user
        from shared.auth import generate_api_key

        api_key = generate_api_key(
            user_id="user_upgrade_test",
            tier="free",
            email="upgrade@example.com"
        )
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        # Verify user is on free tier
        from shared.auth import validate_api_key
        user = validate_api_key(api_key)
        assert user["tier"] == "free"
        assert user["monthly_limit"] == 5000

        # Step 2: Simulate Stripe checkout.session.completed webhook
        # We need to mock the Stripe library for signature verification

        # Set up Stripe webhook secret
        webhook_secret = "whsec_test_secret_key_12345"
        secretsmanager = mock_aws_services["secretsmanager"]
        secretsmanager.create_secret(
            Name="test-stripe-webhook-secret",
            SecretString=json.dumps({"secret": webhook_secret})
        )
        secretsmanager.create_secret(
            Name="test-stripe-api-key",
            SecretString=json.dumps({"key": "sk_test_12345"})
        )

        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = "test-stripe-webhook-secret"
        os.environ["STRIPE_SECRET_ARN"] = "test-stripe-api-key"
        os.environ["STRIPE_PRICE_PRO"] = "price_pro_test"

        # Force the stripe_webhook module to re-read env vars
        _reset_caches()

        # Create the webhook payload
        checkout_session = {
            "id": "cs_test_123",
            "object": "checkout.session",
            "customer_email": "upgrade@example.com",
            "customer": "cus_test_123",
            "subscription": "sub_test_123",
        }

        stripe_event = {
            "id": "evt_test_123",
            "type": "checkout.session.completed",
            "data": {"object": checkout_session},
        }

        # Mock Stripe's Webhook.construct_event and Subscription.retrieve
        # Use readable timestamps for subscription period
        period_start = int(time.time())  # Now
        period_end = period_start + (30 * 24 * 60 * 60)  # 30 days later

        with patch("stripe.Webhook.construct_event") as mock_construct, \
             patch("stripe.Subscription.retrieve") as mock_sub_retrieve:

            mock_construct.return_value = stripe_event
            mock_sub_retrieve.return_value = {
                "id": "sub_test_123",
                "customer": "cus_test_123",
                "status": "active",
                "cancel_at_period_end": False,
                "current_period_start": period_start,
                "current_period_end": period_end,
                "items": {
                    "data": [{
                        "price": {"id": "price_pro_test"},
                        "current_period_start": period_start,
                        "current_period_end": period_end,
                    }]
                }
            }

            from api.stripe_webhook import handler as webhook_handler

            # Create webhook event
            webhook_event = {
                "httpMethod": "POST",
                "headers": {"stripe-signature": "valid_signature"},
                "body": json.dumps(stripe_event),
                "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
            }

            result = webhook_handler(webhook_event, {})

            assert result["statusCode"] == 200

        # Step 3: Verify user tier was updated to pro
        response = table.get_item(
            Key={"pk": "user_upgrade_test", "sk": key_hash}
        )
        item = response["Item"]
        assert item["tier"] == "pro"
        assert item["stripe_customer_id"] == "cus_test_123"
        assert item["stripe_subscription_id"] == "sub_test_123"

        # Step 4: Verify rate limits increased
        user = validate_api_key(api_key)
        assert user["tier"] == "pro"
        assert user["monthly_limit"] == 100000

    def test_subscription_deletion_downgrades_to_free(self, mock_aws_services, api_gateway_event):
        """Test that canceling subscription downgrades user to free tier."""
        # Skip if stripe module is not installed
        pytest.importorskip("stripe")

        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")

        # Create a pro tier user with Stripe customer ID
        from shared.auth import generate_api_key

        api_key = generate_api_key(
            user_id="user_downgrade_test",
            tier="pro",
            email="downgrade@example.com"
        )
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        # Set the Stripe customer ID
        table.update_item(
            Key={"pk": "user_downgrade_test", "sk": key_hash},
            UpdateExpression="SET stripe_customer_id = :cust, tier = :tier",
            ExpressionAttributeValues={
                ":cust": "cus_downgrade_123",
                ":tier": "pro",
            },
        )

        # Set up Stripe secrets
        webhook_secret = "whsec_test_secret_key_12345"
        secretsmanager = mock_aws_services["secretsmanager"]

        # Check if secrets already exist, if not create them
        try:
            secretsmanager.create_secret(
                Name="test-stripe-webhook-secret-2",
                SecretString=json.dumps({"secret": webhook_secret})
            )
        except secretsmanager.exceptions.ResourceExistsException:
            pass

        try:
            secretsmanager.create_secret(
                Name="test-stripe-api-key-2",
                SecretString=json.dumps({"key": "sk_test_12345"})
            )
        except secretsmanager.exceptions.ResourceExistsException:
            pass

        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = "test-stripe-webhook-secret-2"
        os.environ["STRIPE_SECRET_ARN"] = "test-stripe-api-key-2"

        # Force the stripe_webhook module to re-read env vars
        _reset_caches()

        # Create subscription deleted event
        subscription_deleted = {
            "id": "sub_downgrade_123",
            "object": "subscription",
            "customer": "cus_downgrade_123",
            "status": "canceled",
        }

        stripe_event = {
            "id": "evt_downgrade_123",
            "type": "customer.subscription.deleted",
            "data": {"object": subscription_deleted},
        }

        with patch("stripe.Webhook.construct_event") as mock_construct:
            mock_construct.return_value = stripe_event

            from api.stripe_webhook import handler as webhook_handler

            webhook_event = {
                "httpMethod": "POST",
                "headers": {"stripe-signature": "valid_signature"},
                "body": json.dumps(stripe_event),
                "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
            }

            result = webhook_handler(webhook_event, {})
            assert result["statusCode"] == 200

        # Verify user was downgraded to free
        response = table.get_item(
            Key={"pk": "user_downgrade_test", "sk": key_hash}
        )
        assert response["Item"]["tier"] == "free"


# =============================================================================
# Test 5: API Key Lifecycle
# =============================================================================


class TestApiKeyLifecycle:
    """
    End-to-end test for API key lifecycle:
    1. Create multiple keys
    2. Use each key
    3. Revoke a key
    4. Verify revoked key no longer works
    """

    def test_complete_api_key_lifecycle(
        self, mock_aws_services, packages_table_with_data, api_gateway_event
    ):
        """Test the complete API key lifecycle."""
        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")
        user_id = "user_lifecycle_test"
        email = "lifecycle@example.com"

        # Step 1: Create the first key manually (simulating verified signup)
        from shared.auth import generate_api_key, validate_api_key

        first_key = generate_api_key(user_id=user_id, tier="free", email=email)
        first_key_hash = hashlib.sha256(first_key.encode()).hexdigest()

        # Mark as verified
        table.update_item(
            Key={"pk": user_id, "sk": first_key_hash},
            UpdateExpression="SET email_verified = :v",
            ExpressionAttributeValues={":v": True},
        )

        # Step 2: Create additional keys via API
        session_token = create_session_token(user_id, email, "free")

        from api.create_api_key import handler as create_key_handler

        create_event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        # Create second key
        result = create_key_handler(create_event, {})
        assert result["statusCode"] == 201
        second_key = json.loads(result["body"])["api_key"]

        # Create third key
        result = create_key_handler(create_event, {})
        assert result["statusCode"] == 201
        third_key = json.loads(result["body"])["api_key"]

        # All keys should be valid
        assert validate_api_key(first_key) is not None
        assert validate_api_key(second_key) is not None
        assert validate_api_key(third_key) is not None

        # Step 3: Use each key to make requests
        from api.get_package import handler as get_package_handler

        for key in [first_key, second_key, third_key]:
            request_event = {
                "httpMethod": "GET",
                "headers": {"x-api-key": key},
                "pathParameters": {"ecosystem": "npm", "name": "lodash"},
                "queryStringParameters": {},
                "body": None,
                "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
            }
            result = get_package_handler(request_event, {})
            assert result["statusCode"] == 200

        # Step 4: List all keys
        from api.get_api_keys import handler as get_keys_handler

        list_event = {
            "httpMethod": "GET",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = get_keys_handler(list_event, {})
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert len(body["api_keys"]) == 3

        # Get the key_id of the second key (for revocation)
        second_key_hash = hashlib.sha256(second_key.encode()).hexdigest()
        second_key_id = second_key_hash[:16]

        # Step 5: Revoke the second key
        from api.revoke_api_key import handler as revoke_handler

        revoke_event = {
            "httpMethod": "DELETE",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {"key_id": second_key_id},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = revoke_handler(revoke_event, {})
        # 204 No Content is the correct status for successful DELETE
        assert result["statusCode"] == 204

        # Step 6: Verify revoked key no longer works
        assert validate_api_key(second_key) is None

        # Other keys still work
        assert validate_api_key(first_key) is not None
        assert validate_api_key(third_key) is not None

        # Step 7: Verify only 2 keys remain
        result = get_keys_handler(list_event, {})
        body = json.loads(result["body"])
        assert len(body["api_keys"]) == 2

    def test_cannot_revoke_last_key(self, mock_aws_services, api_gateway_event):
        """Test that the last API key cannot be revoked."""
        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")
        user_id = "user_last_key_test"
        email = "lastkey@example.com"

        # Create single key
        from shared.auth import generate_api_key

        only_key = generate_api_key(user_id=user_id, tier="free", email=email)
        only_key_hash = hashlib.sha256(only_key.encode()).hexdigest()
        only_key_id = only_key_hash[:16]

        # Mark as verified
        table.update_item(
            Key={"pk": user_id, "sk": only_key_hash},
            UpdateExpression="SET email_verified = :v",
            ExpressionAttributeValues={":v": True},
        )

        session_token = create_session_token(user_id, email, "free")

        from api.revoke_api_key import handler as revoke_handler

        revoke_event = {
            "httpMethod": "DELETE",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {"key_id": only_key_id},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = revoke_handler(revoke_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "cannot_revoke_last_key"

    def test_max_keys_limit(self, mock_aws_services, api_gateway_event):
        """Test that users cannot exceed max key limit."""
        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")
        user_id = "user_max_keys_test"
        email = "maxkeys@example.com"

        # Create 5 keys (the maximum)
        from shared.auth import generate_api_key

        for i in range(5):
            key = generate_api_key(user_id=user_id, tier="free", email=email if i == 0 else None)
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            table.update_item(
                Key={"pk": user_id, "sk": key_hash},
                UpdateExpression="SET email_verified = :v",
                ExpressionAttributeValues={":v": True},
            )

        session_token = create_session_token(user_id, email, "free")

        from api.create_api_key import handler as create_key_handler

        create_event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = create_key_handler(create_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "max_keys_reached"


# =============================================================================
# Test 6: Monthly Reset Flow
# =============================================================================


class TestMonthlyResetFlow:
    """
    End-to-end test for monthly reset:
    1. User has usage > 0
    2. Reset handler runs
    3. Usage is 0
    4. User can make new requests
    """

    def test_complete_monthly_reset_flow(
        self, mock_aws_services, packages_table_with_data, api_gateway_event
    ):
        """Test the complete monthly reset flow."""
        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")

        # Create multiple users with usage
        from shared.auth import generate_api_key

        users = []
        for i in range(3):
            api_key = generate_api_key(
                user_id=f"user_reset_test_{i}",
                tier="free",
                email=f"reset{i}@example.com"
            )
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            users.append({"api_key": api_key, "key_hash": key_hash, "user_id": f"user_reset_test_{i}"})

            # Set usage > 0
            table.update_item(
                Key={"pk": f"user_reset_test_{i}", "sk": key_hash},
                UpdateExpression="SET requests_this_month = :usage, email_verified = :v",
                ExpressionAttributeValues={":usage": 1000 + i * 500, ":v": True},
            )

        # Verify usage is set
        for user in users:
            response = table.get_item(
                Key={"pk": user["user_id"], "sk": user["key_hash"]}
            )
            assert response["Item"]["requests_this_month"] > 0

        # Step 2: Run reset handler
        from api.reset_usage import handler as reset_handler

        # Create a mock Lambda context
        mock_context = MagicMock()
        mock_context.get_remaining_time_in_millis.return_value = 300000  # 5 minutes
        mock_context.function_name = "test-reset-function"

        result = reset_handler({}, mock_context)

        assert result["statusCode"] == 200
        assert result["completed"] is True
        assert result["items_processed"] >= 3

        # Step 3: Verify usage is 0 for all users
        for user in users:
            response = table.get_item(
                Key={"pk": user["user_id"], "sk": user["key_hash"]}
            )
            assert response["Item"]["requests_this_month"] == 0
            assert "last_reset" in response["Item"]

        # Step 4: Verify users can make new requests
        from api.get_package import handler as get_package_handler

        for user in users:
            request_event = {
                "httpMethod": "GET",
                "headers": {"x-api-key": user["api_key"]},
                "pathParameters": {"ecosystem": "npm", "name": "lodash"},
                "queryStringParameters": {},
                "body": None,
                "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
            }
            result = get_package_handler(request_event, {})
            assert result["statusCode"] == 200

        # Verify usage is now 1 for each user
        for user in users:
            response = table.get_item(
                Key={"pk": user["user_id"], "sk": user["key_hash"]}
            )
            assert response["Item"]["requests_this_month"] == 1

    def test_reset_skips_system_and_pending_records(self, mock_aws_services):
        """Test that reset skips SYSTEM# records and PENDING signups."""
        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")

        # Create a PENDING signup
        table.put_item(
            Item={
                "pk": "user_pending_123",
                "sk": "PENDING",
                "email": "pending@example.com",
                "verification_token": "abc123",
            }
        )

        # Create a demo rate limit record
        table.put_item(
            Item={
                "pk": "demo#192.168.1.1",
                "sk": "hour#2024-01-15-10",
                "requests": 5,
            }
        )

        # Create a regular user
        from shared.auth import generate_api_key

        api_key = generate_api_key(
            user_id="user_skip_test",
            tier="free",
            email="skiptest@example.com"
        )
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        table.update_item(
            Key={"pk": "user_skip_test", "sk": key_hash},
            UpdateExpression="SET requests_this_month = :usage",
            ExpressionAttributeValues={":usage": 500},
        )

        from api.reset_usage import handler as reset_handler

        mock_context = MagicMock()
        mock_context.get_remaining_time_in_millis.return_value = 300000
        mock_context.function_name = "test-reset-function"

        result = reset_handler({}, mock_context)

        assert result["statusCode"] == 200

        # Regular user was reset
        response = table.get_item(
            Key={"pk": "user_skip_test", "sk": key_hash}
        )
        assert response["Item"]["requests_this_month"] == 0

        # PENDING record still exists unchanged
        response = table.get_item(
            Key={"pk": "user_pending_123", "sk": "PENDING"}
        )
        assert "Item" in response
        assert response["Item"]["verification_token"] == "abc123"

        # Demo record still exists unchanged
        response = table.get_item(
            Key={"pk": "demo#192.168.1.1", "sk": "hour#2024-01-15-10"}
        )
        assert "Item" in response
        assert response["Item"]["requests"] == 5

    def test_reset_resumes_from_stored_state(self, mock_aws_services):
        """Test that reset can resume from stored state."""
        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")

        # Create a stored reset state from a previous partial run
        current_month = datetime.now(timezone.utc).strftime("%Y-%m")
        table.put_item(
            Item={
                "pk": "SYSTEM#RESET_STATE",
                "sk": "monthly_reset",
                "reset_month": current_month,
                "last_key": {"pk": "user_abc", "sk": "hash123"},
                "items_processed": 50,
                "stored_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.reset_usage import handler as reset_handler

        mock_context = MagicMock()
        mock_context.get_remaining_time_in_millis.return_value = 300000
        mock_context.function_name = "test-reset-function"

        # The handler should resume from the stored state
        result = reset_handler({}, mock_context)

        assert result["statusCode"] == 200

        # State should be cleared after completion
        response = table.get_item(
            Key={"pk": "SYSTEM#RESET_STATE", "sk": "monthly_reset"}
        )
        assert "Item" not in response


# =============================================================================
# Additional Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Additional edge case tests for comprehensive coverage."""

    def test_invalid_api_key_falls_back_to_demo_mode(
        self, mock_aws_services, packages_table_with_data, api_gateway_event
    ):
        """Test that invalid API key formats fall back to demo mode.

        Security: Invalid API keys should not cause errors, but rather fall back
        to demo mode which has its own IP-based rate limiting.
        """
        from api.get_package import handler as get_package_handler

        # Test various invalid formats - use unique IPs to avoid demo rate limit
        invalid_keys = [
            ("", "10.0.0.1"),
            ("invalid_key", "10.0.0.2"),
            ("wrong_prefix_abc123", "10.0.0.3"),
            ("pw_", "10.0.0.4"),  # Too short
            (None, "10.0.0.5"),
        ]

        for invalid_key, source_ip in invalid_keys:
            api_gateway_event["headers"] = {"x-api-key": invalid_key}
            api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
            api_gateway_event["requestContext"]["identity"]["sourceIp"] = source_ip

            result = get_package_handler(api_gateway_event, {})
            # Should succeed in demo mode
            assert result["statusCode"] == 200, f"Key '{invalid_key}' failed"
            # Verify demo mode is being used
            assert result["headers"].get("X-Demo-Mode") == "true"

    def test_session_expiry(self, mock_aws_services, api_gateway_event):
        """Test that expired sessions are rejected."""
        # Create an expired session token
        session_secret = "test-secret-key-for-signing-sessions-1234567890"
        expired_time = datetime.now(timezone.utc) - timedelta(days=10)
        session_data = {
            "user_id": "user_expired",
            "email": "expired@example.com",
            "tier": "free",
            "exp": int(expired_time.timestamp()),  # Expired
        }
        payload = base64.urlsafe_b64encode(json.dumps(session_data).encode()).decode()
        signature = hmac.new(
            session_secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        expired_token = f"{payload}.{signature}"

        from api.get_api_keys import handler as get_keys_handler

        api_gateway_event["headers"] = {"cookie": f"session={expired_token}"}

        result = get_keys_handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"

    def test_usage_tracking_enforces_limit_atomically(self, mock_aws_services, packages_table_with_data):
        """Test that usage tracking correctly enforces limits at boundary.

        Note: True concurrency testing is limited by moto's thread-safety.
        This test validates atomic conditional check behavior instead.
        """
        from shared.auth import generate_api_key, check_and_increment_usage

        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")

        api_key = generate_api_key(
            user_id="user_atomic_test",
            tier="free",
            email="atomic@example.com"
        )
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        # Initialize USER_META at limit - 1
        limit = 5000
        table.put_item(
            Item={
                "pk": "user_atomic_test",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": limit - 1,
            }
        )

        # First call should succeed (at limit - 1, goes to limit)
        allowed1, count1 = check_and_increment_usage("user_atomic_test", key_hash, limit)
        assert allowed1 is True
        assert count1 == limit

        # Second call should fail (at limit)
        allowed2, count2 = check_and_increment_usage("user_atomic_test", key_hash, limit)
        assert allowed2 is False

        # Verify USER_META counter is exactly at limit
        response = table.get_item(Key={"pk": "user_atomic_test", "sk": "USER_META"})
        assert response["Item"]["requests_this_month"] == limit

    def test_demo_mode_rate_limiting(self, mock_aws_services, packages_table_with_data, api_gateway_event):
        """Test demo mode IP-based rate limiting exhausts limit and blocks excess."""
        from api.get_package import handler as get_package_handler
        from shared.constants import DEMO_REQUESTS_PER_HOUR

        api_gateway_event["headers"] = {}
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["requestContext"]["identity"]["sourceIp"] = "192.168.1.100"

        # Make all allowed demo requests
        for i in range(DEMO_REQUESTS_PER_HOUR):
            result = get_package_handler(api_gateway_event, {})
            assert result["statusCode"] == 200, f"Request {i+1} failed"
            assert result["headers"].get("X-Demo-Mode") == "true"

        # Next request should be rate limited
        result = get_package_handler(api_gateway_event, {})
        assert result["statusCode"] == 429
        body = json.loads(result["body"])
        assert body["error"]["code"] == "demo_rate_limit_exceeded"


# =============================================================================
# Security Tests
# =============================================================================


class TestSessionSecurity:
    """Security tests for session handling and isolation."""

    def test_session_isolation_between_users(self, mock_aws_services, api_gateway_event):
        """Test that each session only returns that user's API keys.

        Security: Ensures user_id in session token is enforced and users
        cannot access other users' API keys.
        """
        from shared.auth import generate_api_key

        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")

        # Create two users with different tiers
        user1_key = generate_api_key(
            user_id="user_isolation_1",
            tier="free",
            email="isolation1@example.com"
        )
        user1_key_hash = hashlib.sha256(user1_key.encode()).hexdigest()
        user1_key_id = user1_key_hash[:16]  # API returns first 16 chars as key_id

        user2_key = generate_api_key(
            user_id="user_isolation_2",
            tier="pro",
            email="isolation2@example.com"
        )
        user2_key_hash = hashlib.sha256(user2_key.encode()).hexdigest()
        user2_key_id = user2_key_hash[:16]  # API returns first 16 chars as key_id

        # Mark both as verified
        for user_id, key_hash in [("user_isolation_1", user1_key_hash), ("user_isolation_2", user2_key_hash)]:
            table.update_item(
                Key={"pk": user_id, "sk": key_hash},
                UpdateExpression="SET email_verified = :v",
                ExpressionAttributeValues={":v": True},
            )

        # Create session tokens for each user
        session1 = create_session_token("user_isolation_1", "isolation1@example.com", "free")
        session2 = create_session_token("user_isolation_2", "isolation2@example.com", "pro")

        from api.get_api_keys import handler as get_keys_handler

        # User 1's session should only return User 1's keys
        api_gateway_event["headers"] = {"cookie": f"session={session1}"}
        result1 = get_keys_handler(api_gateway_event, {})
        assert result1["statusCode"] == 200
        body1 = json.loads(result1["body"])
        assert len(body1["api_keys"]) == 1
        assert body1["api_keys"][0]["tier"] == "free"
        # Verify it's actually User 1's key, not just any free-tier key
        assert body1["api_keys"][0]["key_id"] == user1_key_id

        # User 2's session should only return User 2's keys
        api_gateway_event["headers"] = {"cookie": f"session={session2}"}
        result2 = get_keys_handler(api_gateway_event, {})
        assert result2["statusCode"] == 200
        body2 = json.loads(result2["body"])
        assert len(body2["api_keys"]) == 1
        assert body2["api_keys"][0]["tier"] == "pro"
        # Verify it's actually User 2's key, not just any pro-tier key
        assert body2["api_keys"][0]["key_id"] == user2_key_id


class TestWebhookSecurity:
    """Security tests for Stripe webhook handling."""

    def test_webhook_idempotency(self, mock_aws_services, api_gateway_event):
        """Test that duplicate webhook events are handled idempotently.

        Security: Ensures the billing_events table deduplication works to
        prevent duplicate processing of webhook events.
        """
        pytest.importorskip("stripe")

        table = mock_aws_services["dynamodb"].Table("pkgwatch-api-keys")

        # Create a free tier user
        from shared.auth import generate_api_key

        api_key = generate_api_key(
            user_id="user_idempotent_test",
            tier="free",
            email="idempotent@example.com"
        )
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        # Set up Stripe secrets
        webhook_secret = "whsec_idempotent_test"
        secretsmanager = mock_aws_services["secretsmanager"]
        try:
            secretsmanager.create_secret(
                Name="test-stripe-webhook-idempotent",
                SecretString=json.dumps({"secret": webhook_secret})
            )
        except Exception:
            pass  # Secret may already exist

        try:
            secretsmanager.create_secret(
                Name="test-stripe-api-key-idempotent",
                SecretString=json.dumps({"key": "sk_test_idempotent"})
            )
        except Exception:
            pass

        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = "test-stripe-webhook-idempotent"
        os.environ["STRIPE_SECRET_ARN"] = "test-stripe-api-key-idempotent"
        os.environ["STRIPE_PRICE_PRO"] = "price_pro_idempotent"

        # Force the stripe_webhook module to re-read env vars
        _reset_caches()

        # Create checkout completed event
        checkout_session = {
            "id": "cs_idempotent_123",
            "object": "checkout.session",
            "customer_email": "idempotent@example.com",
            "customer": "cus_idempotent_123",
            "subscription": "sub_idempotent_123",
        }

        stripe_event = {
            "id": "evt_idempotent_123",  # Same event ID for both requests
            "type": "checkout.session.completed",
            "data": {"object": checkout_session},
        }

        # Use readable timestamps for subscription period
        period_start = int(time.time())
        period_end = period_start + (30 * 24 * 60 * 60)

        with patch("stripe.Webhook.construct_event") as mock_construct, \
             patch("stripe.Subscription.retrieve") as mock_sub_retrieve:

            mock_construct.return_value = stripe_event
            mock_sub_retrieve.return_value = {
                "id": "sub_idempotent_123",
                "customer": "cus_idempotent_123",
                "status": "active",
                "cancel_at_period_end": False,
                "current_period_start": period_start,
                "current_period_end": period_end,
                "items": {
                    "data": [{
                        "price": {"id": "price_pro_idempotent"},
                        "current_period_start": period_start,
                        "current_period_end": period_end,
                    }]
                }
            }

            from api.stripe_webhook import handler as webhook_handler

            webhook_event = {
                "httpMethod": "POST",
                "headers": {"stripe-signature": "valid_signature"},
                "body": json.dumps(stripe_event),
                "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
            }

            # First request - should process successfully
            result1 = webhook_handler(webhook_event, {})
            assert result1["statusCode"] == 200
            body1 = json.loads(result1["body"])
            assert body1.get("received") is True

            # Verify user was upgraded to pro after first webhook
            response = table.get_item(Key={"pk": "user_idempotent_test", "sk": key_hash})
            assert response["Item"]["tier"] == "pro"

            # Second request with same event ID - should detect duplicate
            result2 = webhook_handler(webhook_event, {})
            assert result2["statusCode"] == 200
            body2 = json.loads(result2["body"])
            assert body2.get("duplicate") is True

            # Verify user tier is still pro (not double-upgraded or modified)
            response = table.get_item(Key={"pk": "user_idempotent_test", "sk": key_hash})
            assert response["Item"]["tier"] == "pro"

            # Verify billing event was recorded only once
            billing_table = mock_aws_services["dynamodb"].Table("pkgwatch-billing-events")
            response = billing_table.get_item(
                Key={"pk": "evt_idempotent_123", "sk": "checkout.session.completed"}
            )
            assert "Item" in response
