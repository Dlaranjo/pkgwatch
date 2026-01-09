# Agent Prompt: Testing Coverage Improvements

## Context

You are working on DepHealth, a dependency health intelligence platform. The test suite has excellent coverage for scoring algorithms but critical gaps in collectors and integration tests.

**Project Root:** `/home/iebt/projects/startup-experiment/work/dephealth`
**Review Document:** `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` (Section 8: Testing Review)

## Your Mission

Add comprehensive test coverage for untested modules, particularly data collectors, integration flows, and security scenarios.

## Current Test Coverage

| Component | Coverage | Test File |
|-----------|----------|-----------|
| `scoring/health_score.py` | Excellent (1588 lines) | `test_scoring.py` |
| `scoring/abandonment_risk.py` | Excellent | `test_scoring.py` |
| `api/get_package.py` | Good | `test_get_package.py` |
| `api/post_scan.py` | Good | `test_post_scan.py` |
| `shared/auth.py` | Good | `test_auth.py` |
| `collectors/*.py` | **ZERO** | None |
| `api/stripe_webhook.py` | **ZERO** | None |
| `api/dlq_processor.py` | **ZERO** | None |

## Critical Testing Gaps to Fill

### 1. Package Collector Tests (CRITICAL)

**Create:** `tests/test_collectors.py`

**Test the main orchestration logic:**

```python
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import json

# Test fixtures
@pytest.fixture
def sample_depsdev_response():
    return {
        "packageKey": {"system": "NPM", "name": "lodash"},
        "defaultVersion": "4.17.21",
        "projectKey": "github.com/lodash/lodash",
    }

@pytest.fixture
def sample_npm_response():
    return {
        "name": "lodash",
        "version": "4.17.21",
        "repository": {"url": "git+https://github.com/lodash/lodash.git"},
        "maintainers": [{"name": "jdalton"}],
    }

@pytest.fixture
def sample_github_response():
    return {
        "stargazers_count": 58000,
        "open_issues_count": 400,
        "archived": False,
        "pushed_at": "2024-01-15T00:00:00Z",
    }


class TestPackageCollector:
    """Tests for package_collector.py"""

    @pytest.mark.asyncio
    async def test_collect_package_data_success(
        self, sample_depsdev_response, sample_npm_response, sample_github_response
    ):
        """Test successful collection from all sources."""
        with patch("package_collector.get_depsdev_info", new_callable=AsyncMock) as mock_depsdev, \
             patch("package_collector.get_npm_metadata", new_callable=AsyncMock) as mock_npm, \
             patch("package_collector.get_github_data", new_callable=AsyncMock) as mock_github, \
             patch("package_collector.get_bundle_size", new_callable=AsyncMock) as mock_bundle:

            mock_depsdev.return_value = sample_depsdev_response
            mock_npm.return_value = sample_npm_response
            mock_github.return_value = sample_github_response
            mock_bundle.return_value = {"size": 72000, "gzip": 25000}

            from collectors.package_collector import collect_package_data
            result = await collect_package_data("npm", "lodash")

            assert result["name"] == "lodash"
            assert result["ecosystem"] == "npm"
            assert "deps.dev" in result["sources"]
            assert "npm" in result["sources"]
            assert "github" in result["sources"]

    @pytest.mark.asyncio
    async def test_collect_package_graceful_degradation(self, sample_depsdev_response):
        """Test collection continues when GitHub fails."""
        with patch("package_collector.get_depsdev_info", new_callable=AsyncMock) as mock_depsdev, \
             patch("package_collector.get_npm_metadata", new_callable=AsyncMock) as mock_npm, \
             patch("package_collector.get_github_data", new_callable=AsyncMock) as mock_github, \
             patch("package_collector.get_bundle_size", new_callable=AsyncMock) as mock_bundle:

            mock_depsdev.return_value = sample_depsdev_response
            mock_npm.return_value = {}
            mock_github.side_effect = Exception("GitHub API error")
            mock_bundle.return_value = None

            from collectors.package_collector import collect_package_data
            result = await collect_package_data("npm", "lodash")

            # Should still succeed with partial data
            assert result["name"] == "lodash"
            assert "deps.dev" in result["sources"]
            assert "github_error" in result

    @pytest.mark.asyncio
    async def test_github_rate_limit_respected(self):
        """Test that GitHub rate limit is checked before making calls."""
        with patch("package_collector._check_and_increment_github_rate_limit") as mock_rate_limit, \
             patch("package_collector.get_github_data", new_callable=AsyncMock) as mock_github:

            mock_rate_limit.return_value = False  # Rate limit exceeded

            from collectors.package_collector import collect_package_data
            result = await collect_package_data("npm", "lodash")

            # GitHub should not be called
            mock_github.assert_not_called()
            assert "github_error" in result or "github" not in result.get("sources", [])


class TestGitHubRateLimiting:
    """Tests for GitHub rate limiting logic."""

    def test_rate_limit_window_key_format(self):
        """Test rate limit window key generation."""
        from collectors.package_collector import _get_rate_limit_window_key

        key = _get_rate_limit_window_key()

        # Should be in format: hour#YYYY-MM-DD-HH
        assert key.startswith("hour#")
        parts = key.split("#")[1].split("-")
        assert len(parts) == 4  # year-month-day-hour

    @pytest.mark.asyncio
    async def test_rate_limit_check_allows_when_under_limit(self, mock_dynamodb):
        """Test rate limit allows requests when under limit."""
        # Setup DynamoDB with low usage
        table = mock_dynamodb.Table("dephealth-api-keys")

        from collectors.package_collector import _check_and_increment_github_rate_limit

        result = _check_and_increment_github_rate_limit()

        assert result is True

    @pytest.mark.asyncio
    async def test_rate_limit_blocks_when_exceeded(self, mock_dynamodb):
        """Test rate limit blocks when limit exceeded."""
        # Setup DynamoDB with usage at limit
        table = mock_dynamodb.Table("dephealth-api-keys")
        window_key = _get_rate_limit_window_key()

        # Fill all shards to limit
        for shard_id in range(10):
            table.put_item(Item={
                "pk": f"github_rate_limit#{shard_id}",
                "sk": window_key,
                "calls": 500,  # 500 * 10 shards = 5000 total
            })

        from collectors.package_collector import _check_and_increment_github_rate_limit

        result = _check_and_increment_github_rate_limit()

        assert result is False


class TestProcessBatch:
    """Tests for SQS batch processing."""

    @pytest.mark.asyncio
    async def test_process_batch_success(self, mock_dynamodb):
        """Test successful batch processing."""
        records = [
            {"body": json.dumps({"ecosystem": "npm", "name": "lodash", "tier": 1})},
            {"body": json.dumps({"ecosystem": "npm", "name": "express", "tier": 1})},
        ]

        with patch("package_collector.collect_package_data", new_callable=AsyncMock) as mock_collect, \
             patch("package_collector.store_package") as mock_store:

            mock_collect.return_value = {"name": "test", "ecosystem": "npm"}

            from collectors.package_collector import process_batch
            success, failures = await process_batch(records)

            assert success == 2
            assert failures == 0

    @pytest.mark.asyncio
    async def test_process_batch_partial_failure(self, mock_dynamodb):
        """Test batch processing with some failures."""
        records = [
            {"body": json.dumps({"ecosystem": "npm", "name": "lodash", "tier": 1})},
            {"body": json.dumps({"ecosystem": "npm", "name": "nonexistent", "tier": 1})},
        ]

        with patch("package_collector.collect_package_data", new_callable=AsyncMock) as mock_collect:
            # First succeeds, second fails
            mock_collect.side_effect = [
                {"name": "lodash", "ecosystem": "npm"},
                Exception("Package not found"),
            ]

            from collectors.package_collector import process_batch
            success, failures = await process_batch(records)

            assert success == 1
            assert failures == 1
```

### 2. DLQ Processor Tests (HIGH PRIORITY)

**Create:** `tests/test_dlq_processor.py`

```python
import pytest
from unittest.mock import patch, MagicMock
import json
from datetime import datetime, timezone


class TestDLQProcessor:
    """Tests for dlq_processor.py"""

    def test_handler_processes_messages(self, mock_dynamodb, mock_sqs):
        """Test DLQ processor retrieves and requeues messages."""
        # Setup mock SQS with messages
        mock_sqs.return_value.receive_message.return_value = {
            "Messages": [
                {
                    "MessageId": "msg-1",
                    "ReceiptHandle": "handle-1",
                    "Body": json.dumps({
                        "ecosystem": "npm",
                        "name": "lodash",
                        "_retry_count": 1,
                    }),
                }
            ]
        }

        from collectors.dlq_processor import handler
        result = handler({}, None)

        assert result["processed"] >= 1

    def test_handler_increments_retry_count(self, mock_dynamodb, mock_sqs):
        """Test retry count is incremented on requeue."""
        mock_sqs.return_value.receive_message.return_value = {
            "Messages": [
                {
                    "MessageId": "msg-1",
                    "ReceiptHandle": "handle-1",
                    "Body": json.dumps({
                        "ecosystem": "npm",
                        "name": "lodash",
                        "_retry_count": 2,
                    }),
                }
            ]
        }

        from collectors.dlq_processor import handler
        handler({}, None)

        # Verify send_message was called with incremented count
        send_call = mock_sqs.return_value.send_message.call_args
        body = json.loads(send_call.kwargs["MessageBody"])
        assert body["_retry_count"] == 3

    def test_handler_stores_permanent_failure(self, mock_dynamodb, mock_sqs):
        """Test messages exceeding max retries are stored permanently."""
        mock_sqs.return_value.receive_message.return_value = {
            "Messages": [
                {
                    "MessageId": "msg-1",
                    "ReceiptHandle": "handle-1",
                    "Body": json.dumps({
                        "ecosystem": "npm",
                        "name": "failing-package",
                        "_retry_count": 5,  # At max
                    }),
                }
            ]
        }

        from collectors.dlq_processor import handler
        handler({}, None)

        # Verify item stored in DynamoDB with FAILED# prefix
        table = mock_dynamodb.Table("dephealth-api-keys")
        response = table.scan(FilterExpression=Attr("pk").begins_with("FAILED#"))
        assert len(response["Items"]) >= 1

    def test_exponential_backoff_delay(self):
        """Test delay calculation uses exponential backoff."""
        from collectors.dlq_processor import _calculate_delay

        assert _calculate_delay(0) == 60   # 60 seconds
        assert _calculate_delay(1) == 120  # 2 minutes
        assert _calculate_delay(2) == 240  # 4 minutes
        assert _calculate_delay(3) == 480  # 8 minutes
        assert _calculate_delay(4) == 900  # 15 minutes (capped)
        assert _calculate_delay(5) == 900  # Still capped
```

### 3. Stripe Webhook Tests (HIGH PRIORITY)

**Create:** `tests/test_stripe_webhook.py`

```python
import pytest
from unittest.mock import patch, MagicMock
import json
import stripe


@pytest.fixture
def stripe_signature():
    """Generate a mock Stripe signature."""
    return "t=123456789,v1=abc123"


@pytest.fixture
def checkout_completed_event():
    return {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer": "cus_test123",
                "customer_email": "test@example.com",
                "subscription": "sub_test123",
                "metadata": {},
            }
        }
    }


@pytest.fixture
def subscription_deleted_event():
    return {
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "customer": "cus_test123",
                "id": "sub_test123",
            }
        }
    }


class TestStripeWebhook:
    """Tests for stripe_webhook.py"""

    def test_rejects_invalid_signature(self):
        """Test webhook rejects invalid Stripe signature."""
        event = {
            "headers": {"Stripe-Signature": "invalid"},
            "body": json.dumps({}),
        }

        with patch("stripe.Webhook.construct_event") as mock_construct:
            mock_construct.side_effect = stripe.error.SignatureVerificationError(
                "Invalid signature", "sig"
            )

            from api.stripe_webhook import handler
            result = handler(event, None)

            assert result["statusCode"] == 400

    def test_checkout_completed_upgrades_tier(
        self, mock_dynamodb, checkout_completed_event, stripe_signature
    ):
        """Test checkout.session.completed upgrades user tier."""
        # Setup user in database
        table = mock_dynamodb.Table("dephealth-api-keys")
        table.put_item(Item={
            "pk": "user_abc123",
            "sk": "key_hash_123",
            "email": "test@example.com",
            "tier": "free",
        })

        event = {
            "headers": {"Stripe-Signature": stripe_signature},
            "body": json.dumps(checkout_completed_event),
        }

        with patch("stripe.Webhook.construct_event") as mock_construct, \
             patch("stripe.Subscription.retrieve") as mock_sub:

            mock_construct.return_value = stripe.Event.construct_from(
                checkout_completed_event, stripe.api_key
            )
            mock_sub.return_value = MagicMock(
                items=MagicMock(data=[MagicMock(price=MagicMock(id="price_pro"))])
            )

            from api.stripe_webhook import handler
            result = handler(event, None)

            assert result["statusCode"] == 200

            # Verify tier was updated
            response = table.query(
                IndexName="email-index",
                KeyConditionExpression=Key("email").eq("test@example.com"),
            )
            assert response["Items"][0]["tier"] == "pro"

    def test_subscription_deleted_downgrades_to_free(
        self, mock_dynamodb, subscription_deleted_event, stripe_signature
    ):
        """Test subscription deletion downgrades user to free tier."""
        # Setup user in database with paid tier
        table = mock_dynamodb.Table("dephealth-api-keys")
        table.put_item(Item={
            "pk": "user_abc123",
            "sk": "key_hash_123",
            "email": "test@example.com",
            "tier": "pro",
            "stripe_customer_id": "cus_test123",
        })

        event = {
            "headers": {"Stripe-Signature": stripe_signature},
            "body": json.dumps(subscription_deleted_event),
        }

        with patch("stripe.Webhook.construct_event") as mock_construct:
            mock_construct.return_value = stripe.Event.construct_from(
                subscription_deleted_event, stripe.api_key
            )

            from api.stripe_webhook import handler
            result = handler(event, None)

            assert result["statusCode"] == 200

            # Verify tier was downgraded
            response = table.get_item(Key={"pk": "user_abc123", "sk": "key_hash_123"})
            assert response["Item"]["tier"] == "free"
```

### 4. Integration Tests (HIGH PRIORITY)

**Create:** `tests/test_integration_flows.py`

```python
import pytest
from unittest.mock import patch
import json


class TestSignupToVerifyFlow:
    """Integration tests for complete signup flow."""

    def test_complete_signup_flow(self, mock_dynamodb, mock_ses):
        """Test full flow: signup -> verify email -> get API key."""
        # Step 1: Signup
        signup_event = {
            "body": json.dumps({"email": "newuser@example.com"}),
            "headers": {"Content-Type": "application/json"},
        }

        from api.signup import handler as signup_handler
        signup_result = signup_handler(signup_event, None)

        assert signup_result["statusCode"] == 200

        # Step 2: Get verification token from DynamoDB
        table = mock_dynamodb.Table("dephealth-api-keys")
        response = table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("newuser@example.com"),
        )
        pending_user = response["Items"][0]
        assert pending_user["sk"] == "PENDING"
        token = pending_user["verification_token"]

        # Step 3: Verify email
        verify_event = {
            "queryStringParameters": {"token": token},
            "headers": {},
        }

        from api.verify_email import handler as verify_handler
        verify_result = verify_handler(verify_event, None)

        # Should redirect with API key in cookie
        assert verify_result["statusCode"] == 302
        assert "Set-Cookie" in verify_result["headers"]
        assert "new_api_key=dh_" in verify_result["headers"]["Set-Cookie"]


class TestMagicLinkFlow:
    """Integration tests for magic link authentication."""

    def test_complete_magic_link_flow(self, mock_dynamodb, mock_ses):
        """Test full flow: request magic link -> callback -> session."""
        # Setup existing user
        table = mock_dynamodb.Table("dephealth-api-keys")
        table.put_item(Item={
            "pk": "user_abc123",
            "sk": "key_hash_123",
            "email": "existing@example.com",
            "tier": "free",
        })

        # Step 1: Request magic link
        magic_link_event = {
            "body": json.dumps({"email": "existing@example.com"}),
            "headers": {"Content-Type": "application/json"},
        }

        from api.magic_link import handler as magic_link_handler
        magic_result = magic_link_handler(magic_link_event, None)

        assert magic_result["statusCode"] == 200

        # Step 2: Get magic token from DynamoDB
        response = table.get_item(Key={"pk": "user_abc123", "sk": "key_hash_123"})
        magic_token = response["Item"]["magic_token"]

        # Step 3: Callback with token
        callback_event = {
            "queryStringParameters": {"token": magic_token},
            "headers": {},
        }

        from api.auth_callback import handler as callback_handler
        callback_result = callback_handler(callback_event, None)

        # Should redirect with session cookie
        assert callback_result["statusCode"] == 302
        assert "Set-Cookie" in callback_result["headers"]
        assert "session=" in callback_result["headers"]["Set-Cookie"]


class TestPackageScanFlow:
    """Integration tests for package scanning."""

    def test_scan_with_mixed_results(self, mock_dynamodb, seeded_api_keys_table, seeded_packages_table):
        """Test scan with some packages found, some not."""
        event = {
            "body": json.dumps({
                "dependencies": {
                    "lodash": "^4.17.21",
                    "express": "^4.18.0",
                    "nonexistent-package-xyz": "^1.0.0",
                }
            }),
            "headers": {
                "Content-Type": "application/json",
                "X-API-Key": "dh_test_valid_key",
            },
        }

        from api.post_scan import handler
        result = handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        assert body["total"] == 3
        assert len(body["packages"]) == 2  # lodash and express found
        assert "nonexistent-package-xyz" in body["not_found"]
```

### 5. Security Tests (MEDIUM PRIORITY)

**Add to:** `tests/test_security.py`

```python
class TestInputValidation:
    """Tests for input validation and injection prevention."""

    def test_package_name_injection_prevention(self, seeded_api_keys_table):
        """Test that malicious package names don't cause issues."""
        malicious_names = [
            "../../../etc/passwd",
            "package\n\rname",
            "package<script>alert(1)</script>",
            "a" * 1000,  # Very long name
            "package; rm -rf /",
        ]

        for name in malicious_names:
            event = {
                "pathParameters": {"ecosystem": "npm", "name": name},
                "headers": {"X-API-Key": "dh_test_valid_key"},
            }

            from api.get_package import handler
            result = handler(event, None)

            # Should return 400 or 404, not 500
            assert result["statusCode"] in [400, 404], f"Failed for: {name}"

    def test_sql_injection_in_email(self):
        """Test SQL injection attempts in email field."""
        malicious_emails = [
            "test@example.com'; DROP TABLE users; --",
            "test@example.com OR 1=1",
            "admin'--@example.com",
        ]

        for email in malicious_emails:
            event = {
                "body": json.dumps({"email": email}),
                "headers": {"Content-Type": "application/json"},
            }

            from api.signup import handler
            result = handler(event, None)

            # Should reject invalid email format
            assert result["statusCode"] == 400


class TestRaceConditions:
    """Tests for race condition prevention."""

    def test_concurrent_api_key_creation(self, mock_dynamodb):
        """Test that concurrent key creation doesn't exceed limit."""
        # This is a documentation test - actual race condition testing
        # requires concurrent execution which is hard in unit tests
        pass  # See test_concurrency.py for existing tests
```

## Files to Create

| File | Purpose |
|------|---------|
| `tests/test_collectors.py` | Package collector tests |
| `tests/test_dlq_processor.py` | DLQ processor tests |
| `tests/test_stripe_webhook.py` | Stripe webhook tests |
| `tests/test_integration_flows.py` | End-to-end flow tests |

## Files to Modify

| File | Changes |
|------|---------|
| `tests/test_security.py` | Add injection and race condition tests |
| `tests/conftest.py` | Add new fixtures for collectors |

## Success Criteria

1. Collector tests with 80%+ coverage
2. DLQ processor tests covering all paths
3. Stripe webhook tests for all event types
4. Integration tests for signup and auth flows
5. Security tests for injection prevention
6. All existing tests continue to pass
7. Total test count increases by 50+ tests

## Running Tests

```bash
cd /home/iebt/projects/startup-experiment/work/dephealth

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=functions --cov-report=html

# Run specific test file
pytest tests/test_collectors.py -v

# Run specific test class
pytest tests/test_collectors.py::TestPackageCollector -v
```

## Reference

See `/home/iebt/projects/startup-experiment/work/dephealth/PRODUCT_REVIEW.md` Section 8 for full testing analysis.
