"""
Verify Email Endpoint - GET /verify?token=xxx

Verifies email and activates the user account with an API key.
Creates a session so user can immediately access their dashboard.
"""

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import API key generation from shared module
# Import session creation from auth_callback
from api.auth_callback import SESSION_TTL_DAYS, _create_session_token, _get_session_secret
from shared.auth import generate_api_key
from shared.recovery_utils import generate_recovery_codes
from shared.referral_utils import (
    PENDING_TIMEOUT_DAYS,
    REFERRED_USER_BONUS,
    generate_unique_referral_code,
    is_self_referral,
    lookup_referrer_by_code,
    record_referral_event,
    update_referrer_stats,
)

dynamodb = boto3.resource("dynamodb")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "pkgwatch-api-keys")
BASE_URL = os.environ.get("BASE_URL", "https://pkgwatch.dev")

# Pending key display TTL (5 minutes)
PENDING_KEY_TTL_SECONDS = 300

# Minimum response time to normalize timing and prevent enumeration attacks
MIN_RESPONSE_TIME_SECONDS = 1.0


def handler(event, context):
    """
    Lambda handler for GET /verify?token=xxx.

    Verifies the token and creates the user's API key.
    Redirects to dashboard on success.
    """
    start_time = time.time()

    # Extract token from query parameters
    params = event.get("queryStringParameters") or {}
    token = params.get("token", "")

    if not token:
        return _timed_redirect_with_error(start_time, "missing_token", "Verification token is required")

    table = dynamodb.Table(API_KEYS_TABLE)
    now = datetime.now(timezone.utc)

    # Query GSI for pending signup with this token (O(1) instead of O(n) scan)
    try:
        response = table.query(
            IndexName="verification-token-index",
            KeyConditionExpression=Key("verification_token").eq(token),
        )
    except Exception as e:
        logger.error(f"Error querying for token: {e}")
        return _timed_redirect_with_error(start_time, "internal_error", "Failed to verify token")

    items = response.get("Items", [])
    if not items:
        return _timed_redirect_with_error(start_time, "invalid_token", "Invalid or expired verification token")

    # GSI returns KEYS_ONLY, so fetch full record
    gsi_item = items[0]
    user_id = gsi_item["pk"]
    sk = gsi_item["sk"]

    # Verify it's a PENDING record (not some other record with same token somehow)
    if sk != "PENDING":
        return _timed_redirect_with_error(start_time, "invalid_token", "Invalid or expired verification token")

    # Fetch full record to get email and expiration
    try:
        full_response = table.get_item(Key={"pk": user_id, "sk": sk})
        pending_user = full_response.get("Item")
        if not pending_user:
            return _timed_redirect_with_error(start_time, "invalid_token", "Invalid or expired verification token")
    except Exception as e:
        logger.error(f"Error fetching user record: {e}")
        return _timed_redirect_with_error(start_time, "internal_error", "Failed to verify token")

    email = pending_user["email"]

    # Atomically delete pending record with conditional check to prevent replay attacks
    # SECURITY: Token must match to prevent race condition where attacker intercepts
    # verification link and uses it multiple times before user does
    try:
        table.delete_item(
            Key={"pk": user_id, "sk": "PENDING"},
            ConditionExpression="attribute_exists(verification_token) AND verification_token = :expected_token",
            ExpressionAttributeValues={":expected_token": token},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.warning(f"Verification token replay attempt for {user_id}")
            return _timed_redirect_with_error(
                start_time,
                "token_already_used",
                "This verification link has already been used. Please request a new one.",
            )
        logger.error(f"Failed to delete pending record: {e}")
        return _timed_redirect_with_error(start_time, "internal_error", "Failed to verify token")
    except Exception as e:
        logger.error(f"Failed to delete pending record: {e}")
        return _timed_redirect_with_error(start_time, "internal_error", "Failed to verify token")

    # Check expiration (after atomic delete to maintain security)
    expires_str = pending_user.get("verification_expires", "")
    if expires_str:
        try:
            expires = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
            if expires < now:
                return _timed_redirect_with_error(
                    start_time, "token_expired", "Verification link has expired. Please sign up again."
                )
        except (ValueError, TypeError):
            pass

    # Generate API key for the user
    try:
        api_key = generate_api_key(user_id=user_id, tier="free", email=email)
    except Exception as e:
        logger.error(f"Error generating API key: {e}")
        return _timed_redirect_with_error(start_time, "internal_error", "Failed to create API key")

    # Log without full email for privacy (GDPR compliance)
    email_prefix = email.split("@")[0][:3] if "@" in email else email[:3]
    email_domain = email.split("@")[1] if "@" in email else "unknown"
    logger.info(f"Email verified for {email_prefix}***@{email_domain}, API key created")

    # Store API key server-side for one-time retrieval via authenticated endpoint
    # SECURITY IMPROVEMENT: Key never exposed in cookie (even short-lived non-HttpOnly)
    # - Stored in PENDING_DISPLAY record with 5-minute TTL
    # - Retrieved via /auth/pending-key (requires session auth)
    # - One-time use: deleted after first retrieval
    ttl_timestamp = int(time.time()) + PENDING_KEY_TTL_SECONDS

    try:
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING_DISPLAY",
                "api_key": api_key,
                "created_at": now.isoformat(),
                "ttl": ttl_timestamp,
            }
        )
    except Exception as e:
        logger.error(f"Failed to store pending key display: {e}")
        # Continue anyway - user can still see key in dashboard list

    # Generate recovery codes for account security
    # These are generated during email verification so users have them from the start
    try:
        plaintext_codes, hashed_codes = generate_recovery_codes(count=4)

        # Generate a unique referral code for the new user
        user_referral_code = generate_unique_referral_code()

        # Process referral if signup used a referral code
        referral_code_used = pending_user.get("referral_code_used")
        referred_by = None
        referral_pending = False
        referral_pending_expires = None
        bonus_requests = 0

        if referral_code_used:
            referrer = lookup_referrer_by_code(referral_code_used)
            if referrer:
                referrer_id = referrer["user_id"]
                referrer_email = referrer.get("email", "")

                # Check for self-referral
                if is_self_referral(referrer_email, email):
                    logger.warning(f"Self-referral attempt blocked: {user_id}")
                else:
                    # Valid referral - set up the relationship
                    referred_by = referrer_id
                    referral_pending = True
                    referral_pending_expires = (now + timedelta(days=PENDING_TIMEOUT_DAYS)).isoformat()

                    # Credit referred user with bonus immediately
                    bonus_requests = REFERRED_USER_BONUS

                    # Record pending referral event
                    record_referral_event(
                        referrer_id=referrer_id,
                        referred_id=user_id,
                        event_type="pending",
                        referred_email=email,
                        reward_amount=0,  # Referrer hasn't been credited yet
                        ttl_days=PENDING_TIMEOUT_DAYS,
                    )

                    # Update referrer stats (total and pending count)
                    update_referrer_stats(
                        referrer_id,
                        total_delta=1,
                        pending_delta=1,
                    )

                    logger.info(
                        f"Referral processed: {user_id} referred by {referrer_id}, "
                        f"referred user credited {bonus_requests}"
                    )

        # Create USER_META with recovery codes, referral code, and initial counters
        user_meta_item = {
            "pk": user_id,
            "sk": "USER_META",
            "recovery_codes_hash": hashed_codes,
            "recovery_codes_count": 4,
            "recovery_codes_generated_at": now.isoformat(),
            "recovery_codes_shown": False,  # Track if user has seen codes
            "key_count": 1,
            "requests_this_month": 0,
            "referral_code": user_referral_code,
            "created_at": now.isoformat(),
            "bonus_requests": bonus_requests,
            "bonus_requests_lifetime": bonus_requests,
        }

        # Add referral tracking if referred
        if referred_by:
            user_meta_item["referred_by"] = referred_by
            user_meta_item["referred_at"] = now.isoformat()
            user_meta_item["referral_pending"] = referral_pending
            user_meta_item["referral_pending_expires"] = referral_pending_expires

        table.put_item(Item=user_meta_item)

        # Store plaintext codes for one-time retrieval (like PENDING_DISPLAY)
        # User will see these after dismissing the API key modal
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING_RECOVERY_CODES",
                "codes": plaintext_codes,
                "created_at": now.isoformat(),
                "ttl": ttl_timestamp,  # Same 5-min TTL as API key
            }
        )

        logger.info(f"Recovery codes generated for {email_prefix}***@{email_domain}")
    except Exception as e:
        logger.error(f"Failed to generate recovery codes: {e}")
        # Continue anyway - user can generate codes later from dashboard

    # Create session so user can access dashboard and retrieve their API key
    session_secret = _get_session_secret()
    if session_secret:
        session_expires = now + timedelta(days=SESSION_TTL_DAYS)
        session_data = {
            "user_id": user_id,
            "email": email,
            "tier": "free",  # New users always start on free tier
            "exp": int(session_expires.timestamp()),
        }
        session_token = _create_session_token(session_data, session_secret)
        cookie_value = (
            f"session={session_token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_TTL_DAYS * 86400}"
        )
    else:
        cookie_value = None
        logger.warning("Could not create session - SESSION_SECRET_ARN not configured")

    headers = {
        "Location": f"{BASE_URL}/dashboard?verified=true",
        "Cache-Control": "no-store",
        # Security headers to mitigate XSS during redirect
        "Content-Security-Policy": "default-src 'none'",
        "X-Content-Type-Options": "nosniff",
    }

    if cookie_value:
        headers["Set-Cookie"] = cookie_value

    return {
        "statusCode": 302,
        "headers": headers,
        "body": "",
    }


def _redirect_with_error(code: str, message: str) -> dict:
    """Redirect to signup page with error message."""
    redirect_params = urlencode(
        {
            "error": code,
            "message": message,
        }
    )
    return {
        "statusCode": 302,
        "headers": {
            "Location": f"{BASE_URL}/start?{redirect_params}",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'",
            "X-Content-Type-Options": "nosniff",
        },
        "body": "",
    }


def _timed_redirect_with_error(start_time: float, code: str, message: str) -> dict:
    """
    Redirect to start page with error message, after ensuring minimum response time.

    Timing normalization prevents attackers from distinguishing between
    'token not found' (fast) and 'token found but expired' (slower).
    """
    elapsed = time.time() - start_time
    if elapsed < MIN_RESPONSE_TIME_SECONDS:
        time.sleep(MIN_RESPONSE_TIME_SECONDS - elapsed)
    return _redirect_with_error(code, message)
