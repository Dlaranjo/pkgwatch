"""
Signup Endpoint - POST /signup

Creates a pending user account and sends verification email.
"""

import hashlib
import json
import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
ses = boto3.client("ses")
API_KEYS_TABLE = os.environ.get("API_KEYS_TABLE", "dephealth-api-keys")
VERIFICATION_EMAIL_SENDER = os.environ.get(
    "VERIFICATION_EMAIL_SENDER", "noreply@dephealth.laranjo.dev"
)
BASE_URL = os.environ.get("BASE_URL", "https://dephealth.laranjo.dev")

# Email validation regex
EMAIL_REGEX = re.compile(r"^[^@]+@[^@]+\.[^@]+$")


def handler(event, context):
    """
    Lambda handler for POST /signup.

    Request body:
    {
        "email": "user@example.com"
    }

    Creates a pending user and sends verification email.
    """
    # Parse request body
    try:
        body = json.loads(event.get("body", "{}"))
    except json.JSONDecodeError:
        return _error_response(400, "invalid_json", "Request body must be valid JSON")

    email = body.get("email", "").strip().lower()

    # Validate email format
    if not email or not EMAIL_REGEX.match(email):
        return _error_response(400, "invalid_email", "Please provide a valid email address")

    # Check if email already exists using email-index GSI
    table = dynamodb.Table(API_KEYS_TABLE)
    try:
        response = table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(email),
        )
        existing_items = response.get("Items", [])

        # Check for verified users
        for item in existing_items:
            if item.get("email_verified", False):
                return _error_response(
                    409, "email_exists", "This email is already registered. Try logging in instead."
                )

        # Clean up any stale pending signups (expired verification tokens)
        now = datetime.now(timezone.utc)
        for item in existing_items:
            if item.get("sk") == "PENDING":
                expires = item.get("verification_expires")
                if expires:
                    try:
                        expires_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                        if expires_dt < now:
                            # Delete expired pending signup
                            table.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})
                    except (ValueError, TypeError):
                        pass
                else:
                    # No expiry set, delete it
                    table.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})

    except Exception as e:
        logger.error(f"Error checking existing email: {e}")
        return _error_response(500, "internal_error", "Failed to process signup")

    # Generate user ID and verification token
    user_id = f"user_{hashlib.sha256(email.encode()).hexdigest()[:16]}"
    verification_token = secrets.token_urlsafe(32)
    verification_expires = (now + timedelta(hours=24)).isoformat()

    # Create pending user record
    try:
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": email,
                "verification_token": verification_token,
                "verification_expires": verification_expires,
                "created_at": now.isoformat(),
                "email_verified": False,
            },
            ConditionExpression="attribute_not_exists(pk) OR attribute_not_exists(sk)",
        )
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        # Rare race condition - another signup happened simultaneously
        return _error_response(409, "email_exists", "This email is already registered")
    except Exception as e:
        logger.error(f"Error creating pending user: {e}")
        return _error_response(500, "internal_error", "Failed to create account")

    # Send verification email
    verification_url = f"{BASE_URL}/verify?token={verification_token}"
    try:
        _send_verification_email(email, verification_url)
    except Exception as e:
        logger.error(f"Failed to send verification email: {e}")
        # Don't fail the signup if email fails - user can request resend
        # but log it for monitoring

    logger.info(f"Signup initiated for {email}")

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "message": "Check your email to verify your account",
            "email": email,
        }),
    }


def _send_verification_email(email: str, verification_url: str):
    """Send verification email via SES."""
    ses.send_email(
        Source=VERIFICATION_EMAIL_SENDER,
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Verify your DepHealth account", "Charset": "UTF-8"},
            "Body": {
                "Html": {
                    "Data": f"""
                    <html>
                    <body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h1 style="color: #1e293b;">Welcome to DepHealth</h1>
                        <p style="color: #475569; font-size: 16px;">
                            Click the button below to verify your email and get your API key:
                        </p>
                        <a href="{verification_url}"
                           style="display: inline-block; background: #3b82f6; color: white; padding: 12px 24px;
                                  text-decoration: none; border-radius: 6px; margin: 20px 0;">
                            Verify Email
                        </a>
                        <p style="color: #64748b; font-size: 14px;">
                            Or copy this link: <a href="{verification_url}">{verification_url}</a>
                        </p>
                        <p style="color: #94a3b8; font-size: 12px;">
                            This link expires in 24 hours. If you didn't sign up for DepHealth, you can ignore this email.
                        </p>
                    </body>
                    </html>
                    """,
                    "Charset": "UTF-8",
                },
                "Text": {
                    "Data": f"""Welcome to DepHealth

Click the link below to verify your email and get your API key:

{verification_url}

This link expires in 24 hours. If you didn't sign up for DepHealth, you can ignore this email.
""",
                    "Charset": "UTF-8",
                },
            },
        },
    )


def _error_response(status_code: int, code: str, message: str) -> dict:
    """Generate error response."""
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": {"code": code, "message": message}}),
    }
