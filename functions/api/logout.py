"""
Logout Endpoint - POST /auth/logout

Clears the session cookie to log the user out.
"""

import json
import logging

from shared.response_utils import get_cors_headers

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def handler(event, context):
    """
    Lambda handler for POST /auth/logout.

    Clears the session cookie by setting it with Max-Age=0.
    """
    # Extract origin for CORS
    headers = event.get("headers") or {}
    origin = headers.get("origin") or headers.get("Origin")
    cors_headers = get_cors_headers(origin)

    # Clear session cookie by setting Max-Age=0 and empty value
    # Cookie attributes must match the original cookie settings for proper clearing
    # Original cookie set in auth_callback.py: session=...; Path=/; HttpOnly; Secure; SameSite=Strict
    cookie_header = "session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict"

    logger.info("User logged out - session cookie cleared")

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Set-Cookie": cookie_header,
            **cors_headers,
        },
        "body": json.dumps({"message": "Logged out successfully"}),
    }
