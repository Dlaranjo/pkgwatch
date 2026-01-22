"""
Referral Redirect Endpoint - GET /r/{code}

Redirects clean referral URLs to the start page with the referral code.
Example: /r/abc12345 -> /start?ref=abc12345
"""

import logging
import os
import re

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

BASE_URL = os.environ.get("BASE_URL", "https://pkgwatch.dev")

# Match referral_utils.py regex (alphanumeric + _ and - for backwards compatibility)
REFERRAL_CODE_REGEX = re.compile(r"^[a-zA-Z0-9_-]{6,12}$")


def handler(event, context):
    """
    Lambda handler for GET /r/{code}.

    Redirects to start page with referral code as query parameter.
    The frontend will capture this and store it in localStorage.
    """
    # Extract referral code from path
    path_params = event.get("pathParameters", {}) or {}
    code = path_params.get("code", "")

    if not code:
        # No code provided, redirect to start page without ref
        return {
            "statusCode": 302,
            "headers": {
                "Location": f"{BASE_URL}/start",
                "Cache-Control": "no-store",
            },
            "body": "",
        }

    # Validate code format (alphanumeric, _, -, 6-12 chars)
    if not REFERRAL_CODE_REGEX.match(code):
        logger.warning(f"Invalid referral code format in redirect: {code[:20]}")
        return {
            "statusCode": 302,
            "headers": {
                "Location": f"{BASE_URL}/start",
                "Cache-Control": "no-store",
            },
            "body": "",
        }

    # Redirect to start page with ref parameter
    # The frontend JavaScript will capture this and store it
    logger.info(f"Referral redirect for code: {code}")

    return {
        "statusCode": 302,
        "headers": {
            "Location": f"{BASE_URL}/start?ref={code}",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'",
            "X-Content-Type-Options": "nosniff",
        },
        "body": "",
    }
