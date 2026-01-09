"""
Response utilities for Lambda handlers.

Provides consistent response formatting for success and error responses.
"""

import json
import os
from decimal import Decimal
from typing import Optional, Any, Dict, List

# CORS configuration
_PROD_ORIGINS = [
    "https://dephealth.laranjo.dev",
    "https://app.dephealth.laranjo.dev",
]
_DEV_ORIGINS = [
    "http://localhost:4321",  # Astro dev server
    "http://localhost:3000",
]
ALLOWED_ORIGINS: List[str] = (
    _PROD_ORIGINS + _DEV_ORIGINS
    if os.environ.get("ALLOW_DEV_CORS") == "true"
    else _PROD_ORIGINS
)


def get_cors_headers(origin: Optional[str]) -> Dict[str, str]:
    """
    Get CORS headers if origin is allowed.

    Args:
        origin: The Origin header from the request

    Returns:
        Dict with CORS headers if origin is allowed, empty dict otherwise
    """
    if origin and origin in ALLOWED_ORIGINS:
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-API-Key, Authorization",
            "Access-Control-Allow-Credentials": "true",
        }
    return {}


def decimal_default(obj: Any) -> Any:
    """JSON serializer for Decimal types from DynamoDB."""
    if isinstance(obj, Decimal):
        if obj % 1 == 0:
            return int(obj)
        return float(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def json_response(
    status_code: int, body: dict, headers: Optional[dict] = None
) -> dict:
    """
    Create standardized JSON response.

    Args:
        status_code: HTTP status code
        body: Response body dictionary
        headers: Optional additional headers

    Returns:
        Lambda response dictionary
    """
    response_headers = {"Content-Type": "application/json"}
    if headers:
        response_headers.update(headers)

    return {
        "statusCode": status_code,
        "headers": response_headers,
        "body": json.dumps(body, default=decimal_default),
    }


def error_response(
    status_code: int,
    code: str,
    message: str,
    headers: Optional[Dict[str, str]] = None,
    details: Optional[Dict[str, Any]] = None,
    retry_after: Optional[int] = None,
    origin: Optional[str] = None,
) -> dict:
    """
    Create an error response.

    Args:
        status_code: HTTP status code
        code: Machine-readable error code (snake_case)
        message: Human-readable error message
        headers: Additional response headers
        details: Optional additional error details
        retry_after: Optional Retry-After header value in seconds
        origin: Request Origin header for CORS

    Returns:
        Lambda response dict
    """
    response_headers = {"Content-Type": "application/json"}
    response_headers.update(get_cors_headers(origin))
    if headers:
        response_headers.update(headers)
    if retry_after is not None:
        response_headers["Retry-After"] = str(retry_after)

    body = {
        "error": {
            "code": code,
            "message": message,
        }
    }
    if details:
        body["error"]["details"] = details

    return {
        "statusCode": status_code,
        "headers": response_headers,
        "body": json.dumps(body, default=decimal_default),
    }


def success_response(
    data: Any,
    status_code: int = 200,
    headers: Optional[Dict[str, str]] = None,
    origin: Optional[str] = None,
) -> dict:
    """
    Create a success response.

    Args:
        data: Response body data
        status_code: HTTP status code (default 200)
        headers: Additional response headers
        origin: Request Origin header for CORS

    Returns:
        Lambda response dict
    """
    response_headers = {"Content-Type": "application/json"}
    response_headers.update(get_cors_headers(origin))
    if headers:
        response_headers.update(headers)

    return {
        "statusCode": status_code,
        "headers": response_headers,
        "body": json.dumps(data, default=decimal_default),
    }


def redirect_response(
    location: str,
    status_code: int = 302,
    headers: Optional[Dict[str, str]] = None,
) -> dict:
    """
    Create a redirect response.

    Args:
        location: Redirect URL
        status_code: HTTP status code (302 or 301)
        headers: Additional headers (e.g., Set-Cookie)

    Returns:
        Lambda response dict
    """
    response_headers = {"Location": location}
    if headers:
        response_headers.update(headers)

    return {
        "statusCode": status_code,
        "headers": response_headers,
        "body": "",
    }
