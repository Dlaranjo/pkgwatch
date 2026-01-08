"""
Shared Response Utilities.

Provides common response helpers used across API handlers.

NOTE: This module consolidates response utilities. The `errors.py` module
contains error classes and also has error_response/success_response functions.
For consistency, prefer using this module's functions for simple responses,
and errors.py's classes for typed error handling.
"""

import json
from decimal import Decimal
from typing import Optional


def decimal_default(obj):
    """JSON encoder for Decimal types from DynamoDB."""
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
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
    headers: Optional[dict] = None,
    details: Optional[dict] = None,
) -> dict:
    """
    Generate standardized error response.

    Args:
        status_code: HTTP status code
        code: Error code (e.g., "invalid_request", "not_found")
        message: Human-readable error message
        headers: Optional additional headers (e.g., CORS)
        details: Optional additional error details

    Returns:
        Lambda response dictionary
    """
    response_headers = {"Content-Type": "application/json"}
    if headers:
        response_headers.update(headers)

    body = {"error": {"code": code, "message": message}}
    if details:
        body["error"]["details"] = details

    return {
        "statusCode": status_code,
        "headers": response_headers,
        "body": json.dumps(body),
    }


def success_response(
    body: dict,
    headers: Optional[dict] = None,
) -> dict:
    """
    Generate standardized success response (200 OK).

    Args:
        body: Response body dictionary
        headers: Optional additional headers

    Returns:
        Lambda response dictionary
    """
    return json_response(200, body, headers)
