"""
Standardized error responses for the API.
"""

import json
from typing import Optional


class APIError(Exception):
    """Base class for API errors."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        details: Optional[dict] = None,
    ):
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)

    def to_response(self) -> dict:
        """Convert to API Gateway response format."""
        body = {
            "error": {
                "code": self.code,
                "message": self.message,
            }
        }
        if self.details:
            body["error"]["details"] = self.details

        return {
            "statusCode": self.status_code,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(body),
        }


class InvalidAPIKeyError(APIError):
    """Raised when API key is invalid or missing."""

    def __init__(self, message: str = "Invalid or missing API key"):
        super().__init__(
            code="invalid_api_key",
            message=message,
            status_code=401,
        )


class RateLimitExceededError(APIError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        limit: int,
        retry_after_seconds: int,
        upgrade_url: str = "https://pkgwatch.laranjo.dev/pricing",
    ):
        super().__init__(
            code="rate_limit_exceeded",
            message=f"Monthly limit of {limit} requests exceeded",
            status_code=429,
            details={
                "retry_after_seconds": retry_after_seconds,
                "upgrade_url": upgrade_url,
            },
        )
        self.retry_after_seconds = retry_after_seconds

    def to_response(self) -> dict:
        response = super().to_response()
        response["headers"]["Retry-After"] = str(self.retry_after_seconds)
        response["headers"]["X-RateLimit-Remaining"] = "0"
        return response


class PackageNotFoundError(APIError):
    """Raised when a package is not found."""

    def __init__(self, package: str, ecosystem: str = "npm"):
        super().__init__(
            code="package_not_found",
            message=f"Package '{package}' not found in {ecosystem}",
            status_code=404,
        )


class InvalidEcosystemError(APIError):
    """Raised when an invalid ecosystem is specified."""

    def __init__(self, ecosystem: str, supported: list[str] = None):
        supported = supported or ["npm"]
        super().__init__(
            code="invalid_ecosystem",
            message=f"Unsupported ecosystem: {ecosystem}. Supported: {', '.join(supported)}",
            status_code=400,
        )


class InvalidRequestError(APIError):
    """Raised for general invalid request errors."""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(
            code="invalid_request",
            message=message,
            status_code=400,
            details=details,
        )


class InternalError(APIError):
    """Raised for internal server errors."""

    def __init__(self, message: str = "An internal error occurred"):
        super().__init__(
            code="internal_error",
            message=message,
            status_code=500,
        )


# Note: error_response and success_response are now in response_utils.py
# They are re-exported via shared/__init__.py for backwards compatibility
