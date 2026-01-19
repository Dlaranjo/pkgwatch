"""
Shared error classification for DLQ processing.

Centralizes error classification logic used by both package_collector
and dlq_processor to ensure consistent retry decisions.
"""

# Transient errors - worth retrying
TRANSIENT_PATTERNS = [
    "timeout",
    "timed out",
    "503",
    "502",
    "504",
    "rate limit",
    "too many requests",
    "connection",
    "connection reset",
    "connection refused",
    "unavailable",
    "temporarily",
    "temporarily unavailable",
    "service unavailable",
]

# Permanent errors - don't retry
PERMANENT_PATTERNS = [
    "404",
    "not found",
    "does not exist",
    "malformed",
    "forbidden",
    "unauthorized",
    # Security/structural errors - never retry
    "path traversal",
    "package name too long",
    "empty package name",
]


def classify_error(error_message: str) -> str:
    """
    Classify error as transient or permanent for DLQ retry decisions.

    Args:
        error_message: The error message to classify

    Returns:
        "permanent" - Don't retry, error is not recoverable
        "transient" - Retry later, error may be temporary
        "unknown" - Unable to classify, default handling applies
    """
    if not error_message:
        return "unknown"

    error_lower = error_message.lower()

    # Check for permanent errors first (don't retry these)
    for pattern in PERMANENT_PATTERNS:
        if pattern.lower() in error_lower:
            return "permanent"

    # Check for transient errors (worth retrying)
    for pattern in TRANSIENT_PATTERNS:
        if pattern.lower() in error_lower:
            return "transient"

    return "unknown"
