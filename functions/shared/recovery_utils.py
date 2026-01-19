"""
Recovery Utilities for Account Recovery System.

Provides secure generation and verification of recovery codes,
session IDs, and tokens for the account recovery flow.
"""

import secrets
import bcrypt
from typing import Optional


# Recovery code configuration
RECOVERY_CODE_SEGMENT_LENGTH = 4  # 4 hex chars per segment
RECOVERY_CODE_SEGMENTS = 4  # 4 segments = 16 hex chars = 64 bits entropy
BCRYPT_COST_FACTOR = 12  # bcrypt work factor (2^12 iterations)


def generate_recovery_codes(count: int = 8) -> tuple[list[str], list[str]]:
    """
    Generate recovery codes and their bcrypt hashes.

    Each code is 16 hex characters formatted as XXXX-XXXX-XXXX-XXXX,
    providing 64 bits of entropy. Codes are hashed with bcrypt for
    secure storage.

    Args:
        count: Number of codes to generate (default 8)

    Returns:
        Tuple of (plaintext_codes, bcrypt_hashes)
        - plaintext_codes: List of formatted codes to show user once
        - bcrypt_hashes: List of bcrypt hashes to store in database
    """
    plaintext_codes = []
    bcrypt_hashes = []

    for _ in range(count):
        # Generate 8 random bytes = 64 bits of entropy
        raw_bytes = secrets.token_bytes(8)
        hex_str = raw_bytes.hex().upper()

        # Format as XXXX-XXXX-XXXX-XXXX
        segments = [
            hex_str[i : i + RECOVERY_CODE_SEGMENT_LENGTH]
            for i in range(0, len(hex_str), RECOVERY_CODE_SEGMENT_LENGTH)
        ]
        formatted_code = "-".join(segments)
        plaintext_codes.append(formatted_code)

        # Hash with bcrypt for secure storage
        # Use the unformatted hex string for hashing (normalized)
        code_hash = bcrypt.hashpw(
            hex_str.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_COST_FACTOR)
        )
        bcrypt_hashes.append(code_hash.decode("utf-8"))

    return plaintext_codes, bcrypt_hashes


def normalize_recovery_code(code: str) -> str:
    """
    Normalize a recovery code for comparison.

    Removes dashes and converts to uppercase hex string.

    Args:
        code: Recovery code (with or without dashes)

    Returns:
        Normalized uppercase hex string
    """
    return code.replace("-", "").upper().strip()


def verify_recovery_code(code: str, hashed_codes: list[str]) -> tuple[bool, int]:
    """
    Verify a recovery code against stored hashes.

    Uses bcrypt.checkpw for timing-safe comparison against each
    stored hash. Returns the index of the matching code for
    atomic removal.

    Args:
        code: Recovery code to verify (with or without dashes)
        hashed_codes: List of bcrypt hashes from database

    Returns:
        Tuple of (is_valid, index)
        - is_valid: True if code matches any hash
        - index: Index of matching hash (-1 if not valid)
    """
    if not code or not hashed_codes:
        return False, -1

    normalized = normalize_recovery_code(code)

    # Validate format (should be 16 hex chars after normalization)
    if len(normalized) != 16 or not all(c in "0123456789ABCDEF" for c in normalized):
        return False, -1

    # Check against each stored hash
    for i, stored_hash in enumerate(hashed_codes):
        try:
            if bcrypt.checkpw(normalized.encode("utf-8"), stored_hash.encode("utf-8")):
                return True, i
        except (ValueError, TypeError):
            # Invalid hash format, skip
            continue

    return False, -1


def generate_recovery_session_id() -> str:
    """
    Generate a secure session ID for recovery flow.

    Returns:
        URL-safe session ID (32 bytes = 256 bits entropy)
    """
    return secrets.token_urlsafe(32)


def generate_recovery_token() -> str:
    """
    Generate a secure token for email update verification.

    This token is used after recovery code verification to
    allow the user to update their email address.

    Returns:
        URL-safe token (32 bytes = 256 bits entropy)
    """
    return secrets.token_urlsafe(32)


def mask_email(email: str) -> str:
    """
    Mask an email address for display during recovery.

    Shows first 1-2 characters before @, then *** and the domain.
    Examples:
        - john@example.com -> j***@example.com
        - ab@test.org -> a***@test.org
        - x@foo.com -> x***@foo.com

    Args:
        email: Full email address

    Returns:
        Masked email for display
    """
    if not email or "@" not in email:
        return "***@***.***"

    local, domain = email.rsplit("@", 1)

    if len(local) == 0:
        masked_local = "***"
    elif len(local) == 1:
        masked_local = local[0] + "***"
    else:
        # Show first character + ***
        masked_local = local[0] + "***"

    return f"{masked_local}@{domain}"


def validate_recovery_code_format(code: str) -> bool:
    """
    Validate recovery code format without checking against hashes.

    Accepts codes with or without dashes.

    Args:
        code: Recovery code to validate

    Returns:
        True if format is valid
    """
    if not code:
        return False

    normalized = normalize_recovery_code(code)
    return len(normalized) == 16 and all(c in "0123456789ABCDEF" for c in normalized)
