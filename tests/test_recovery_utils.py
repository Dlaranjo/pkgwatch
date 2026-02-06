"""
Tests for recovery utility functions.

Tests cover:
- Recovery code generation and hashing
- Recovery code verification with PBKDF2
- Session and token generation
- Email masking for privacy
- Format validation
"""

import os
import sys

# Set environment for imports
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions"))

from shared.recovery_utils import (
    generate_recovery_codes,
    generate_recovery_session_id,
    generate_recovery_token,
    mask_email,
    normalize_recovery_code,
    validate_recovery_code_format,
    verify_recovery_code,
)


class TestGenerateRecoveryCodes:
    """Tests for recovery code generation."""

    def test_generates_correct_count(self):
        """Should generate the requested number of codes."""
        plaintext, hashes = generate_recovery_codes(count=8)
        assert len(plaintext) == 8
        assert len(hashes) == 8

    def test_generates_custom_count(self):
        """Should generate custom count of codes."""
        plaintext, hashes = generate_recovery_codes(count=4)
        assert len(plaintext) == 4
        assert len(hashes) == 4

    def test_code_format(self):
        """Should generate codes in XXXX-XXXX-XXXX-XXXX format."""
        plaintext, _ = generate_recovery_codes(count=1)
        code = plaintext[0]

        # Check format
        parts = code.split("-")
        assert len(parts) == 4
        for part in parts:
            assert len(part) == 4
            assert all(c in "0123456789ABCDEF" for c in part)

    def test_codes_are_unique(self):
        """Should generate unique codes."""
        plaintext, _ = generate_recovery_codes(count=100)
        assert len(set(plaintext)) == 100

    def test_hash_format(self):
        """Should generate hashes in salt$hash format."""
        _, hashes = generate_recovery_codes(count=1)
        hash_str = hashes[0]

        assert "$" in hash_str
        salt_hex, hash_hex = hash_str.split("$", 1)

        # Salt should be 16 bytes = 32 hex chars
        assert len(salt_hex) == 32
        # Hash should be 32 bytes = 64 hex chars
        assert len(hash_hex) == 64

    def test_each_hash_has_unique_salt(self):
        """Should generate unique salt for each code."""
        _, hashes = generate_recovery_codes(count=5)
        salts = [h.split("$")[0] for h in hashes]
        assert len(set(salts)) == 5


class TestNormalizeRecoveryCode:
    """Tests for recovery code normalization."""

    def test_removes_dashes(self):
        """Should remove dashes from code."""
        result = normalize_recovery_code("AAAA-BBBB-CCCC-DDDD")
        assert result == "AAAABBBBCCCCDDDD"

    def test_converts_to_uppercase(self):
        """Should convert to uppercase."""
        result = normalize_recovery_code("aaaa-bbbb-cccc-dddd")
        assert result == "AAAABBBBCCCCDDDD"

    def test_strips_whitespace(self):
        """Should strip whitespace."""
        result = normalize_recovery_code("  AAAA-BBBB-CCCC-DDDD  ")
        assert result == "AAAABBBBCCCCDDDD"

    def test_handles_no_dashes(self):
        """Should handle code without dashes."""
        result = normalize_recovery_code("AAAABBBBCCCCDDDD")
        assert result == "AAAABBBBCCCCDDDD"


class TestVerifyRecoveryCode:
    """Tests for recovery code verification."""

    def test_verifies_valid_code(self):
        """Should verify valid recovery code."""
        plaintext, hashes = generate_recovery_codes(count=3)

        # Verify each code
        for i, code in enumerate(plaintext):
            is_valid, index = verify_recovery_code(code, hashes)
            assert is_valid is True
            assert index == i

    def test_rejects_invalid_code(self):
        """Should reject invalid recovery code."""
        _, hashes = generate_recovery_codes(count=3)

        is_valid, index = verify_recovery_code("1111-2222-3333-4444", hashes)
        assert is_valid is False
        assert index == -1

    def test_verifies_code_without_dashes(self):
        """Should verify code entered without dashes."""
        plaintext, hashes = generate_recovery_codes(count=1)
        code_no_dashes = plaintext[0].replace("-", "")

        is_valid, index = verify_recovery_code(code_no_dashes, hashes)
        assert is_valid is True
        assert index == 0

    def test_verifies_lowercase_code(self):
        """Should verify lowercase code."""
        plaintext, hashes = generate_recovery_codes(count=1)
        code_lower = plaintext[0].lower()

        is_valid, index = verify_recovery_code(code_lower, hashes)
        assert is_valid is True
        assert index == 0

    def test_rejects_empty_code(self):
        """Should reject empty code."""
        _, hashes = generate_recovery_codes(count=1)

        is_valid, index = verify_recovery_code("", hashes)
        assert is_valid is False
        assert index == -1

    def test_rejects_none_code(self):
        """Should reject None code."""
        _, hashes = generate_recovery_codes(count=1)

        is_valid, index = verify_recovery_code(None, hashes)
        assert is_valid is False
        assert index == -1

    def test_handles_empty_hash_list(self):
        """Should handle empty hash list."""
        is_valid, index = verify_recovery_code("AAAA-BBBB-CCCC-DDDD", [])
        assert is_valid is False
        assert index == -1

    def test_handles_none_hash_list(self):
        """Should handle None hash list."""
        is_valid, index = verify_recovery_code("AAAA-BBBB-CCCC-DDDD", None)
        assert is_valid is False
        assert index == -1

    def test_rejects_wrong_length_code(self):
        """Should reject code with wrong length."""
        _, hashes = generate_recovery_codes(count=1)

        # Too short
        is_valid, index = verify_recovery_code("AAAA-BBBB-CCCC", hashes)
        assert is_valid is False
        assert index == -1

        # Too long
        is_valid, index = verify_recovery_code("AAAA-BBBB-CCCC-DDDD-EEEE", hashes)
        assert is_valid is False
        assert index == -1

    def test_rejects_non_hex_characters(self):
        """Should reject code with non-hex characters."""
        _, hashes = generate_recovery_codes(count=1)

        is_valid, index = verify_recovery_code("GGGG-HHHH-IIII-JJJJ", hashes)
        assert is_valid is False
        assert index == -1

    def test_handles_invalid_hash_format(self):
        """Should handle invalid hash format in list."""
        invalid_hashes = [
            "invalid_hash_no_dollar",
            "also$invalid$too_many_parts",
        ]

        is_valid, index = verify_recovery_code("AAAA-BBBB-CCCC-DDDD", invalid_hashes)
        assert is_valid is False
        assert index == -1

    def test_handles_invalid_hex_in_hash(self):
        """Should handle invalid hex in hash."""
        invalid_hashes = [
            "notvalidhex$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ]

        # This should be caught by the try/except
        is_valid, index = verify_recovery_code("AAAA-BBBB-CCCC-DDDD", invalid_hashes)
        assert is_valid is False
        assert index == -1

    def test_timing_safe_comparison(self):
        """Should use timing-safe comparison (test that it runs)."""
        plaintext, hashes = generate_recovery_codes(count=1)

        # Just verify the function works - actual timing safety is from hmac.compare_digest
        is_valid, index = verify_recovery_code(plaintext[0], hashes)
        assert is_valid is True


class TestGenerateRecoverySessionId:
    """Tests for recovery session ID generation."""

    def test_generates_string(self):
        """Should generate a string."""
        session_id = generate_recovery_session_id()
        assert isinstance(session_id, str)

    def test_generates_url_safe(self):
        """Should generate URL-safe characters."""
        session_id = generate_recovery_session_id()
        # URL-safe base64 uses alphanumeric plus - and _
        assert all(c.isalnum() or c in "-_" for c in session_id)

    def test_generates_unique_ids(self):
        """Should generate unique session IDs."""
        ids = [generate_recovery_session_id() for _ in range(100)]
        assert len(set(ids)) == 100

    def test_sufficient_length(self):
        """Should generate ID with sufficient entropy."""
        session_id = generate_recovery_session_id()
        # 32 bytes base64-encoded is at least 43 characters
        assert len(session_id) >= 40


class TestGenerateRecoveryToken:
    """Tests for recovery token generation."""

    def test_generates_string(self):
        """Should generate a string."""
        token = generate_recovery_token()
        assert isinstance(token, str)

    def test_generates_url_safe(self):
        """Should generate URL-safe characters."""
        token = generate_recovery_token()
        assert all(c.isalnum() or c in "-_" for c in token)

    def test_generates_unique_tokens(self):
        """Should generate unique tokens."""
        tokens = [generate_recovery_token() for _ in range(100)]
        assert len(set(tokens)) == 100

    def test_sufficient_length(self):
        """Should generate token with sufficient entropy."""
        token = generate_recovery_token()
        # 32 bytes base64-encoded is at least 43 characters
        assert len(token) >= 40


class TestMaskEmail:
    """Tests for email masking."""

    def test_masks_normal_email(self):
        """Should mask normal email address."""
        result = mask_email("john@example.com")
        assert result == "j***@example.com"

    def test_masks_short_local_part(self):
        """Should mask short local part."""
        result = mask_email("a@example.com")
        assert result == "a***@example.com"

    def test_masks_long_local_part(self):
        """Should mask long local part (only first char)."""
        result = mask_email("verylongname@example.com")
        assert result == "v***@example.com"

    def test_handles_empty_string(self):
        """Should handle empty string."""
        result = mask_email("")
        assert result == "***@***.***"

    def test_handles_none(self):
        """Should handle None-like input (would error, but function expects string)."""
        # The function expects a string, so this tests edge case
        result = mask_email("")
        assert "***" in result

    def test_handles_no_at_symbol(self):
        """Should handle email without @ symbol."""
        result = mask_email("notanemail")
        assert result == "***@***.***"

    def test_preserves_domain(self):
        """Should preserve the domain part."""
        result = mask_email("user@subdomain.example.org")
        assert result == "u***@subdomain.example.org"

    def test_handles_plus_addressing(self):
        """Should handle plus addressing."""
        result = mask_email("user+tag@example.com")
        assert result == "u***@example.com"

    def test_handles_multiple_at_symbols(self):
        """Should use last @ as separator."""
        result = mask_email("user@weird@example.com")
        # rsplit ensures we split on the last @
        assert result == "u***@example.com"


class TestValidateRecoveryCodeFormat:
    """Tests for recovery code format validation."""

    def test_validates_correct_format_with_dashes(self):
        """Should validate correct format with dashes."""
        assert validate_recovery_code_format("AAAA-BBBB-CCCC-DDDD") is True

    def test_validates_correct_format_without_dashes(self):
        """Should validate correct format without dashes."""
        assert validate_recovery_code_format("AAAABBBBCCCCDDDD") is True

    def test_validates_lowercase(self):
        """Should validate lowercase code."""
        assert validate_recovery_code_format("aaaa-bbbb-cccc-dddd") is True

    def test_validates_mixed_case(self):
        """Should validate mixed case code."""
        assert validate_recovery_code_format("AaAa-BbBb-CcCc-DdDd") is True

    def test_rejects_empty_code(self):
        """Should reject empty code."""
        assert validate_recovery_code_format("") is False

    def test_rejects_none(self):
        """Should reject None."""
        assert validate_recovery_code_format(None) is False

    def test_rejects_too_short(self):
        """Should reject code that's too short."""
        assert validate_recovery_code_format("AAAA-BBBB-CCCC") is False

    def test_rejects_too_long(self):
        """Should reject code that's too long."""
        assert validate_recovery_code_format("AAAA-BBBB-CCCC-DDDD-EEEE") is False

    def test_rejects_non_hex(self):
        """Should reject non-hex characters."""
        assert validate_recovery_code_format("GGGG-HHHH-IIII-JJJJ") is False

    def test_accepts_all_hex_digits(self):
        """Should accept all valid hex digits."""
        assert validate_recovery_code_format("0123-4567-89AB-CDEF") is True

    def test_rejects_special_characters(self):
        """Should reject special characters (except dash)."""
        assert validate_recovery_code_format("AAAA!BBBB@CCCC#DDDD") is False

    def test_handles_whitespace(self):
        """Should handle whitespace (strips it)."""
        assert validate_recovery_code_format("  AAAA-BBBB-CCCC-DDDD  ") is True


class TestIntegration:
    """Integration tests for the recovery utils module."""

    def test_full_code_lifecycle(self):
        """Test full lifecycle: generate, verify, and ensure consumed codes fail."""
        # Generate codes
        plaintext_codes, hashed_codes = generate_recovery_codes(count=4)

        # Verify first code
        is_valid, index = verify_recovery_code(plaintext_codes[0], hashed_codes)
        assert is_valid is True
        assert index == 0

        # Simulate consuming the code (remove from list)
        remaining_hashes = [h for i, h in enumerate(hashed_codes) if i != index]

        # Same code should now fail
        is_valid, index = verify_recovery_code(plaintext_codes[0], remaining_hashes)
        assert is_valid is False

        # Other codes should still work
        is_valid, index = verify_recovery_code(plaintext_codes[1], remaining_hashes)
        assert is_valid is True

    def test_code_verification_is_position_independent(self):
        """Verify that codes work regardless of position in the list."""
        plaintext_codes, hashed_codes = generate_recovery_codes(count=5)

        # Verify last code first
        is_valid, index = verify_recovery_code(plaintext_codes[4], hashed_codes)
        assert is_valid is True
        assert index == 4

        # Verify middle code
        is_valid, index = verify_recovery_code(plaintext_codes[2], hashed_codes)
        assert is_valid is True
        assert index == 2

        # Verify first code
        is_valid, index = verify_recovery_code(plaintext_codes[0], hashed_codes)
        assert is_valid is True
        assert index == 0
