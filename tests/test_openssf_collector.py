"""Tests for OpenSSF Scorecard collector."""

import os
import sys

import httpx
import pytest
import respx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../functions/collectors"))

from openssf_collector import OPENSSF_API, get_openssf_scorecard


@pytest.fixture
def mock_openssf_response():
    """Sample OpenSSF Scorecard API response."""
    return {
        "score": 5.7,
        "date": "2026-01-26",
        "checks": [
            {"name": "Code-Review", "score": 9},
            {"name": "Maintained", "score": 10},
            {"name": "Vulnerabilities", "score": 10},
            {"name": "Security-Policy", "score": 5},
            {"name": "CI-Tests", "score": -1},  # Not applicable
        ]
    }


class TestGetOpenSSFScorecard:
    """Tests for get_openssf_scorecard function."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_successful_fetch(self, mock_openssf_response):
        """Test successful scorecard fetch."""
        respx.get(f"{OPENSSF_API}/projects/github.com/facebook/react").mock(
            return_value=httpx.Response(200, json=mock_openssf_response)
        )

        result = await get_openssf_scorecard("facebook", "react")

        assert result is not None
        assert result["openssf_score"] == 5.7
        assert result["openssf_date"] == "2026-01-26"
        assert result["openssf_source"] == "direct"
        # Check that score=-1 checks are filtered out
        assert len(result["openssf_checks"]) == 4
        assert all(c["score"] >= 0 for c in result["openssf_checks"])

    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_owner_returns_none(self):
        """Test that empty owner returns None."""
        result = await get_openssf_scorecard("", "react")
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_repo_returns_none(self):
        """Test that empty repo returns None."""
        result = await get_openssf_scorecard("facebook", "")
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_404_returns_none(self):
        """Test that 404 returns None (not an error)."""
        respx.get(f"{OPENSSF_API}/projects/github.com/unknown/repo").mock(
            return_value=httpx.Response(404)
        )

        result = await get_openssf_scorecard("unknown", "repo")
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_500_returns_none(self):
        """Test that server errors return None."""
        respx.get(f"{OPENSSF_API}/projects/github.com/facebook/react").mock(
            return_value=httpx.Response(500)
        )

        result = await get_openssf_scorecard("facebook", "react")
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_502_returns_none(self):
        """Test that 502 Bad Gateway returns None."""
        respx.get(f"{OPENSSF_API}/projects/github.com/facebook/react").mock(
            return_value=httpx.Response(502)
        )

        result = await get_openssf_scorecard("facebook", "react")
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_503_returns_none(self):
        """Test that 503 Service Unavailable returns None."""
        respx.get(f"{OPENSSF_API}/projects/github.com/facebook/react").mock(
            return_value=httpx.Response(503)
        )

        result = await get_openssf_scorecard("facebook", "react")
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_429_raises_for_circuit_breaker(self):
        """Test that 429 rate limit raises exception for circuit breaker."""
        respx.get(f"{OPENSSF_API}/projects/github.com/facebook/react").mock(
            return_value=httpx.Response(429)
        )

        with pytest.raises(httpx.HTTPStatusError):
            await get_openssf_scorecard("facebook", "react")

    @pytest.mark.asyncio
    @respx.mock
    async def test_timeout_raises_for_circuit_breaker(self):
        """Test that timeout raises exception for circuit breaker."""
        respx.get(f"{OPENSSF_API}/projects/github.com/facebook/react").mock(
            side_effect=httpx.TimeoutException("Connection timed out")
        )

        with pytest.raises(httpx.TimeoutException):
            await get_openssf_scorecard("facebook", "react")

    @pytest.mark.asyncio
    @respx.mock
    async def test_response_missing_score_returns_none(self):
        """Test that response with missing score returns None."""
        respx.get(f"{OPENSSF_API}/projects/github.com/facebook/react").mock(
            return_value=httpx.Response(200, json={"date": "2026-01-26", "checks": []})
        )

        result = await get_openssf_scorecard("facebook", "react")
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_response_with_null_score_returns_none(self):
        """Test that response with null score returns None."""
        respx.get(f"{OPENSSF_API}/projects/github.com/facebook/react").mock(
            return_value=httpx.Response(200, json={"score": None, "checks": []})
        )

        result = await get_openssf_scorecard("facebook", "react")
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_malformed_json_returns_none(self):
        """Test that malformed JSON response returns None."""
        respx.get(f"{OPENSSF_API}/projects/github.com/facebook/react").mock(
            return_value=httpx.Response(200, content=b"not json")
        )

        result = await get_openssf_scorecard("facebook", "react")
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_url_quoting_special_characters(self):
        """Test that special characters in owner/repo are properly URL encoded."""
        respx.get(f"{OPENSSF_API}/projects/github.com/my-org/my-repo").mock(
            return_value=httpx.Response(200, json={"score": 7.5, "checks": []})
        )

        result = await get_openssf_scorecard("my-org", "my-repo")
        assert result is not None
        assert result["openssf_score"] == 7.5

    @pytest.mark.asyncio
    @respx.mock
    async def test_filters_invalid_checks(self):
        """Test that non-dict checks are filtered out."""
        response = {
            "score": 5.0,
            "checks": [
                {"name": "Valid", "score": 5},
                "invalid_check",
                None,
                {"name": "Also-Valid", "score": 8},
            ]
        }
        respx.get(f"{OPENSSF_API}/projects/github.com/owner/repo").mock(
            return_value=httpx.Response(200, json=response)
        )

        result = await get_openssf_scorecard("owner", "repo")
        assert result is not None
        assert len(result["openssf_checks"]) == 2

    @pytest.mark.asyncio
    @respx.mock
    async def test_score_zero_is_valid(self):
        """Test that score=0 is valid (not treated as missing)."""
        respx.get(f"{OPENSSF_API}/projects/github.com/owner/repo").mock(
            return_value=httpx.Response(200, json={"score": 0, "checks": []})
        )

        result = await get_openssf_scorecard("owner", "repo")
        assert result is not None
        assert result["openssf_score"] == 0
