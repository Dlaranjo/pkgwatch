"""Tests for data quality utilities."""

from shared.data_quality import (
    build_data_quality_compact,
    build_data_quality_full,
    get_assessment_category,
    get_quality_explanation,
)


class TestGetAssessmentCategory:
    """Tests for assessment category determination."""

    def test_complete_with_repo_returns_verified(self):
        """Complete data with repo should return VERIFIED."""
        assert get_assessment_category("complete", True) == "VERIFIED"

    def test_complete_without_repo_returns_verified(self):
        """Complete data without repo still returns VERIFIED."""
        assert get_assessment_category("complete", False) == "VERIFIED"

    def test_partial_with_repo_returns_partial(self):
        """Partial data with repo should return PARTIAL."""
        assert get_assessment_category("partial", True) == "PARTIAL"

    def test_partial_without_repo_returns_unverified(self):
        """Partial data without repo should return UNVERIFIED."""
        assert get_assessment_category("partial", False) == "UNVERIFIED"

    def test_minimal_with_repo_returns_unverified(self):
        """Minimal data with repo should return UNVERIFIED."""
        assert get_assessment_category("minimal", True) == "UNVERIFIED"

    def test_minimal_without_repo_returns_unverified(self):
        """Minimal data without repo should return UNVERIFIED."""
        assert get_assessment_category("minimal", False) == "UNVERIFIED"

    def test_unknown_status_returns_unverified(self):
        """Unknown status should default to UNVERIFIED."""
        assert get_assessment_category("unknown", True) == "UNVERIFIED"
        assert get_assessment_category("", False) == "UNVERIFIED"

    def test_abandoned_minimal_returns_unavailable(self):
        """Abandoned minimal status should return UNAVAILABLE."""
        assert get_assessment_category("abandoned_minimal", True) == "UNAVAILABLE"
        assert get_assessment_category("abandoned_minimal", False) == "UNAVAILABLE"


class TestGetQualityExplanation:
    """Tests for human-readable quality explanations."""

    def test_complete_data_returns_complete_message(self):
        """Complete data should return a positive message."""
        result = get_quality_explanation("complete", [], True)
        assert result == "Complete data from all sources"

    def test_no_repository_explains_github_unavailable(self):
        """Missing repo should explain GitHub metrics unavailable."""
        result = get_quality_explanation("minimal", [], False)
        assert "No repository URL" in result
        assert "GitHub metrics unavailable" in result

    def test_github_missing_source_explains_failure(self):
        """GitHub in missing_sources should explain collection failure."""
        result = get_quality_explanation("partial", ["github"], True)
        assert "GitHub data collection failed" in result

    def test_npm_missing_source_explains_registry_incomplete(self):
        """npm in missing_sources should explain registry incomplete."""
        result = get_quality_explanation("partial", ["npm"], True)
        assert "Registry data incomplete" in result

    def test_pypi_missing_source_explains_registry_incomplete(self):
        """pypi in missing_sources should explain registry incomplete."""
        result = get_quality_explanation("partial", ["pypi"], True)
        assert "Registry data incomplete" in result

    def test_depsdev_missing_source_explains_unavailable(self):
        """deps.dev in missing_sources should explain data unavailable."""
        result = get_quality_explanation("partial", ["depsdev"], True)
        assert "deps.dev data unavailable" in result

    def test_multiple_missing_sources_combines_explanations(self):
        """Multiple missing sources should combine explanations."""
        result = get_quality_explanation("partial", ["github", "depsdev"], True)
        assert "GitHub data collection failed" in result
        assert "deps.dev data unavailable" in result
        assert ";" in result  # Combined with semicolon

    def test_no_repo_and_github_error_shows_both(self):
        """Missing repo and GitHub error should show both explanations."""
        result = get_quality_explanation("partial", ["github"], False)
        assert "No repository URL" in result
        assert "GitHub data collection failed" in result

    def test_partial_with_no_specific_issues_shows_generic(self):
        """Partial with empty missing_sources shows generic message."""
        result = get_quality_explanation("partial", [], True)
        assert result == "Some data sources unavailable"

    def test_abandoned_minimal_explains_collection_exhausted(self):
        """Abandoned minimal should explain retries exhausted."""
        result = get_quality_explanation("abandoned_minimal", [], False)
        assert "unavailable after multiple collection attempts" in result


class TestBuildDataQualityFull:
    """Tests for full data quality object builder."""

    def test_complete_package_with_all_fields(self):
        """Complete package should have VERIFIED assessment."""
        item = {
            "data_status": "complete",
            "missing_sources": [],
            "repository_url": "https://github.com/owner/repo",
        }
        result = build_data_quality_full(item)

        assert result["status"] == "complete"
        assert result["assessment"] == "VERIFIED"
        assert result["missing_sources"] == []
        assert result["has_repository"] is True
        assert "Complete data" in result["explanation"]

    def test_partial_package_with_github_error(self):
        """Partial package with GitHub error should show PARTIAL."""
        item = {
            "data_status": "partial",
            "missing_sources": ["github"],
            "repository_url": "https://github.com/owner/repo",
        }
        result = build_data_quality_full(item)

        assert result["status"] == "partial"
        assert result["assessment"] == "PARTIAL"
        assert result["missing_sources"] == ["github"]
        assert result["has_repository"] is True
        assert "GitHub data collection failed" in result["explanation"]

    def test_minimal_package_without_repo(self):
        """Minimal package without repo should be UNVERIFIED."""
        item = {
            "data_status": "minimal",
            "missing_sources": ["github"],
            "repository_url": None,
        }
        result = build_data_quality_full(item)

        assert result["status"] == "minimal"
        assert result["assessment"] == "UNVERIFIED"
        assert result["has_repository"] is False
        assert "No repository URL" in result["explanation"]

    def test_missing_data_status_defaults_to_minimal(self):
        """Missing data_status field should default to minimal/UNVERIFIED."""
        item = {
            "repository_url": "https://github.com/owner/repo",
        }
        result = build_data_quality_full(item)

        assert result["status"] == "minimal"
        assert result["assessment"] == "UNVERIFIED"

    def test_missing_sources_none_handled(self):
        """None missing_sources should be converted to empty list."""
        item = {
            "data_status": "partial",
            "missing_sources": None,
        }
        result = build_data_quality_full(item)

        assert result["missing_sources"] == []

    def test_missing_sources_non_list_handled(self):
        """Non-list missing_sources should be converted to empty list."""
        item = {
            "data_status": "partial",
            "missing_sources": "github",  # String instead of list
        }
        result = build_data_quality_full(item)

        assert result["missing_sources"] == []

    def test_empty_item_handles_gracefully(self):
        """Empty item should return sensible defaults."""
        item = {}
        result = build_data_quality_full(item)

        assert result["status"] == "minimal"
        assert result["assessment"] == "UNVERIFIED"
        assert result["missing_sources"] == []
        assert result["has_repository"] is False

    def test_abandoned_minimal_returns_unavailable(self):
        """Abandoned minimal package should return UNAVAILABLE assessment."""
        item = {
            "data_status": "abandoned_minimal",
            "missing_sources": ["github", "depsdev"],
            "repository_url": None,
        }
        result = build_data_quality_full(item)

        assert result["status"] == "abandoned_minimal"
        assert result["assessment"] == "UNAVAILABLE"
        assert result["has_repository"] is False
        assert "unavailable after multiple collection attempts" in result["explanation"]


class TestBuildDataQualityCompact:
    """Tests for compact data quality object builder."""

    def test_complete_package_returns_verified(self):
        """Complete package should have VERIFIED assessment."""
        item = {
            "data_status": "complete",
            "repository_url": "https://github.com/owner/repo",
        }
        result = build_data_quality_compact(item)

        assert result["assessment"] == "VERIFIED"
        assert result["has_repository"] is True
        # Compact version should not include status, missing_sources, or explanation
        assert "status" not in result
        assert "missing_sources" not in result
        assert "explanation" not in result

    def test_partial_package_with_repo_returns_partial(self):
        """Partial package with repo should have PARTIAL assessment."""
        item = {
            "data_status": "partial",
            "repository_url": "https://github.com/owner/repo",
        }
        result = build_data_quality_compact(item)

        assert result["assessment"] == "PARTIAL"
        assert result["has_repository"] is True

    def test_minimal_package_without_repo_returns_unverified(self):
        """Minimal package without repo should have UNVERIFIED assessment."""
        item = {
            "data_status": "minimal",
            "repository_url": None,
        }
        result = build_data_quality_compact(item)

        assert result["assessment"] == "UNVERIFIED"
        assert result["has_repository"] is False

    def test_missing_data_status_defaults_to_minimal(self):
        """Missing data_status should default to UNVERIFIED."""
        item = {}
        result = build_data_quality_compact(item)

        assert result["assessment"] == "UNVERIFIED"
        assert result["has_repository"] is False

    def test_empty_string_repository_url_is_falsy(self):
        """Empty string repository_url should be treated as no repo."""
        item = {
            "data_status": "partial",
            "repository_url": "",
        }
        result = build_data_quality_compact(item)

        assert result["has_repository"] is False
        assert result["assessment"] == "UNVERIFIED"

    def test_abandoned_minimal_returns_unavailable(self):
        """Abandoned minimal package should have UNAVAILABLE assessment."""
        item = {
            "data_status": "abandoned_minimal",
            "repository_url": None,
        }
        result = build_data_quality_compact(item)

        assert result["assessment"] == "UNAVAILABLE"
        assert result["has_repository"] is False


# =============================================================================
# COMPREHENSIVE ASSESSMENT CATEGORY TESTS
# =============================================================================


class TestAssessmentCategoryExhaustive:
    """Exhaustive testing of all data_status x has_repo combinations."""

    import pytest

    @pytest.mark.parametrize(
        "status,has_repo,expected",
        [
            ("complete", True, "VERIFIED"),
            ("complete", False, "VERIFIED"),
            ("partial", True, "PARTIAL"),
            ("partial", False, "UNVERIFIED"),
            ("minimal", True, "UNVERIFIED"),
            ("minimal", False, "UNVERIFIED"),
            ("abandoned_minimal", True, "UNAVAILABLE"),
            ("abandoned_minimal", False, "UNAVAILABLE"),
            ("abandoned_partial", True, "UNAVAILABLE"),
            ("abandoned_partial", False, "UNAVAILABLE"),
            ("pending", True, "UNVERIFIED"),
            ("pending", False, "UNVERIFIED"),
            ("", True, "UNVERIFIED"),
            ("", False, "UNVERIFIED"),
        ],
    )
    def test_all_status_repo_combinations(self, status, has_repo, expected):
        """Every status x has_repo combination should map to expected category."""
        assert get_assessment_category(status, has_repo) == expected


class TestQualityExplanationEdgeCases:
    """Edge case tests for quality explanations."""

    def test_all_sources_missing(self):
        """Multiple missing sources should all appear in explanation."""
        result = get_quality_explanation("partial", ["github", "npm", "depsdev"], True)
        assert "GitHub data collection failed" in result
        assert "Registry data incomplete" in result
        assert "deps.dev data unavailable" in result

    def test_abandoned_partial_returns_unavailable_message(self):
        """abandoned_partial should return same message as abandoned_minimal."""
        result_min = get_quality_explanation("abandoned_minimal", [], False)
        result_partial = get_quality_explanation("abandoned_partial", [], False)
        assert result_min == result_partial

    def test_unknown_missing_source_shows_generic(self):
        """Unknown source names should result in generic message."""
        result = get_quality_explanation("partial", ["unknown_source"], True)
        assert result == "Some data sources unavailable"


class TestBuildDataQualityFullEdgeCases:
    """Additional edge cases for build_data_quality_full."""

    def test_abandoned_partial_returns_unavailable(self):
        """abandoned_partial should also return UNAVAILABLE assessment."""
        item = {
            "data_status": "abandoned_partial",
            "missing_sources": ["github"],
            "repository_url": "https://github.com/owner/repo",
        }
        result = build_data_quality_full(item)
        assert result["assessment"] == "UNAVAILABLE"
        assert "unavailable after multiple collection attempts" in result["explanation"]

    def test_missing_repository_url_key_entirely(self):
        """Missing repository_url key should default to has_repository=False."""
        item = {"data_status": "complete"}
        result = build_data_quality_full(item)
        assert result["has_repository"] is False

    def test_integer_missing_sources_handled(self):
        """Integer type missing_sources should be converted to empty list."""
        item = {
            "data_status": "partial",
            "missing_sources": 42,
        }
        result = build_data_quality_full(item)
        assert result["missing_sources"] == []

    def test_dict_missing_sources_handled(self):
        """Dict type missing_sources should be converted to empty list."""
        item = {
            "data_status": "partial",
            "missing_sources": {"github": True},
        }
        result = build_data_quality_full(item)
        assert result["missing_sources"] == []
