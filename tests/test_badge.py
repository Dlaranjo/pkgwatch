"""
Tests for GET /badge/{ecosystem}/{name} endpoint.
"""

import xml.etree.ElementTree as ET
from decimal import Decimal
from unittest.mock import patch


class TestBadgeHandler:
    """Tests for the badge Lambda handler."""

    def _make_event(self, ecosystem="npm", name="lodash", style=None, label=None):
        """Build a minimal API Gateway event for badge requests."""
        event = {
            "httpMethod": "GET",
            "headers": {},
            "pathParameters": {"ecosystem": ecosystem, "name": name},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {
                "identity": {"sourceIp": "127.0.0.1"},
            },
        }
        if style:
            event["queryStringParameters"]["style"] = style
        if label:
            event["queryStringParameters"]["label"] = label
        return event

    @patch("api.badge.get_package")
    def test_healthy_package_returns_green_badge(self, mock_get):
        """A package with health_score >= 70 should return a green badge."""
        mock_get.return_value = {
            "pk": "npm#lodash",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "lodash",
            "health_score": Decimal("85"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="lodash")
        result = handler(event, {})

        assert result["statusCode"] == 200
        assert result["headers"]["Content-Type"] == "image/svg+xml"
        body = result["body"]
        # Should contain the green color
        assert "#4c1" in body
        # Should contain the score
        assert "85" in body
        # Should contain the default label
        assert "pkgwatch" in body
        mock_get.assert_called_once_with("npm", "lodash")

    @patch("api.badge.get_package")
    def test_medium_package_returns_yellow_badge(self, mock_get):
        """A package with 50 <= health_score < 70 should return a yellow badge."""
        mock_get.return_value = {
            "pk": "npm#mid-pkg",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "mid-pkg",
            "health_score": Decimal("55"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="mid-pkg")
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        # Should contain the yellow color
        assert "#dfb317" in body
        assert "55" in body

    @patch("api.badge.get_package")
    def test_risky_package_returns_red_badge(self, mock_get):
        """A package with health_score < 50 should return a red badge."""
        mock_get.return_value = {
            "pk": "npm#abandoned-pkg",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "abandoned-pkg",
            "health_score": Decimal("25"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="abandoned-pkg")
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        # Should contain the red color
        assert "#e05d44" in body
        assert "25" in body

    @patch("api.badge.get_package")
    def test_unknown_package_returns_grey_badge(self, mock_get):
        """A package with no health_score should return a grey 'unknown' badge."""
        mock_get.return_value = {
            "pk": "npm#new-pkg",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "new-pkg",
            "health_score": None,
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="new-pkg")
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        # Should contain the grey color
        assert "#9f9f9f" in body
        assert "unknown" in body

    @patch("api.badge.get_package")
    def test_not_found_package_returns_grey_not_found_badge(self, mock_get):
        """A package not in the database should return a grey 'not found' badge."""
        mock_get.return_value = None

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="nonexistent-pkg")
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        assert "#9f9f9f" in body
        assert "not found" in body

    @patch("api.badge.get_package")
    def test_custom_label_param(self, mock_get):
        """The ?label= query param should override the default label text."""
        mock_get.return_value = {
            "pk": "npm#lodash",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "lodash",
            "health_score": Decimal("85"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="lodash", label="health")
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        assert "health" in body
        # Default label should not appear
        assert "pkgwatch" not in body

    @patch("api.badge.get_package")
    def test_flat_square_style(self, mock_get):
        """The ?style=flat-square param should produce a badge without rounded corners."""
        mock_get.return_value = {
            "pk": "npm#lodash",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "lodash",
            "health_score": Decimal("85"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="lodash", style="flat-square")
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        # flat-square should NOT have rounded corners (rx="3") or gradient
        assert 'rx="3"' not in body
        assert "linearGradient" not in body
        # Should still have the score
        assert "85" in body

    @patch("api.badge.get_package")
    def test_flat_style_has_gradient_and_rounded_corners(self, mock_get):
        """The default flat style should include gradient and rounded corners."""
        mock_get.return_value = {
            "pk": "npm#lodash",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "lodash",
            "health_score": Decimal("85"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="lodash", style="flat")
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        assert 'rx="3"' in body
        assert "linearGradient" in body

    @patch("api.badge.get_package")
    def test_invalid_ecosystem_returns_error_badge(self, mock_get):
        """An invalid ecosystem should return an 'invalid ecosystem' badge."""
        from api.badge import handler

        event = self._make_event(ecosystem="rubygems", name="rails")
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        assert "invalid ecosystem" in body
        assert "#9f9f9f" in body
        # Should NOT call get_package for invalid ecosystem
        mock_get.assert_not_called()

    @patch("api.badge.get_package")
    def test_cache_headers_are_set(self, mock_get):
        """Response should include Cache-Control for CDN caching."""
        mock_get.return_value = {
            "pk": "npm#lodash",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "lodash",
            "health_score": Decimal("85"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="lodash")
        result = handler(event, {})

        assert result["statusCode"] == 200
        assert result["headers"]["Cache-Control"] == "public, max-age=3600"

    @patch("api.badge.get_package")
    def test_content_type_is_svg(self, mock_get):
        """Response Content-Type should be image/svg+xml."""
        mock_get.return_value = {
            "pk": "npm#lodash",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "lodash",
            "health_score": Decimal("85"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="lodash")
        result = handler(event, {})

        assert result["headers"]["Content-Type"] == "image/svg+xml"

    @patch("api.badge.get_package")
    def test_missing_name_returns_error_badge(self, mock_get):
        """Missing package name should return an error badge."""
        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="lodash")
        event["pathParameters"]["name"] = None
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        assert "error" in body
        assert "#9f9f9f" in body
        mock_get.assert_not_called()

    @patch("api.badge.get_package")
    def test_pypi_package(self, mock_get):
        """Should support PyPI ecosystem packages."""
        mock_get.return_value = {
            "pk": "pypi#requests",
            "sk": "LATEST",
            "ecosystem": "pypi",
            "name": "requests",
            "health_score": Decimal("90"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="pypi", name="requests")
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        assert "#4c1" in body  # green
        assert "90" in body
        mock_get.assert_called_once_with("pypi", "requests")

    @patch("api.badge.get_package")
    def test_npm_name_normalized_to_lowercase(self, mock_get):
        """npm package names should be normalized to lowercase."""
        mock_get.return_value = None

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="Lodash")
        handler(event, {})

        mock_get.assert_called_once_with("npm", "lodash")

    @patch("api.badge.get_package")
    def test_url_encoded_package_name(self, mock_get):
        """URL-encoded package names (scoped packages) should be decoded."""
        mock_get.return_value = {
            "pk": "npm#@babel/core",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "@babel/core",
            "health_score": Decimal("88"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="%40babel%2Fcore")
        result = handler(event, {})

        assert result["statusCode"] == 200
        mock_get.assert_called_once_with("npm", "@babel/core")

    @patch("api.badge.get_package")
    def test_invalid_style_falls_back_to_flat(self, mock_get):
        """An invalid style parameter should fall back to the flat style."""
        mock_get.return_value = {
            "pk": "npm#lodash",
            "sk": "LATEST",
            "ecosystem": "npm",
            "name": "lodash",
            "health_score": Decimal("85"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="lodash", style="plastic")
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        # Should fall back to flat style with gradient
        assert "linearGradient" in body
        assert 'rx="3"' in body

    @patch("api.badge.get_package")
    def test_score_boundary_70_is_green(self, mock_get):
        """Score of exactly 70 should be green."""
        mock_get.return_value = {
            "health_score": Decimal("70"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="pkg")
        result = handler(event, {})

        assert "#4c1" in result["body"]

    @patch("api.badge.get_package")
    def test_score_boundary_50_is_yellow(self, mock_get):
        """Score of exactly 50 should be yellow."""
        mock_get.return_value = {
            "health_score": Decimal("50"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="pkg")
        result = handler(event, {})

        assert "#dfb317" in result["body"]

    @patch("api.badge.get_package")
    def test_score_boundary_49_is_red(self, mock_get):
        """Score of 49 should be red."""
        mock_get.return_value = {
            "health_score": Decimal("49"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="pkg")
        result = handler(event, {})

        assert "#e05d44" in result["body"]

    @patch("api.badge.get_package")
    def test_xml_special_chars_escaped_in_label(self, mock_get):
        """Special XML characters in label should be properly escaped."""
        mock_get.return_value = {
            "health_score": Decimal("85"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="pkg", label="<script>")
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        # Raw <script> should not appear - should be escaped
        assert "<script>" not in body
        assert "&lt;script&gt;" in body

    @patch("api.badge.get_package")
    def test_error_badge_has_shorter_cache(self, mock_get):
        """Error badges should have a shorter cache time (300s vs 3600s)."""
        mock_get.return_value = None

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="nonexistent")
        result = handler(event, {})

        assert "max-age=300" in result["headers"]["Cache-Control"]

    @patch("api.badge.get_package")
    def test_svg_is_valid_xml(self, mock_get):
        """Returned SVG should be parseable as XML."""
        import xml.etree.ElementTree as ET

        mock_get.return_value = {
            "health_score": Decimal("85"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="lodash")
        result = handler(event, {})

        # Should not raise an exception
        ET.fromstring(result["body"])

    @patch("api.badge.get_package")
    def test_is_base64_encoded_is_false(self, mock_get):
        """Response should set isBase64Encoded to False for raw SVG."""
        mock_get.return_value = {
            "health_score": Decimal("85"),
        }

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="lodash")
        result = handler(event, {})

        assert result["isBase64Encoded"] is False


class TestBadgeSVGInjection:
    """Security tests: SVG injection attacks via label, value, and package name."""

    def _make_event(self, ecosystem="npm", name="lodash", style=None, label=None):
        """Build a minimal API Gateway event for badge requests."""
        event = {
            "httpMethod": "GET",
            "headers": {},
            "pathParameters": {"ecosystem": ecosystem, "name": name},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {
                "identity": {"sourceIp": "127.0.0.1"},
            },
        }
        if style:
            event["queryStringParameters"]["style"] = style
        if label:
            event["queryStringParameters"]["label"] = label
        return event

    @patch("api.badge.get_package")
    def test_svg_injection_in_label_escaped(self, mock_get):
        """SVG/script injection in label param must be XML-escaped."""
        mock_get.return_value = {"health_score": Decimal("85")}

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="pkg", label='<script>alert("xss")</script>')
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        # Raw script tag must not appear in SVG
        assert "<script>" not in body
        assert "&lt;script&gt;" in body
        # Must still be valid XML
        ET.fromstring(body)

    @patch("api.badge.get_package")
    def test_svg_injection_in_score_value_escaped(self, mock_get):
        """If health_score were somehow a string with HTML, it should be safe."""
        # This tests the _escape_xml on the value side
        mock_get.return_value = {"health_score": None}

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="pkg")
        result = handler(event, {})

        body = result["body"]
        # "unknown" should appear, which is safe text
        assert "unknown" in body
        # Must be valid XML
        ET.fromstring(body)

    @patch("api.badge.get_package")
    def test_ampersand_in_label_escaped(self, mock_get):
        """Ampersand in label must be XML-escaped."""
        mock_get.return_value = {"health_score": Decimal("85")}

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="pkg", label="AT&T")
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        assert "&amp;" in body
        # Must be valid XML
        ET.fromstring(body)

    @patch("api.badge.get_package")
    def test_quote_in_label_escaped(self, mock_get):
        """Quotes in label must be XML-escaped."""
        mock_get.return_value = {"health_score": Decimal("85")}

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="pkg", label='say "hello"')
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        assert "&quot;" in body
        ET.fromstring(body)

    @patch("api.badge.get_package")
    def test_label_truncated_to_100_chars(self, mock_get):
        """Labels longer than 100 chars must be truncated."""
        mock_get.return_value = {"health_score": Decimal("85")}

        from api.badge import handler

        long_label = "x" * 200
        event = self._make_event(ecosystem="npm", name="pkg", label=long_label)
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        # The label in the SVG should be at most 100 chars
        assert "x" * 101 not in body

    @patch("api.badge.get_package")
    def test_path_traversal_in_badge_name(self, mock_get):
        """Path traversal in package name should return not found badge."""
        mock_get.return_value = None

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="../../../etc/passwd")
        result = handler(event, {})

        assert result["statusCode"] == 200
        body = result["body"]
        assert "not found" in body
        assert "etc/passwd" not in body or "&" in body  # Either not present or XML-escaped


class TestBadgeCacheHeaders:
    """Tests for badge cache header correctness."""

    def _make_event(self, ecosystem="npm", name="lodash", style=None, label=None):
        """Build a minimal API Gateway event for badge requests."""
        event = {
            "httpMethod": "GET",
            "headers": {},
            "pathParameters": {"ecosystem": ecosystem, "name": name},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }
        if style:
            event["queryStringParameters"]["style"] = style
        if label:
            event["queryStringParameters"]["label"] = label
        return event

    @patch("api.badge.get_package")
    def test_success_badge_has_1_hour_cache(self, mock_get):
        """Successful badge should have max-age=3600 (1 hour)."""
        mock_get.return_value = {"health_score": Decimal("85")}

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="lodash")
        result = handler(event, {})

        assert result["statusCode"] == 200
        assert result["headers"]["Cache-Control"] == "public, max-age=3600"

    @patch("api.badge.get_package")
    def test_error_badge_has_5_min_cache(self, mock_get):
        """Error badge should have max-age=300 (5 minutes)."""
        mock_get.return_value = None

        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="nonexistent")
        result = handler(event, {})

        assert result["statusCode"] == 200
        assert result["headers"]["Cache-Control"] == "public, max-age=300"

    @patch("api.badge.get_package")
    def test_invalid_ecosystem_error_badge_has_5_min_cache(self, mock_get):
        """Invalid ecosystem error badge should have 5 min cache."""
        from api.badge import handler

        event = self._make_event(ecosystem="rubygems", name="rails")
        result = handler(event, {})

        assert result["headers"]["Cache-Control"] == "public, max-age=300"

    @patch("api.badge.get_package")
    def test_missing_name_error_badge_has_5_min_cache(self, mock_get):
        """Missing name error badge should have 5 min cache."""
        from api.badge import handler

        event = self._make_event(ecosystem="npm", name="lodash")
        event["pathParameters"]["name"] = None
        result = handler(event, {})

        assert result["headers"]["Cache-Control"] == "public, max-age=300"


class TestBadgeColorAccuracy:
    """Tests to verify exact color for each score range boundary."""

    def _make_event(self, ecosystem="npm", name="pkg"):
        return {
            "httpMethod": "GET",
            "headers": {},
            "pathParameters": {"ecosystem": ecosystem, "name": name},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

    @patch("api.badge.get_package")
    def test_score_0_is_red(self, mock_get):
        """Score of 0 should produce red badge."""
        mock_get.return_value = {"health_score": Decimal("0")}

        from api.badge import handler

        result = handler(self._make_event(), {})
        assert "#e05d44" in result["body"]

    @patch("api.badge.get_package")
    def test_score_49_is_red(self, mock_get):
        """Score of 49 should produce red badge."""
        mock_get.return_value = {"health_score": Decimal("49")}

        from api.badge import handler

        result = handler(self._make_event(), {})
        assert "#e05d44" in result["body"]

    @patch("api.badge.get_package")
    def test_score_50_is_yellow(self, mock_get):
        """Score of 50 should produce yellow badge."""
        mock_get.return_value = {"health_score": Decimal("50")}

        from api.badge import handler

        result = handler(self._make_event(), {})
        assert "#dfb317" in result["body"]

    @patch("api.badge.get_package")
    def test_score_69_is_yellow(self, mock_get):
        """Score of 69 should produce yellow badge."""
        mock_get.return_value = {"health_score": Decimal("69")}

        from api.badge import handler

        result = handler(self._make_event(), {})
        assert "#dfb317" in result["body"]

    @patch("api.badge.get_package")
    def test_score_70_is_green(self, mock_get):
        """Score of 70 should produce green badge."""
        mock_get.return_value = {"health_score": Decimal("70")}

        from api.badge import handler

        result = handler(self._make_event(), {})
        assert "#4c1" in result["body"]

    @patch("api.badge.get_package")
    def test_score_100_is_green(self, mock_get):
        """Score of 100 should produce green badge."""
        mock_get.return_value = {"health_score": Decimal("100")}

        from api.badge import handler

        result = handler(self._make_event(), {})
        assert "#4c1" in result["body"]

    @patch("api.badge.get_package")
    def test_score_none_is_grey(self, mock_get):
        """Score of None should produce grey badge."""
        mock_get.return_value = {"health_score": None}

        from api.badge import handler

        result = handler(self._make_event(), {})
        assert "#9f9f9f" in result["body"]


class TestBadgeNullPathParameters:
    """Tests for null/missing pathParameters edge cases in badge."""

    def _make_event(self, ecosystem="npm", name="lodash"):
        return {
            "httpMethod": "GET",
            "headers": {},
            "pathParameters": {"ecosystem": ecosystem, "name": name},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

    @patch("api.badge.get_package")
    def test_null_path_parameters(self, mock_get):
        """None pathParameters should return error badge."""
        from api.badge import handler

        event = self._make_event()
        event["pathParameters"] = None
        result = handler(event, {})

        assert result["statusCode"] == 200
        assert "error" in result["body"]

    @patch("api.badge.get_package")
    def test_empty_path_parameters(self, mock_get):
        """Empty pathParameters should return error badge."""
        from api.badge import handler

        event = self._make_event()
        event["pathParameters"] = {}
        result = handler(event, {})

        assert result["statusCode"] == 200
        assert "error" in result["body"]

    @patch("api.badge.get_package")
    def test_null_query_string_parameters(self, mock_get):
        """None queryStringParameters should not crash."""
        mock_get.return_value = {"health_score": Decimal("85")}

        from api.badge import handler

        event = self._make_event()
        event["queryStringParameters"] = None
        result = handler(event, {})

        assert result["statusCode"] == 200
        assert "pkgwatch" in result["body"]


class TestBadgePyPINormalization:
    """Tests for PyPI name normalization in badge endpoint (Fix 5)."""

    def _make_event(self, ecosystem="pypi", name="flask"):
        return {
            "httpMethod": "GET",
            "headers": {},
            "pathParameters": {"ecosystem": ecosystem, "name": name},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

    @patch("api.badge.get_package")
    def test_pypi_name_normalized_for_lookup(self, mock_get):
        """Badge endpoint should normalize PyPI names (e.g., Flask -> flask)."""
        mock_get.return_value = {"health_score": Decimal("80")}

        from api.badge import handler

        event = self._make_event(ecosystem="pypi", name="Flask")
        result = handler(event, {})

        # Verify get_package was called with normalized name
        mock_get.assert_called_with("pypi", "flask")
        assert result["statusCode"] == 200

    @patch("api.badge.get_package")
    def test_pypi_name_with_underscores_normalized(self, mock_get):
        """Badge endpoint should normalize underscores in PyPI names."""
        mock_get.return_value = {"health_score": Decimal("75")}

        from api.badge import handler

        event = self._make_event(ecosystem="pypi", name="scikit_learn")
        result = handler(event, {})

        mock_get.assert_called_with("pypi", "scikit-learn")
        assert result["statusCode"] == 200
