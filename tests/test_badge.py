"""
Tests for GET /badge/{ecosystem}/{name} endpoint.
"""

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
