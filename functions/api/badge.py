"""
Badge Endpoint - GET /badge/{ecosystem}/{name}

Returns an SVG badge showing a package's health score,
similar to shields.io badges. Designed for embedding in READMEs.

No authentication required - this is a public endpoint.
"""

import logging
import math
from decimal import Decimal
from urllib.parse import unquote

from shared.dynamo import get_package
from shared.package_validation import normalize_npm_name

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Color coding for health scores
COLOR_GREEN = "#4c1"  # score >= 70
COLOR_YELLOW = "#dfb317"  # score >= 50
COLOR_RED = "#e05d44"  # score < 50
COLOR_GREY = "#9f9f9f"  # unknown / pending

# Character width approximation for Verdana 11px
CHAR_WIDTH = 6.5
PADDING = 10  # padding on each side of label/value

# SVG template for flat style (with rounded corners and gradient)
SVG_FLAT_TEMPLATE = """\
<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{label_x}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_x}" y="14">{label}</text>
    <text x="{value_x}" y="15" fill="#010101" fill-opacity=".3">{value}</text>
    <text x="{value_x}" y="14">{value}</text>
  </g>
</svg>"""

# SVG template for flat-square style (no rounded corners, no gradient)
SVG_FLAT_SQUARE_TEMPLATE = """\
<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">
  <g>
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{label_x}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_x}" y="14">{label}</text>
    <text x="{value_x}" y="15" fill="#010101" fill-opacity=".3">{value}</text>
    <text x="{value_x}" y="14">{value}</text>
  </g>
</svg>"""


def _get_score_color(score):
    """Return badge color based on health score."""
    if score is None:
        return COLOR_GREY
    # Convert Decimal to int/float for comparison
    if isinstance(score, Decimal):
        score = int(score)
    if score >= 70:
        return COLOR_GREEN
    if score >= 50:
        return COLOR_YELLOW
    return COLOR_RED


def _get_score_text(score):
    """Return display text for the score value."""
    if score is None:
        return "unknown"
    if isinstance(score, Decimal):
        score = int(score)
    return str(score)


def _calculate_width(text):
    """Calculate pixel width for text using character width approximation."""
    return math.ceil(len(text) * CHAR_WIDTH) + PADDING * 2


def _escape_xml(text):
    """Escape special XML characters in text."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _render_badge(label, value, color, style="flat"):
    """Render an SVG badge with the given label, value, and color."""
    label = _escape_xml(label)
    value = _escape_xml(value)

    label_width = _calculate_width(label)
    value_width = _calculate_width(value)
    total_width = label_width + value_width

    label_x = label_width / 2
    value_x = label_width + value_width / 2

    template = SVG_FLAT_SQUARE_TEMPLATE if style == "flat-square" else SVG_FLAT_TEMPLATE

    return template.format(
        total_width=total_width,
        label_width=label_width,
        value_width=value_width,
        label_x=label_x,
        value_x=value_x,
        label=label,
        value=value,
        color=color,
    )


def _svg_response(svg_body, status_code=200, cache_max_age=3600):
    """Return a raw SVG response (not JSON)."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "image/svg+xml",
            "Cache-Control": f"public, max-age={cache_max_age}",
        },
        "body": svg_body,
        "isBase64Encoded": False,
    }


def _error_badge(message, style="flat"):
    """Return an error badge SVG."""
    svg = _render_badge("pkgwatch", message, COLOR_GREY, style)
    return _svg_response(svg, status_code=200, cache_max_age=300)


def handler(event, context):
    """
    Lambda handler for GET /badge/{ecosystem}/{name}.

    Returns an SVG badge showing the package's health score.
    No authentication required - public endpoint for README embedding.
    """
    # Extract path parameters
    path_params = event.get("pathParameters") or {}
    ecosystem = path_params.get("ecosystem", "npm").lower()
    name = path_params.get("name")

    # Extract query parameters
    query_params = event.get("queryStringParameters") or {}
    style = query_params.get("style", "flat")
    label = query_params.get("label", "pkgwatch")[:100]

    # Validate style parameter
    if style not in ("flat", "flat-square"):
        style = "flat"

    if not name:
        return _error_badge("error", style)

    # Handle URL-encoded package names (e.g., %40babel%2Fcore -> @babel/core)
    name = unquote(name)

    # Normalize npm package names to lowercase
    if ecosystem == "npm":
        name = normalize_npm_name(name)

    # Validate ecosystem
    if ecosystem not in ("npm", "pypi"):
        return _error_badge("invalid ecosystem", style)

    # Look up package from DynamoDB
    item = get_package(ecosystem, name)

    if not item:
        return _error_badge("not found", style)

    # Get health score (may be None for packages still collecting)
    health_score = item.get("health_score")
    color = _get_score_color(health_score)
    value = _get_score_text(health_score)

    svg = _render_badge(label, value, color, style)
    return _svg_response(svg)
