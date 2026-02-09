"""
Backtesting fixtures - loads JSON fixture files for scoring validation.

Each fixture represents a real package's state at a specific point in time,
with expected scoring outcomes based on what actually happened to the package.
"""

import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    """Load a fixture JSON file by name."""
    path = FIXTURES_DIR / f"{name}.json"
    with open(path) as f:
        return json.load(f)


def all_fixture_names() -> list[str]:
    """Return all fixture names (without .json extension)."""
    return sorted(p.stem for p in FIXTURES_DIR.glob("*.json"))


def abandoned_fixture_names() -> list[str]:
    """Return fixture names for packages that were abandoned/deprecated."""
    names = []
    for name in all_fixture_names():
        fixture = load_fixture(name)
        if fixture.get("expected", {}).get("known_abandoned"):
            names.append(name)
    return names


def healthy_fixture_names() -> list[str]:
    """Return fixture names for packages that are healthy controls."""
    names = []
    for name in all_fixture_names():
        fixture = load_fixture(name)
        if not fixture.get("expected", {}).get("known_abandoned"):
            names.append(name)
    return names
