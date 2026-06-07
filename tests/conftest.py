"""Shared pytest fixtures and helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.models import Report

FIXTURES = Path(__file__).parent / "fixtures"


def analyze_fixture(name: str) -> Report:
    root = FIXTURES / name
    component = detect_component(root, source=str(root))
    return analyze_directory(root, component)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def malicious_npm() -> Report:
    return analyze_fixture("malicious_npm_pkg")


@pytest.fixture
def malicious_py() -> Report:
    return analyze_fixture("malicious_py_pkg")


@pytest.fixture
def mcp_report() -> Report:
    return analyze_fixture("mcp_server")


@pytest.fixture
def prompt_report() -> Report:
    return analyze_fixture("prompt_injection")


@pytest.fixture
def clean_report() -> Report:
    return analyze_fixture("clean_pkg")
