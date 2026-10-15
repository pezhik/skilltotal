"""Shared pytest fixtures and helpers."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

if os.name == "nt":
    # A program the suite starts from a process without a console (an editor's or an agent's test
    # run) gets a console window of its own, which flashes on the screen: dozens per run. Every
    # child is started with no window unless the code chose a console itself; subprocess and
    # multiprocessing's worker processes both start children through this one call.
    import _winapi

    _CREATE_NO_WINDOW = 0x08000000
    _CHOSE_A_CONSOLE = 0x00000008 | 0x00000010  # DETACHED_PROCESS | CREATE_NEW_CONSOLE
    _create_process = _winapi.CreateProcess

    def _create_process_without_window(app, cmd, proc_attrs, thread_attrs, inherit, flags,
                                       *rest):
        if not flags & (_CHOSE_A_CONSOLE | _CREATE_NO_WINDOW):
            flags |= _CREATE_NO_WINDOW
        return _create_process(app, cmd, proc_attrs, thread_attrs, inherit, flags, *rest)

    _winapi.CreateProcess = _create_process_without_window

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.models import Report

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _outside_ci(monkeypatch):
    """The hook's strict mode follows CI's variables, and this suite itself runs in CI: every test
    starts outside it, and the strict-mode tests set what they need."""
    from skilltotal.cli import HOOK_CI_MARKERS

    for name in (*HOOK_CI_MARKERS, "SKILLTOTAL_STRICT", "SKILLTOTAL_ALLOW_UNCHECKED"):
        monkeypatch.delenv(name, raising=False)
    # A registry or index the machine configures would turn every install the CLI checks into a
    # question (setup-node in CI sets NPM_CONFIG_USERCONFIG): each test starts without one.
    for name in ("NPM_CONFIG_REGISTRY", "NPM_CONFIG_USERCONFIG", "YARN_REGISTRY",
                 "YARN_NPM_REGISTRY_SERVER", "BUN_CONFIG_REGISTRY", "PIP_INDEX_URL",
                 "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_CONFIG_FILE", "UV_INDEX_URL",
                 "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_FIND_LINKS"):
        monkeypatch.delenv(name, raising=False)


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
