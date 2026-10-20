"""Coverage notes that mean "this code was not analyzed" must reach the hook and
`--fail-on-unanalyzed`, which both read UNANALYZED_TITLES."""

from skilltotal import autorun
from skilltotal.models import COMPILED_WITHOUT_SOURCE, UNANALYZED_LOADED_CODE, UNANALYZED_TITLES


def test_code_loaded_from_a_skipped_folder_counts_as_unanalyzed():
    assert UNANALYZED_LOADED_CODE in UNANALYZED_TITLES


def test_bytecode_shipped_without_source_counts_as_unanalyzed():
    # The Trail of Bits bypass of source-reading scanners: the payload ships only as a .pyc.
    assert COMPILED_WITHOUT_SOURCE in UNANALYZED_TITLES


def test_an_unread_mcp_server_bundle_counts_as_unanalyzed():
    assert autorun.MCP_BUNDLE_NOT_ANALYZED in UNANALYZED_TITLES


def test_folders_not_analyzed_stays_informational():
    # Every local scan with node_modules gets this note; gating on it would fail them all.
    assert "Folders not analyzed" not in UNANALYZED_TITLES
