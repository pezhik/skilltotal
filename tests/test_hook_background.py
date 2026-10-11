"""The agent hook's checks: the verdict cache they share, and checks that outlast the hook's wait.

Everything here runs offline: the registry lookup is stubbed, and the processes a check runs in are
small scripts that stand in for the scan, unless a test says it runs the real one on a local folder.
"""

from __future__ import annotations

import json
import os
import threading
import time

import pytest

from skilltotal import cli, hook_scan


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """The cached scan asks the registry which release a name resolves to; tests stay offline."""
    from skilltotal import collector

    monkeypatch.setattr(collector, "resolve_release", lambda source, timeout=0: None)


@pytest.fixture
def cache(tmp_path, monkeypatch):
    path = tmp_path / "cache"
    monkeypatch.setenv("SKILLTOTAL_CACHE_DIR", str(path))
    return path


def _report(version="1.0.0", url=""):
    return {
        "risk_level": "low",
        "risk_score": 0,
        "component": {"version": version, "download_url": url},
        "verdict": {"has_malicious_indicators": False, "headline": "No malicious indicators"},
    }


def _job(cache, key, artifact=""):
    return {"key": key, "ttl": 3600, "artifact": artifact, "at": time.time(),
            "engine": cli.__version__, "cache": str(cache / "hook-cache.json")}


def _cached(cache):
    try:
        return json.loads((cache / "hook-cache.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


# --- The cache: one way to keep a verdict, one writer at a time ---------------------------------


def test_checks_that_finish_at_once_all_keep_their_verdicts(cache, monkeypatch):
    """A check that runs in the background records its verdict whenever it ends, so two can end at
    the same moment. Each reads the cache, adds its entry and writes the file back: without a lock,
    the second write drops the entry of the first."""
    real_read = cli._hook_cache_read

    def slow_read(path):
        entries = real_read(path)
        time.sleep(0.05)  # widen the window between reading the file and writing it back
        return entries

    monkeypatch.setattr(cli, "_hook_cache_read", slow_read)
    keys = [f"npm:pkg{i}@1.0.0" for i in range(6)]
    threads = [threading.Thread(target=cli._hook_remember, args=(_job(cache, key), _report()))
               for key in keys]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert sorted(_cached(cache)) == sorted(keys)
    assert not (cache / "hook-cache.json.lock").exists()


def test_the_shared_function_keeps_only_the_file_the_key_names(cache):
    # The same check as the hook's own: a verdict for another file than the key names is returned
    # for this answer but never kept, whichever process records it.
    key = "pypi:x==1.0 x-1.0.tar.gz 0123456789abcdef"
    job = _job(cache, key, artifact="x-1.0.tar.gz")
    trimmed = cli._hook_remember(job, _report(url="https://files.example/x-1.0-py3-none-any.whl"))
    assert trimmed["risk_level"] == "low"
    assert _cached(cache) == {}
    cli._hook_remember(job, _report(url="https://files.example/x-1.0.tar.gz"))
    assert list(_cached(cache)) == [key]


def test_a_writer_waits_for_a_held_lock(tmp_path):
    lock = tmp_path / "hook-cache.json.lock"
    lock.write_text("", encoding="ascii")  # another writer holds it
    entered = threading.Event()

    def write():
        with hook_scan.file_lock(lock, wait_s=10):
            entered.set()

    thread = threading.Thread(target=write)
    thread.start()
    time.sleep(0.3)
    assert not entered.is_set()
    lock.unlink()
    thread.join(10)
    assert entered.is_set()
    assert not lock.exists()


def test_a_lock_left_by_a_writer_that_died_is_free(tmp_path):
    lock = tmp_path / "hook-cache.json.lock"
    lock.write_text("", encoding="ascii")
    old = time.time() - 600
    os.utime(lock, (old, old))
    started = time.monotonic()
    with hook_scan.file_lock(lock, wait_s=5):
        pass
    assert time.monotonic() - started < 2


def test_a_lock_that_stays_held_is_given_up_and_left_alone(tmp_path):
    lock = tmp_path / "hook-cache.json.lock"
    lock.write_text("", encoding="ascii")
    with pytest.raises(TimeoutError):
        with hook_scan.file_lock(lock, wait_s=0.3):
            pass
    assert lock.exists()
