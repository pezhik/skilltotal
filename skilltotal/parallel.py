"""Scanners run side by side in worker processes, results in the usual order.

Every scanner is a function of the file index alone, so on a large component they can run at
once, each in a process of its own. The index goes to each worker once; the results come back
and are used in SCANNERS order, so the report is the same, byte for byte, as a scan in one
process. Nothing about detection changes here.

Processes are opt-in: only an entry point that is safe to re-import turns them on (the CLI does,
in ``main``). A library caller gets one process unless it asks, since starting workers re-imports
the caller's main module, and an unguarded script would run itself again in each worker. A small
component (the common case, and most hook checks) is scanned in this process whatever the
setting: workers cost more to start than its scan takes. Any failure to use processes (a sandbox
that forbids them, a worker that dies) falls back to this process: a slower scan, never a
different one. An error raised by a scanner itself is raised as it would be without workers.
"""

from __future__ import annotations

import multiprocessing
import os
from collections.abc import Callable, Sequence
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from pickle import PicklingError  # nosec B403 - only our own index is sent, to our own workers
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from skilltotal.file_index import FileIndex
    from skilltotal.scanners.base import Scanner, ScanResult

# The setting that fixes the number of worker processes (1 = none).
WORKERS_ENV = "SKILLTOTAL_WORKERS"
MAX_DEFAULT_WORKERS = 4
# Below these, workers cost more to start than they save.
MIN_FILES = 200
MIN_BYTES = 4 * 1024 * 1024
# The slowest scanners start first, so the longest one is never left to run alone at the end.
_SLOWEST_FIRST = ("prompt_surface", "python_ast", "secrets", "mcp", "agent_config",
                  "sensitive_paths", "scoped_identity", "oauth_auth")

_enabled = False


def enable() -> None:
    """Let this process use workers (for entry points whose main module is guarded)."""
    global _enabled
    _enabled = True


def worker_count() -> int:
    raw = os.environ.get(WORKERS_ENV, "").strip()
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            return 1
    if not _enabled:
        return 1
    return max(1, min(MAX_DEFAULT_WORKERS, os.cpu_count() or 1))


def run_scanners(
    index: FileIndex, scanners: Sequence[Scanner],
    progress: Callable[[int], None] | None = None,
) -> list[ScanResult]:
    """Each scanner's result for ``index``, in ``scanners`` order. ``progress(n)`` is called as
    the n-th scanner finishes."""
    workers = min(worker_count(), len(scanners))
    size = sum(len(f.text) for f in index.files)
    if (workers > 1 and (len(index.files) >= MIN_FILES or size >= MIN_BYTES)
            and not multiprocessing.current_process().daemon):
        try:
            return _in_workers(index, scanners, workers, progress)
        except (BrokenProcessPool, OSError, PicklingError, RuntimeError):
            pass  # no workers to be had: the same scan, here
    results = []
    for number, scanner in enumerate(scanners, 1):
        if progress is not None:
            progress(number)
        results.append(scanner.scan(index))
    return results


def _in_workers(
    index: FileIndex, scanners: Sequence[Scanner], workers: int,
    progress: Callable[[int], None] | None,
) -> list[ScanResult]:
    names = [s.name for s in scanners]
    order = sorted(range(len(scanners)), key=lambda i: (
        _SLOWEST_FIRST.index(names[i]) if names[i] in _SLOWEST_FIRST else len(_SLOWEST_FIRST), i))
    results: list[ScanResult | None] = [None] * len(scanners)
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=workers, mp_context=context,
                             initializer=_receive_index, initargs=(index, names)) as pool:
        futures = {pool.submit(_scan_one, i): i for i in order}
        for done, future in enumerate(as_completed(futures), 1):
            if progress is not None:
                progress(done)
            results[futures[future]] = future.result()
    return results  # type: ignore[return-value]


# --- In the worker -------------------------------------------------------------------------------

_index: FileIndex | None = None
_names: list[str] = []


def _receive_index(index: FileIndex, names: list[str]) -> None:
    global _index, _names
    _index, _names = index, names


def _scan_one(position: int) -> ScanResult:
    from skilltotal.scanners import SCANNERS

    scanner = next(s for s in SCANNERS if s.name == _names[position])
    assert _index is not None  # nosec B101 - set by the pool's initializer before any task
    return scanner.scan(_index)
