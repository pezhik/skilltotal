"""Files the Claude Code hook's checks share: the verdict cache, written one check at a time.

More than one process writes the hook's verdict cache: hooks for commands the agent runs in
parallel, and checks that finish after the hook that started them. Each write reads the file, adds
an entry and writes the file back, so every write holds a lock file for that time, and the file is
replaced in one step, so a reader never sees half of it.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def file_lock(path: Path, *, wait_s: float = 15.0, stale_s: float = 10.0) -> Iterator[None]:
    """Hold ``path`` as a lock: created exclusively on the way in, removed on the way out.

    A lock file older than ``stale_s`` belongs to a writer that died (a write takes milliseconds),
    so it is taken over. Raises TimeoutError when the lock is still held after ``wait_s``.
    """
    deadline = time.monotonic() + wait_s
    while True:
        try:
            os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            break
        except FileExistsError:
            pass
        except PermissionError:
            # Windows answers "access denied" for a lock file that is being deleted. Anywhere,
            # when there is no lock file at all, the directory itself refuses: waiting won't help.
            if not path.exists():
                raise
        try:
            if time.time() - path.stat().st_mtime > stale_s:
                path.unlink()
                continue
        except OSError:
            continue  # released (or taken over) just now: try again at once
        if time.monotonic() >= deadline:
            raise TimeoutError(f"{path.name} is still held")
        time.sleep(0.02)
    try:
        yield
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def write_atomic(path: Path, text: str) -> None:
    """Replace ``path`` with ``text`` in one step: a reader sees the old file or the new one.

    Windows refuses to replace a file another process has open, and readers keep the cache open for
    a moment, so the replace is retried briefly before it gives up.
    """
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        for attempt in range(20):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(0.05)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
