"""Checks the Claude Code hook can stop waiting for: they finish on their own, and keep the verdict.

The hook gives the checks of one command a limited time. A large package can take minutes to scan,
and a scan killed at that limit was lost: every retry downloaded the package again and ran out of
time again, so it could never be installed unattended. So a check runs in processes of its own,
which outlive the hook:

* the supervisor, which the hook starts detached, runs the scan for at most ``CEILING_S`` seconds.
  When the hook has stopped waiting, it records the verdict in the hook's cache itself, under the
  same key and with the same trimmed entry the hook would have kept, so the same command run again
  is answered from there. A check that fails, or that the ceiling stops, records nothing;
* the scan, the supervisor's child, fetches the component, says how much text it is about to read
  as soon as it knows, and writes its report. The hook waits for it while that size says it can
  finish in the time left, and not a moment longer.

Both run in an empty directory with the check's own temp directory as TMP, never in the agent's
project, and neither holds the hook's stdin, stdout or stderr: the plugin reads the hook's answer
with ``$(...)``, which waits until every holder of that pipe has closed it. They and the hook talk
only through files in the check's directory:

    cwd/          the empty directory both processes run in
    scan.json     what to scan, the hook's process id and the ceiling (written by the hook)
    size          how much text the scan is about to read, in megabytes (written by the scan as
                  soon as it knows; the hook stops waiting at once when that says it can't wait
                  long enough)
    report.json   the report (written by the scan)
    job.json      where and under which key to record the verdict (written by the hook when it
                  stops waiting)
    abort         asks the supervisor to stop the scan and record nothing
    done          created exclusively by whichever of the hook and the supervisor is done with the
                  check first; the other one is the last, and removes the directory

A marker per cache key under the cache directory says a check of that artifact is running, so one
artifact is never checked twice at once and no more than ``MAX_BACKGROUND`` checks go on without a
hook (see :class:`Pending`).

More than one process writes the verdict cache: hooks for commands the agent runs in parallel, and
checks that finish after their hook. Each write reads the file, adds an entry and writes the file
back, so every write holds a lock file for that time (:func:`file_lock`), and the file is replaced
in one step, so a reader never sees half of it.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import signal
import subprocess  # nosec B404 - runs this same CLI with fixed arguments
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from skilltotal.collector import TreeSize

# A check stops after this long, wherever it is, and records nothing.
CEILING_S = 20 * 60
# Checks that may go on without a hook at once; past that, a check is stopped instead.
MAX_BACKGROUND = 2
# How often the waiting hook looks at its check.
_POLL_S = 0.1
# Windows process creation flags (subprocess has them only on Windows).
_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_NO_WINDOW = 0x08000000

# How long a scan takes once it knows its size: seconds ~ _SCAN_FIXED_S + _SCAN_S_PER_MB * MB, the
# megabytes of readable text it reports (``tree_size``, whole megabytes). Measured on 2026-10-11 on
# an Intel i7-3770 (4 cores) with Windows 11 and Python 3.14, twice, while other work kept the CPU
# busy as it is on an agent's machine: seconds from the size report to the report, and seconds to
# fetch and extract the package before it.
#
#     package                      readable MB   after the size, s   fetch, s
#     npm express 5.3.0                   0.07        0.6 /   0.6      1 /  1
#     pypi requests 2.34.2                0.22        1.8 /   2.1      1 /  1
#     pypi fastapi 0.143.0                0.83        6.8 /   8.3      1 /  1
#     npm lodash 4.18.1                   1.35       11.5 /  15.3      5 /  6
#     npm typescript 7.0.2                2.38        9.2 /  10.5      3 /  3
#     pypi botocore 1.43.111              5.64       39.4 /  45.9     13 / 17
#     npm zod 4.6.6                       5.86       47.1 /  55.5      5 /  5
#     npm react-dom 19.3.0                7.69       55.0 /  73.8      2 /  2
#     pypi openai 3.29.0                  7.95       55.4 /  90.2      8 / 12
#     npm @anthropic-ai/sdk 0.133.0      12.68       67.8 /  99.7     15 / 25
#     npm openai 7.32.0                  20.13      102.8 / 154.2     22 / 26
#     pypi django 6.1.2                  22.57      107.0 / 151.1     17 / 27
#     pypi sympy 1.14.0                  25.57      240.1              6
#     pypi transformers 5.19.0           48.10      428.8             15
#     npm aws-sdk 2.1693.0               69.38      450.8             11
#     npm next 16.4.0                   135.16      927.5             53
#
# Least squares over the 28 runs gives 4.5 + 6.9 * MB, below half of them. A wait cut short by an
# estimate that is too high only sends a check to the background a little early; one that is too
# low holds the agent until the deadline for a check that goes there anyway. So the line below
# lies above every run, with the size in whole megabytes as the hook reads it: 1.04 to 3 times the
# actual time of the runs that took over 5 s, 1.7 times at the median.
_SCAN_FIXED_S = 6.0
_SCAN_S_PER_MB = 11.0


def scan_seconds(readable_mb: float) -> float:
    """About how long a scan still takes once it knows it holds ``readable_mb`` MB of text."""
    return _SCAN_FIXED_S + _SCAN_S_PER_MB * readable_mb


def detached(os_name: str = os.name) -> dict[str, Any]:
    """Popen options that let a check outlive the hook and a kill of the hook's process group.

    On Windows: no console (closing the hook's console misses it) and a process group of its own
    (Ctrl+C and Ctrl+Break sent to the hook's group miss it); no window either. On POSIX: a session
    of its own, so neither a kill of the hook's process group nor a hang-up reaches it.
    """
    if os_name == "nt":
        return {"creationflags": _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP | _CREATE_NO_WINDOW}
    return {"start_new_session": True}


def _own_group(os_name: str = os.name) -> dict[str, Any]:
    """Popen options for the scan the supervisor starts. On POSIX, a process group of its own, so
    the ceiling stops it together with anything it started (a git clone). On Windows, a console of
    its own without a window: the supervisor has none to hand down, and a console program started
    without one gets a new, visible console window."""
    return {"creationflags": _CREATE_NO_WINDOW} if os_name == "nt" else {"start_new_session": True}


def _interpreter(os_name: str = os.name) -> tuple[str, dict[str, str]]:
    """This Python, and what the environment must add for the process to be this Python.

    In a venv on Windows (pipx installs there) ``sys.executable`` is a launcher that runs the base
    interpreter as a child process. For as long as that child runs, the launcher holds its working
    directory, which a check removes when it is done, and owns its process id, which a marker
    names; and a detached launcher starts its child with a visible console window. So, as
    multiprocessing does, the base interpreter is started directly and told which venv it is for.
    """
    base = getattr(sys, "_base_executable", "") or sys.executable
    if os_name == "nt" and os.path.normcase(base) != os.path.normcase(sys.executable):
        return base, {"__PYVENV_LAUNCHER__": sys.executable}
    return sys.executable, {}


def _spawn(argv: list[str], **options: Any) -> subprocess.Popen:
    """Start a process that holds none of the caller's handles: its stdin, stdout and stderr are
    the null device, and no other descriptor is inherited."""
    return subprocess.Popen(  # nosec B603 - sys.executable with fixed arguments, no shell
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        close_fds=True, **options,
    )


def _role_argv(role: str, tmp: str) -> list[str]:
    """The command line of one of a check's processes: this CLI, on the check's directory.

    ``python -m`` puts its working directory first on ``sys.path``; that directory is the check's
    empty one, and ``-P`` (3.11+) keeps it off ``sys.path`` as well.
    """
    safe_path = ["-P"] if sys.version_info >= (3, 11) else []
    python = _interpreter()[0]
    return [python, *safe_path, "-m", "skilltotal", "hook", "claude-code", f"--{role}", tmp]


def pid_alive(pid: int) -> bool:
    """Whether process ``pid`` is still running."""
    if pid <= 0:
        return False
    if os.name == "nt":
        return _windows_pid_alive(pid)
    try:
        os.kill(pid, 0)  # signal 0 only asks; never on Windows, where it ends the process
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # someone else's process
    except OSError:
        return False
    return True


def _windows_pid_alive(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes

    synchronize, access_denied, wait_timeout = 0x00100000, 5, 0x102
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel32.OpenProcess(synchronize, False, pid)
    if not handle:
        # No such process, unless it exists and is not this user's to open.
        return ctypes.get_last_error() == access_denied  # type: ignore[attr-defined]
    try:
        return kernel32.WaitForSingleObject(handle, 0) == wait_timeout
    finally:
        kernel32.CloseHandle(handle)


def claim(path: Path) -> bool:
    """Create ``path`` exclusively: True for the first one to get there, False after that."""
    try:
        os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    except FileExistsError:
        return False
    return True


def remove_tree(path: str | Path) -> None:
    """Remove a check's directory. On Windows a scan stopped a moment ago may still hold a file
    open while it goes, so a removal that left something behind is tried again briefly."""
    for _ in range(25):
        shutil.rmtree(path, ignore_errors=True)
        if not os.path.exists(path):
            return
        time.sleep(0.2)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _read_size(path: Path) -> int | None:
    """The megabytes the scan reported, or None while it has not (or is writing them now)."""
    try:
        text = path.read_text(encoding="ascii").strip()
    except (OSError, ValueError):
        return None
    return int(text) if text.isdigit() else None


class ScanContinues(TimeoutError):
    """The hook stopped waiting for a check that is still running. The caller decides its fate
    with ``scan.hand_over``: it goes on and records its verdict, or it is stopped.

    ``large``: the size of what it scans says it takes longer than the wait had left, so the wait
    stopped as soon as the size was known. ``seconds_left``: how long it should still take, once
    the size is known.
    """

    def __init__(self, scan: RunningScan, *, large: bool = False) -> None:
        super().__init__("the check is still running")
        self.scan = scan
        self.large = large
        self.seconds_left = scan.seconds_left()


class RunningScan:
    """A check the hook started: its supervisor process and the directory they share."""

    def __init__(self, proc: subprocess.Popen, tmp: str) -> None:
        self.proc = proc
        self.tmp = tmp
        self._started = time.monotonic()
        self._ends: float | None = None  # when the report should be in (monotonic), once known

    @property
    def pid(self) -> int:
        return self.proc.pid

    def seconds_left(self) -> float | None:
        return None if self._ends is None else self._ends - time.monotonic()

    @classmethod
    def start(cls, source: str) -> RunningScan:
        """Start checking ``source`` in a supervisor that outlives this process.

        The check gets a temp directory of its own, removed by whoever finishes last (see the
        module docstring), and runs in an empty directory inside it, never in the project the agent
        works in: a ``json.py`` planted in an opened repository must not run inside the scanner,
        and a ``.skilltotal.toml`` there must not tune the scan of someone else's package.
        """
        tmp = tempfile.mkdtemp(prefix="skilltotal_hook_")
        try:
            cwd = os.path.join(tmp, "cwd")
            os.mkdir(cwd)
            Path(tmp, "scan.json").write_text(json.dumps(
                {"source": source, "hook_pid": os.getpid(), "ceiling": CEILING_S}),
                encoding="utf-8")
            env = {**os.environ, **_interpreter()[1], "TMPDIR": tmp, "TEMP": tmp, "TMP": tmp,
                   "PYTHONIOENCODING": "utf-8"}
            proc = _spawn(_role_argv("supervise", tmp), cwd=cwd, env=env, **detached())
        except BaseException:
            remove_tree(tmp)
            raise
        return cls(proc, tmp)

    def wait(self, timeout: float) -> dict:
        """The report, if the check ends within ``timeout`` seconds; else raises ScanContinues.

        The scan says how much text it is about to read as soon as it knows (``size``). When that
        says it needs longer than the wait has left, the wait stops at once: holding the agent
        until the deadline would end the same way, later.
        """
        deadline = time.monotonic() + timeout
        while True:
            try:
                self.proc.wait(timeout=max(0.0, min(_POLL_S, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
            else:
                return self._collect()
            now = time.monotonic()
            if self._ends is None:
                size = _read_size(Path(self.tmp, "size"))
                if size is not None:
                    # Never later than the ceiling: by then the check has ended, either way.
                    self._ends = min(now + scan_seconds(size), self._started + CEILING_S)
                    if self._ends > deadline:
                        raise ScanContinues(self, large=True)
            if now >= deadline:
                raise ScanContinues(self)

    def hand_over(self, job: dict | None) -> dict | None:
        """Leave the check to itself: it records its verdict as ``job`` says, or, with no job, it is
        stopped and records nothing. Returns the report instead when the check was done first: it
        is then the answer, and the caller keeps it as if it had come in time."""
        if job is None:
            Path(self.tmp, "abort").write_text("", encoding="ascii")
        else:
            # Written before the claim: once the supervisor sees the claim, it reads the job.
            Path(self.tmp, "job.json").write_text(json.dumps(job), encoding="utf-8")
        if claim(Path(self.tmp, "done")):
            return None
        try:
            self.proc.wait(timeout=30)  # done first, it is exiting now
        except subprocess.TimeoutExpired:
            pass
        return self._collect()

    def _collect(self) -> dict:
        """The report of a check that ended while the hook was there to read it."""
        try:
            report = _read_json(Path(self.tmp, "report.json"))
        finally:
            remove_tree(self.tmp)
        if not isinstance(report, dict):
            raise RuntimeError("the scan failed")
        return report


# --- The check's own processes -------------------------------------------------------------------


def supervise(tmp: Path, remember: Callable[[dict, dict], object]) -> int:
    """The supervisor: run the scan within the ceiling, then finish the check.

    When the hook still waits, it reads the report itself. When the hook has stopped waiting, or
    died while it waited, the check is this process's to finish: it calls ``remember(job, report)``
    if the scan succeeded and the hook left a job, frees the marker the job names, and removes the
    check's directory.
    """
    spec = _read_json(tmp / "scan.json") or {}
    succeeded = _run_scan(tmp, float(spec.get("ceiling", CEILING_S)))
    if claim(tmp / "done") and pid_alive(int(spec.get("hook_pid", 0))):
        return 0  # the hook still waits: it reads the report and removes the directory
    job = _read_json(tmp / "job.json")
    try:
        report = _read_json(tmp / "report.json") if succeeded else None
        if isinstance(job, dict) and isinstance(report, dict):
            remember(job, report)
    finally:
        if isinstance(job, dict):
            Pending.release(Marker(Path(str(job.get("marker"))), str(job.get("token"))))
        _step_out_of(tmp)
        remove_tree(tmp)
    return 0


def _run_scan(tmp: Path, ceiling: float) -> bool:
    """Run the scan until it ends, the hook stops it, or the ceiling; True if it succeeded."""
    try:
        scan = _spawn(_role_argv("scan-into", str(tmp)), cwd=str(tmp / "cwd"),
                      env={**os.environ, **_interpreter()[1]}, **_own_group())
    except OSError:
        return False
    deadline = time.monotonic() + ceiling
    while True:
        try:
            return scan.wait(timeout=0.5) == 0
        except subprocess.TimeoutExpired:
            if (tmp / "abort").exists() or time.monotonic() >= deadline:
                _stop(scan)
                return False


def _stop(proc: subprocess.Popen) -> None:
    try:
        if hasattr(os, "killpg"):
            os.killpg(proc.pid, signal.SIGKILL)  # its group: the scan and what it started
        else:
            proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        pass


def _step_out_of(tmp: Path) -> None:
    """Leave ``tmp`` before removing it: Windows refuses to remove a process's working directory."""
    try:
        here, gone = Path.cwd().resolve(), tmp.resolve()
        if here == gone or gone in here.parents:
            os.chdir(gone.parent)
    except OSError:
        pass


def scan_into(tmp: Path) -> int:
    """The scan: scan what ``scan.json`` names, say how much text it is about to read as soon as
    it knows, and write the report beside it.

    The size goes to ``size`` in whole megabytes, as the hosted service's scan runner reports it:
    for a GitHub repository the collector measures it before cloning; anything else is measured
    on disk once it is fetched and extracted. That is why this runs the collector and the analysis
    itself instead of ``engine.analyze``, which adds two notes about the source besides (a link it
    normalized, archive entries it left out); the hook's verdict uses neither.
    """
    from skilltotal.collector import collect
    from skilltotal.engine import analyze_directory

    source = str((_read_json(tmp / "scan.json") or {})["source"])
    size_file = tmp / "size"

    def report_size(size: TreeSize) -> None:
        try:
            size_file.write_text(str(round(size.readable / 1024 / 1024)), encoding="ascii")
        except OSError:
            pass  # the hook then waits as it would have anyway; the scan goes on

    with collect(source, on_size=report_size) as ctx:
        if not size_file.exists():
            report_size(tree_size(ctx.root))
        report = analyze_directory(ctx.root, ctx.component)
    write_atomic(tmp / "report.json", json.dumps(report.to_dict()))
    return 0


# Folders an index never opens, so they are no part of the work ahead.
_NOT_INDEXED = frozenset({".git", ".hg", ".svn", "node_modules"})


def tree_size(root: Path) -> TreeSize:
    """The bytes under ``root``, and the part an index would read: the same measure the collector
    takes of a GitHub tree before cloning it, here taken on disk."""
    from skilltotal.collector import TreeSize, _readable_bytes
    from skilltotal.file_index import walk_files

    total = readable = 0
    for path in walk_files(root, skip=lambda name: name in _NOT_INDEXED):
        try:
            size = path.stat().st_size
        except OSError:
            continue
        total += size
        readable += _readable_bytes(path.relative_to(root).as_posix(), size)
    return TreeSize(total=total, readable=readable)


# --- One check per artifact, and at most MAX_BACKGROUND going on without a hook -----------------


@dataclass(frozen=True)
class Marker:
    """A marker this process wrote; ``token`` tells it from a marker another check wrote since."""

    path: Path
    token: str
    started: float = 0.0


class AlreadyRunning(Exception):
    """A live check of the same artifact holds the marker."""

    def __init__(self, age: float, seconds_left: float | None) -> None:
        super().__init__("a check of this artifact is already running")
        self.age = age
        self.seconds_left = seconds_left


class Pending:
    """The checks running now: one marker file per cache key in ``directory``.

    A marker names the process the check depends on (the hook while it waits, the supervisor once
    the check goes on alone), when the check started, whether it runs in the background, and when
    it is expected to end. A marker whose process is gone, or older than the ceiling, is stale: its
    check is over, whatever the file says.
    """

    def __init__(self, directory: Path) -> None:
        self.dir = directory

    def marker_path(self, key: str) -> Path:
        return self.dir / (hashlib.sha256(key.encode("utf-8")).hexdigest()[:40] + ".json")

    def claim(self, key: str, now: float) -> Marker | None:
        """Mark ``key`` as being checked by this process.

        Raises AlreadyRunning while a live check holds the marker. Returns None when no marker can
        be written at all: the check then runs only while the hook waits for it.
        """
        path = self.marker_path(key)
        token = secrets.token_hex(8)
        record = json.dumps({"pid": os.getpid(), "started": now, "token": token,
                             "background": False, "ends": None})
        for _ in range(3):
            try:
                self.dir.mkdir(parents=True, exist_ok=True)
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            except OSError:
                if not path.exists():
                    return None
            else:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(record)
                return Marker(path, token, now)
            info = _live(path, now)
            if info is not None:
                ends = info.get("ends")
                left = ends - now if isinstance(ends, (int, float)) else None
                raise AlreadyRunning(now - float(info.get("started", now)), left)
            _unlink(path)  # stale: its check is over
        return None

    def go_background(self, marker: Marker, pid: int, ends: float | None) -> None:
        """The check goes on without the hook: the marker now names its own process."""
        write_atomic(marker.path, json.dumps({"pid": pid, "started": marker.started,
                                              "token": marker.token, "background": True,
                                              "ends": ends}))

    def background(self, now: float, exclude: Marker) -> int:
        """How many other checks go on without a hook now. Stale markers are removed on the way."""
        running = 0
        for path in self.dir.glob("*.json"):
            if path == exclude.path:
                continue
            info = _live(path, now)
            if info is None:
                _unlink(path)
            elif info.get("background") is True:
                running += 1
        return running

    def lock(self) -> Any:
        return file_lock(self.dir / "pending.lock", wait_s=5.0)

    @staticmethod
    def release(marker: Marker | None) -> None:
        """Remove ``marker``, unless another check has replaced it since."""
        if marker is None:
            return
        info = _read_json(marker.path)
        if isinstance(info, dict) and info.get("token") == marker.token:
            _unlink(marker.path)


def _live(path: Path, now: float) -> dict | None:
    """The marker at ``path`` while its check runs; None when it is stale or gone."""
    info = _read_json(path)
    if not isinstance(info, dict):
        # Being written at this moment, or garbage: give a writer a few seconds.
        try:
            age = now - path.stat().st_mtime
        except OSError:
            return None
        return {"started": now} if 0 <= age < 5 else None
    pid, started = info.get("pid"), info.get("started")
    if not (isinstance(pid, int) and isinstance(started, (int, float))):
        return None
    if not 0 <= now - started < CEILING_S or not pid_alive(pid):
        return None
    return info


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


# --- The verdict cache: one writer at a time -----------------------------------------------------


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
