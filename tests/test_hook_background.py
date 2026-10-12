"""The agent hook's checks: the verdict cache they share, and checks that outlast the hook's wait.

Everything here runs offline: the registry lookup is stubbed, and the processes a check runs in are
small scripts that stand in for the scan, unless a test says it runs the real one on a local folder.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from skilltotal import cli, hook_scan
from skilltotal.agent_hook import (
    BackgroundFull,
    CheckInBackground,
    TooLargeToCheck,
    hook_response,
)

# Stands in for the supervisor the hook starts. Steps, comma-separated: `size=N` writes the size
# file, `sleep=S` waits, `report` writes a report and ends first (the hook collects it), `fail` ends
# first without one, `wait` runs until the hook hands the check over or stops it, then notes what
# scan.json says to record the verdict under in $FAKE_LOG and, being the last one out, removes the
# check's directory.
FAKE_SUPERVISOR = r'''
import json, os, shutil, sys, time

steps, tmp = sys.argv[1], sys.argv[2]


def at(name):
    return os.path.join(tmp, name)


def claim():
    try:
        os.close(os.open(at("done"), os.O_CREAT | os.O_EXCL | os.O_WRONLY))
    except FileExistsError:
        return False
    return True


for step in steps.split(","):
    name, _, value = step.partition("=")
    if name == "size":
        with open(at("size"), "w", encoding="ascii") as fh:
            fh.write(value)
    elif name == "sleep":
        time.sleep(float(value))
    elif name == "report":
        with open(at("report.json"), "w", encoding="utf-8") as fh:
            json.dump({"risk_level": "low", "risk_score": 0, "component": {"version": "1.0.0"},
                       "verdict": {"has_malicious_indicators": False, "headline": "fake"}}, fh)
        claim()
        sys.exit(0)
    elif name == "fail":
        claim()
        sys.exit(1)
    elif name == "wait":
        deadline = time.time() + 30
        while time.time() < deadline and not os.path.exists(at("done")):
            time.sleep(0.05)
        last = not claim()
        with open(at("scan.json"), encoding="utf-8") as fh:
            job = json.load(fh).get("job")
        with open(os.environ["FAKE_LOG"], "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"last": last, "job": job, "abort": os.path.exists(at("abort")),
                                 "pid": os.getpid()}) + "\n")
        if last:
            os.chdir(os.path.dirname(tmp))
            shutil.rmtree(tmp, ignore_errors=True)
        sys.exit(0)
'''

# Stands in for the scan the real supervisor starts: `pid` notes its process id in $FAKE_PID,
# `child=S` starts a process that sleeps S seconds with its working directory in the check's (as a
# git clone the scan started would) and notes its id in $FAKE_CHILD_PID, `sleep=S` waits, `report`
# writes a report, `exit=N` ends with that code.
FAKE_SCAN = r'''
import json, os, subprocess, sys, time

steps, tmp = sys.argv[1], sys.argv[2]
for step in steps.split(","):
    name, _, value = step.partition("=")
    if name == "pid":
        with open(os.environ["FAKE_PID"], "w", encoding="ascii") as fh:
            fh.write(str(os.getpid()))
    elif name == "child":
        work = os.path.join(tmp, "work")
        os.makedirs(work, exist_ok=True)
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(%s)" % value],
                                 cwd=work)
        with open(os.environ["FAKE_CHILD_PID"], "w", encoding="ascii") as fh:
            fh.write(str(child.pid))
    elif name == "sleep":
        time.sleep(float(value))
    elif name == "report":
        with open(os.path.join(tmp, "report.json"), "w", encoding="utf-8") as fh:
            json.dump({"risk_level": "low", "risk_score": 0, "component": {"version": "1.0.0"},
                       "verdict": {"has_malicious_indicators": False, "headline": "fake"}}, fh)
    elif name == "exit":
        sys.exit(int(value))
'''


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
    with hook_scan.file_lock(cache / "hook-cache.json.lock", wait_s=0):  # and nobody holds it
        pass


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


@contextmanager
def _held(lock):
    """Another writer holding ``lock`` for as long as the block runs."""
    holding, done = threading.Event(), threading.Event()

    def hold():
        with hook_scan.file_lock(lock, wait_s=10):
            holding.set()
            done.wait(30)

    thread = threading.Thread(target=hold)
    thread.start()
    assert holding.wait(10)
    try:
        yield
    finally:
        done.set()
        thread.join(10)


# Takes the lock in a process of its own, says so, and keeps it until it is killed.
HOLD_LOCK = r'''
import sys, time
from pathlib import Path
from skilltotal import hook_scan

with hook_scan.file_lock(Path(sys.argv[1]), wait_s=10):
    Path(sys.argv[2]).write_text("held", encoding="ascii")
    time.sleep(120)
'''


def test_a_writer_waits_for_a_held_lock(tmp_path):
    lock = tmp_path / "hook-cache.json.lock"
    entered = threading.Event()

    def write():
        with hook_scan.file_lock(lock, wait_s=10):
            entered.set()

    with _held(lock):
        thread = threading.Thread(target=write)
        thread.start()
        time.sleep(0.3)
        assert not entered.is_set()
    thread.join(10)
    assert entered.is_set()


def test_a_lock_whose_holder_died_is_free_at_once(tmp_path):
    """The lock is the operating system's, on a file that stays in place: it ends with the process
    that held it, however that process ended. Nobody has to judge whether a lock file is stale,
    which two waiters could judge at once and both take the lock."""
    lock = tmp_path / "hook-cache.json.lock"
    holding = tmp_path / "holding"
    holder = subprocess.Popen([sys.executable, "-c", HOLD_LOCK, str(lock), str(holding)])
    try:
        assert _eventually(holding.exists, 30)
        with pytest.raises(TimeoutError):
            with hook_scan.file_lock(lock, wait_s=0.3):
                pass
    finally:
        holder.kill()
        holder.wait(30)
    started = time.monotonic()
    with hook_scan.file_lock(lock, wait_s=10):
        pass
    assert time.monotonic() - started < 5


def test_a_lock_that_stays_held_is_given_up_and_left_alone(tmp_path):
    lock = tmp_path / "hook-cache.json.lock"
    with _held(lock):
        with pytest.raises(TimeoutError):
            with hook_scan.file_lock(lock, wait_s=0.3):
                pass
        with pytest.raises(TimeoutError):  # giving up took nothing from the holder
            with hook_scan.file_lock(lock, wait_s=0.1):
                pass


def test_writers_take_turns(tmp_path):
    lock = tmp_path / "hook-cache.json.lock"
    inside, most = [0], [0]
    count = threading.Lock()

    def write():
        for _ in range(40):
            with hook_scan.file_lock(lock, wait_s=60):
                with count:
                    inside[0] += 1
                    most[0] = max(most[0], inside[0])
                time.sleep(0.001)
                with count:
                    inside[0] -= 1

    threads = [threading.Thread(target=write) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(120)
    assert most[0] == 1


def test_a_lock_file_busy_for_a_moment_is_waited_for(tmp_path, monkeypatch):
    """Windows answers "access denied" for a file that another process is opening or deleting at
    that moment. That is a busy lock, not a failure: raised, it escaped from the hand-over and left
    a check half handed over (134 times in 15,000 takes under contention)."""
    lock = tmp_path / "hook-cache.json.lock"
    real_open = os.open
    refusals = [3]

    def busy_open(path, flags, *args, **kwargs):
        if os.fspath(path) == str(lock) and refusals[0]:
            refusals[0] -= 1
            raise PermissionError(13, "simulated: the file is busy")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(hook_scan.os, "open", busy_open)
    with hook_scan.file_lock(lock, wait_s=5):
        pass
    assert refusals[0] == 0


# --- Helpers for checks that run in processes of their own --------------------------------------


def _eventually(condition, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return bool(condition())


def _dead_pid():
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def _must_not_spawn(*args, **kwargs):
    raise AssertionError("no check may start here")


def _bash(command):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}}


def _reason(answer):
    return answer["hookSpecificOutput"]["permissionDecisionReason"]


def _marker(cache, key, *, pid, started, background=True, ends=None, token="another"):
    """A marker as a hook or a check writes it: ``key`` is being checked by process ``pid``."""
    path = hook_scan.Pending(cache / "hook-pending").marker_path(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"pid": pid, "started": started, "token": token,
                                "background": background, "ends": ends}), encoding="utf-8")
    return path


def _markers(cache):
    return sorted((cache / "hook-pending").glob("*.json"))


def _seen(log):
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def fake_supervisor(tmp_path, monkeypatch):
    """The hook starts FAKE_SUPERVISOR in place of the real supervisor; checks start in a temp
    directory of the test's own. Returns a function that sets the fake's steps."""
    temp = tmp_path / "temp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    script = tmp_path / "fake_supervisor.py"
    script.write_text(FAKE_SUPERVISOR, encoding="utf-8")
    log = tmp_path / "fake.log"
    monkeypatch.setenv("FAKE_LOG", str(log))
    started = []
    real_spawn = hook_scan._spawn

    def spawn(argv, **options):
        started.append(real_spawn(argv, **options))
        return started[-1]

    monkeypatch.setattr(hook_scan, "_spawn", spawn)

    def use(steps):
        monkeypatch.setattr(hook_scan, "_role_argv",
                            lambda role, tmp: [sys.executable, str(script), steps, tmp])
        return SimpleNamespace(log=log, temp=temp, started=started)

    yield use
    for proc in started:  # no stand-in outlives its test
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def fake_scan(tmp_path, monkeypatch):
    """The real supervisor, run in this process, starts FAKE_SCAN in place of the real scan.
    Returns a function that sets the fake's steps."""
    script = tmp_path / "fake_scan.py"
    script.write_text(FAKE_SCAN, encoding="utf-8")
    monkeypatch.setenv("FAKE_PID", str(tmp_path / "scan.pid"))
    monkeypatch.setenv("FAKE_CHILD_PID", str(tmp_path / "child.pid"))
    real_argv = hook_scan._role_argv
    python = hook_scan._interpreter()[0]  # as the real scan is started: no launcher in between

    def use(steps):
        monkeypatch.setattr(
            hook_scan, "_role_argv",
            lambda role, tmp: ([python, str(script), steps, tmp] if role == "scan-into"
                               else real_argv(role, tmp)))

    return use


SECRET = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def check_dir(tmp_path, monkeypatch):
    """Makes a check's directory as the hook sets it up: named skilltotal_hook_*, directly in the
    temp directory, with the secret this process holds in its environment in its scan.json.
    ``handed_over``: the hook stopped waiting for it."""
    temp = tmp_path / "checks"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    monkeypatch.setenv(hook_scan.SECRET_ENV, SECRET)

    def make(*, hook_pid, ceiling=60.0, job=None, handed_over=False, abort=False):
        check = Path(tempfile.mkdtemp(prefix="skilltotal_hook_"))
        (check / "cwd").mkdir()
        spec = {"source": "npm:x@1.0.0", "hook_pid": hook_pid, "ceiling": ceiling,
                "secret": SECRET}
        if job is not None:
            spec["job"] = job
        (check / "scan.json").write_text(json.dumps(spec), encoding="utf-8")
        if abort:
            (check / "abort").write_text("", encoding="ascii")
        if handed_over:
            (check / "done").write_text("", encoding="ascii")
        return check

    return make


def _job_for(cache, key="npm:x@1.0.0"):
    """What the hook starts a check with, and the marker of that check."""
    marker = _marker(cache, key, pid=os.getpid(), started=time.time(), background=False,
                     token="mine")
    return {**_job(cache, key), "token": "mine"}, marker


def _hook(monkeypatch, *states):
    """The supervisor's view of its hook: alive or gone at each look, then as at the last."""
    looks = list(states)

    def gone():
        return looks.pop(0) if len(looks) > 1 else looks[0]

    monkeypatch.setattr(hook_scan, "_watch_hook", lambda pid: SimpleNamespace(gone=gone))


# --- Starting a check: processes that outlive the hook and hold none of its std handles ---------


def test_a_check_starts_detached_holding_none_of_the_hooks_std_handles(tmp_path, monkeypatch):
    """The plugin reads the hook's answer with `answer=$(... | skilltotal hook claude-code)`, and
    that waits until every holder of the pipe has closed it: a check that inherited the hook's
    stdout or stderr would hold the agent's command until the scan ended."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    seen = {}

    class Started:
        pid = 4242

    def popen(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return Started()

    monkeypatch.setattr(hook_scan.subprocess, "Popen", popen)
    check = hook_scan.RunningScan.start("npm:x@1.0.0")
    try:
        assert seen["stdin"] is subprocess.DEVNULL
        assert seen["stdout"] is subprocess.DEVNULL
        assert seen["stderr"] is subprocess.DEVNULL
        assert seen["close_fds"] is True
        for name, value in hook_scan.detached().items():
            assert seen[name] == value
        safe_path = ["-P"] if sys.version_info >= (3, 11) else []
        python, venv = hook_scan._interpreter()
        assert seen["argv"] == [python, *safe_path, "-m", "skilltotal", "hook", "claude-code",
                                "--supervise", check.tmp]
        assert venv.items() <= seen["env"].items()
        # Today's isolation: an empty directory of its own, never the agent's project. The check's
        # directory sits directly in the temp directory the supervisor is given.
        cwd = Path(seen["cwd"])
        assert cwd == Path(check.tmp) / "cwd"
        assert not any(cwd.iterdir())
        assert Path(check.tmp).name.startswith("skilltotal_hook_")
        assert all(seen["env"][name] == str(tmp_path) for name in ("TMPDIR", "TEMP", "TMP"))
        assert seen["env"]["PYTHONIOENCODING"] == "utf-8"
        spec = json.loads((Path(check.tmp) / "scan.json").read_text(encoding="utf-8"))
        # A one-time secret ties the check's processes to this check: in scan.json and in their
        # environment, never on a command line, where any process list shows it.
        secret = seen["env"][hook_scan.SECRET_ENV]
        assert len(secret) >= 32
        assert spec == {"source": "npm:x@1.0.0", "hook_pid": os.getpid(),
                        "ceiling": hook_scan.CEILING_S, "secret": secret}
        assert not any(secret in arg for arg in seen["argv"])
    finally:
        hook_scan.remove_tree(check.tmp)


def test_windows_and_posix_detach_a_check_their_own_way():
    # Windows: no console of the hook's and a process group of its own, so closing the hook's
    # console or Ctrl+C / Ctrl+Break sent to its group miss the check; and no window.
    detached = (getattr(subprocess, "DETACHED_PROCESS", 0x8)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)
                | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
    assert hook_scan.detached("nt") == {"creationflags": detached}
    # The scan it starts gets a console without a window: a console program started by a process
    # that has none would otherwise get a visible one.
    assert hook_scan._own_group("nt") == {
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)}
    # POSIX: a session of its own, so a kill of the hook's process group or a hang-up misses it;
    # the scan gets a group of its own too, so the ceiling stops whatever it started with it.
    assert hook_scan.detached("posix") == {"start_new_session": True}
    assert hook_scan._own_group("posix") == {"start_new_session": True}


def test_in_a_windows_venv_the_check_runs_the_base_interpreter_for_that_venv(monkeypatch):
    """A venv's python.exe on Windows is a launcher that starts the real interpreter as its child
    and holds that child's working directory while it runs, so a check could not remove its own
    directory. Like multiprocessing, the check starts the base interpreter for the venv instead."""
    monkeypatch.setattr(sys, "executable", r"C:\venv\Scripts\python.exe")
    monkeypatch.setattr(sys, "_base_executable", r"C:\Python314\python.exe", raising=False)
    assert hook_scan._interpreter("nt") == (
        r"C:\Python314\python.exe", {"__PYVENV_LAUNCHER__": r"C:\venv\Scripts\python.exe"})
    # Elsewhere a venv's python is the interpreter itself.
    assert hook_scan._interpreter("posix") == (r"C:\venv\Scripts\python.exe", {})
    monkeypatch.setattr(sys, "_base_executable", sys.executable, raising=False)
    assert hook_scan._interpreter("nt") == (sys.executable, {})


def test_the_scan_the_supervisor_starts_holds_none_of_its_handles_either(check_dir, monkeypatch):
    seen = {}

    class Ended:
        pid = 4343

        def wait(self, timeout=None):
            return 1

    def popen(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return Ended()

    monkeypatch.setattr(hook_scan.subprocess, "Popen", popen)
    check = check_dir(hook_pid=_dead_pid())
    hook_scan.supervise(check, remember=_must_not_spawn)
    assert seen["stdin"] is subprocess.DEVNULL
    assert seen["stdout"] is subprocess.DEVNULL
    assert seen["stderr"] is subprocess.DEVNULL
    assert seen["close_fds"] is True
    assert Path(seen["cwd"]) == check / "cwd"
    safe_path = ["-P"] if sys.version_info >= (3, 11) else []
    python, venv = hook_scan._interpreter()
    assert seen["argv"] == [python, *safe_path, "-m", "skilltotal", "hook", "claude-code",
                            "--scan-into", str(check)]
    assert venv.items() <= seen["env"].items()
    # The scan's temp files go in the check's directory, and it holds the check's secret.
    assert all(seen["env"][name] == str(check) for name in ("TMPDIR", "TEMP", "TMP"))
    assert seen["env"][hook_scan.SECRET_ENV] == SECRET
    for name, value in hook_scan._own_group().items():
        assert seen[name] == value
    assert not check.exists()  # the last one out removed the check's directory


def test_a_process_is_alive_until_it_ends():
    assert hook_scan.pid_alive(os.getpid())
    assert not hook_scan.pid_alive(_dead_pid())
    assert not hook_scan.pid_alive(0)


# --- The supervisor: the ceiling, and who records the verdict -----------------------------------


def test_a_check_the_hook_left_records_its_verdict_itself(check_dir, cache, fake_scan):
    fake_scan("report")
    job, marker = _job_for(cache)
    check = check_dir(hook_pid=os.getpid(), job=job, handed_over=True)
    assert hook_scan.supervise(check, remember=cli._hook_remember) == 0
    assert list(_cached(cache)) == ["npm:x@1.0.0"]
    assert not marker.exists()
    assert not check.exists()


def test_a_check_leaves_its_report_to_a_hook_that_still_waits(check_dir, fake_scan, monkeypatch):
    fake_scan("report")
    _hook(monkeypatch, False)
    check = check_dir(hook_pid=os.getpid())
    hook_scan.supervise(check, remember=_must_not_spawn)
    # Done first: the waiting hook reads the report, keeps the verdict and removes the directory.
    assert (check / "done").exists()
    assert (check / "report.json").exists()
    hook_scan.remove_tree(str(check))


def test_a_check_whose_hook_died_while_waiting_finishes_on_its_own(check_dir, cache, fake_scan):
    fake_scan("report")
    job, marker = _job_for(cache)
    check = check_dir(hook_pid=_dead_pid(), job=job)
    hook_scan.supervise(check, remember=cli._hook_remember)
    assert list(_cached(cache)) == ["npm:x@1.0.0"]
    assert not marker.exists()
    assert not check.exists()


def test_the_hard_ceiling_stops_a_scan_and_records_nothing(tmp_path, check_dir, cache,
                                                           fake_scan):
    fake_scan("pid,sleep=120,report")
    job, marker = _job_for(cache)
    check = check_dir(hook_pid=os.getpid(), ceiling=1.0, job=job, handed_over=True)
    started = time.monotonic()
    hook_scan.supervise(check, remember=cli._hook_remember)
    assert time.monotonic() - started < 30
    assert _cached(cache) == {}
    scan_pid = int((tmp_path / "scan.pid").read_text(encoding="ascii"))
    assert _eventually(lambda: not hook_scan.pid_alive(scan_pid), 10)
    assert not marker.exists()
    assert not check.exists()


def test_a_check_the_hook_stopped_records_nothing(check_dir, cache, fake_scan):
    fake_scan("sleep=120,report")
    check = check_dir(hook_pid=os.getpid(), abort=True, handed_over=True)
    started = time.monotonic()
    hook_scan.supervise(check, remember=cli._hook_remember)
    assert time.monotonic() - started < 30
    assert _cached(cache) == {}
    assert not check.exists()


def test_a_scan_that_fails_in_the_background_records_nothing(check_dir, cache, fake_scan):
    fake_scan("exit=1")
    job, marker = _job_for(cache)
    check = check_dir(hook_pid=os.getpid(), job=job, handed_over=True)
    hook_scan.supervise(check, remember=cli._hook_remember)
    assert _cached(cache) == {}
    assert not marker.exists()
    assert not check.exists()


# --- A check's processes touch nothing but a check the hook made --------------------------------


def _precious(root):
    """A directory that is no check: what the check's processes must leave exactly as it is."""
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "file.txt").write_text("keep me", encoding="utf-8")
    return root


def _tree(root):
    return sorted(str(path.relative_to(root)) for path in root.rglob("*"))


@pytest.mark.parametrize("role", ["supervise", "scan-into"])
@pytest.mark.parametrize("case", ["any folder", "named like a check, elsewhere", "no scan.json",
                                  "another secret", "no secret in the environment"])
def test_the_check_processes_refuse_anything_but_a_check_the_hook_made(
        tmp_path, monkeypatch, role, case):
    """`skilltotal hook claude-code --supervise DIR` removed DIR, whatever it was: with no scan.json
    the hook counted as gone, so the supervisor cleaned up after it. The flags are hidden, not
    secret, and a prompt-injected agent can run them as well as the hook can."""
    temp = tmp_path / "checks"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    monkeypatch.setenv(hook_scan.SECRET_ENV, SECRET)
    if case == "any folder":
        victim = _precious(tmp_path / "precious")
    else:
        home = tmp_path / "elsewhere" if case == "named like a check, elsewhere" else temp
        victim = _precious(home / "skilltotal_hook_planted")
        if case != "no scan.json":
            secret = "f" * 32 if case == "another secret" else SECRET
            (victim / "scan.json").write_text(json.dumps(
                {"source": "npm:x@1.0.0", "hook_pid": 0, "ceiling": 1.0, "secret": secret}),
                encoding="utf-8")
        if case == "no secret in the environment":
            monkeypatch.delenv(hook_scan.SECRET_ENV)
    before = _tree(victim)
    monkeypatch.setattr(hook_scan, "_spawn", _must_not_spawn)
    assert cli.main(["hook", "claude-code", f"--{role}", str(victim)]) != cli.EXIT_OK
    assert _tree(victim) == before
    assert (victim / "sub" / "file.txt").read_text(encoding="utf-8") == "keep me"


def test_a_check_writes_only_the_hooks_own_cache_and_marker(tmp_path, check_dir, cache, fake_scan):
    """Where a check records its verdict and which marker it frees come from the hook's own
    settings and the cache key, never from a path in a file of the check's directory: a planted
    job.json cannot aim the write or the removal anywhere else."""
    fake_scan("report")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    victim = elsewhere / "victim.txt"
    victim.write_text("keep me", encoding="utf-8")
    job, marker = _job_for(cache)
    job.update(cache=str(elsewhere / "planted.json"), marker=str(victim))
    check = check_dir(hook_pid=os.getpid(), job=job, handed_over=True)
    hook_scan.supervise(check, remember=cli._hook_remember)
    assert victim.read_text(encoding="utf-8") == "keep me"
    assert not (elsewhere / "planted.json").exists()
    assert list(_cached(cache)) == ["npm:x@1.0.0"]  # the hook's own cache
    assert not marker.exists()  # the marker the key names, which is the check's own


# --- The hook: waiting, handing a check over, one check per artifact, at most two behind ---------


def test_a_check_that_ends_in_time_answers_and_leaves_nothing_behind(cache, fake_supervisor):
    fake = fake_supervisor("report")
    report = cli._hook_scan_cached("npm:x@1.0.0", 30)
    assert report["verdict"]["headline"] == "fake"
    assert list(_cached(cache)) == ["npm:x@1.0.0"]
    assert not list(fake.temp.iterdir())
    assert _markers(cache) == []


def test_a_late_check_goes_on_in_the_background_with_what_it_must_record(cache, fake_supervisor):
    fake = fake_supervisor("wait")
    started = time.monotonic()
    with pytest.raises(CheckInBackground) as late:
        cli._hook_scan_cached("npm:big@1.0.0", 0.5)
    assert time.monotonic() - started < 10
    assert late.value.started_ago is None  # this command started it
    assert _eventually(lambda: _seen(fake.log))
    [handed] = _seen(fake.log)
    assert handed["last"] and not handed["abort"]
    job = handed["job"]
    assert job["key"] == "npm:big@1.0.0"
    assert job["ttl"] == cli._hook_cache_ttl("npm:big@1.0.0")
    assert job["engine"] == cli.__version__
    # No path: where the verdict goes and which marker is the check's follow from the hook's own
    # settings and the key, never from a file in the check's directory.
    assert "cache" not in job and "marker" not in job
    # The marker now names the check's own process: the hook is about to exit.
    path = hook_scan.Pending(cache / "hook-pending").marker_path(job["key"])
    marker = json.loads(path.read_text(encoding="utf-8"))
    assert marker["background"] is True
    assert marker["token"] == job["token"]
    assert marker["pid"] == fake.started[0].pid


def test_a_scan_that_fails_is_not_cached_and_frees_its_marker(cache, fake_supervisor):
    fake = fake_supervisor("fail")
    out = hook_response(_bash("npm install x@1.0.0"), scan=cli._hook_scan_cached)
    assert "npm:x@1.0.0: not checked because the scan failed." in _reason(out)
    assert _cached(cache) == {}
    assert not list(fake.temp.iterdir())
    assert _markers(cache) == []


def test_a_check_already_running_for_the_artifact_is_not_started_twice(cache, monkeypatch):
    now = time.time()
    _marker(cache, "npm:big@1.0.0", pid=os.getpid(), started=now - 200, ends=now + 30)
    monkeypatch.setattr(hook_scan, "_spawn", _must_not_spawn)
    with pytest.raises(CheckInBackground) as running:
        cli._hook_scan_cached("npm:big@1.0.0", 30)
    assert 190 < running.value.started_ago < 260
    assert 0 < running.value.seconds_left <= 30
    out = hook_response(_bash("npm install big@1.0.0"), scan=cli._hook_scan_cached)
    assert _reason(out) == (
        "SkillTotal needs your approval for this install. npm:big@1.0.0: a full check started "
        "3 minutes ago is still running in the background and takes about 1 minute more. Run "
        "the same command again after that.")


@pytest.mark.parametrize("stale", ["its process is gone", "older than the ceiling"])
def test_a_stale_marker_does_not_hold_a_check_back(cache, fake_supervisor, stale):
    fake_supervisor("report")
    now = time.time()
    if stale == "its process is gone":
        _marker(cache, "npm:x@1.0.0", pid=_dead_pid(), started=now - 5)
    else:
        _marker(cache, "npm:x@1.0.0", pid=os.getpid(), started=now - hook_scan.CEILING_S - 5)
    assert cli._hook_scan_cached("npm:x@1.0.0", 30)["verdict"]["headline"] == "fake"
    assert _markers(cache) == []


def test_a_stale_marker_is_replaced_only_under_the_lock(cache):
    """Two hooks that both find a stale marker must not both replace it: the second would remove
    the first one's fresh marker and start a second check of the same artifact."""
    pending = hook_scan.Pending(cache / "hook-pending")
    stale = _marker(cache, "npm:x@1.0.0", pid=_dead_pid(), started=time.time() - 5)
    claimed = []
    with _held(pending.dir / "pending.lock"):
        thread = threading.Thread(
            target=lambda: claimed.append(pending.claim("npm:x@1.0.0", time.time())))
        thread.start()
        time.sleep(0.3)
        assert json.loads(stale.read_text(encoding="utf-8"))["token"] == "another"
    thread.join(10)
    assert claimed and claimed[0] is not None
    assert json.loads(stale.read_text(encoding="utf-8"))["token"] == claimed[0].token


def test_a_marker_being_read_elsewhere_is_still_removed(cache, monkeypatch):
    # Windows refuses to remove a file another process has open, for as long as it has it open.
    marker = _marker(cache, "npm:x@1.0.0", pid=os.getpid(), started=time.time(), token="mine")
    real_unlink = Path.unlink
    refusals = [3]

    def busy_unlink(self, *args, **kwargs):
        if self == marker and refusals[0]:
            refusals[0] -= 1
            raise PermissionError(13, "simulated: someone is reading it")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", busy_unlink)
    hook_scan.Pending.release(hook_scan.Marker(marker, "mine"))
    assert not marker.exists()


def test_no_more_than_two_checks_run_in_the_background(cache, fake_supervisor):
    fake = fake_supervisor("wait")
    for other in ("npm:a@1.0.0", "npm:b@1.0.0"):
        _marker(cache, other, pid=os.getpid(), started=time.time() - 10)
    with pytest.raises(BackgroundFull) as full:
        cli._hook_scan_cached("npm:c@1.0.0", 0.5)
    assert full.value.running == 2
    assert _eventually(lambda: _seen(fake.log))
    [stopped] = _seen(fake.log)
    assert stopped["abort"]  # stopped: it records nothing (see the supervisor's tests)
    assert len(_markers(cache)) == 2  # its own marker is gone


def test_a_check_that_ends_in_time_runs_even_with_the_background_full(cache, fake_supervisor):
    fake_supervisor("report")
    for other in ("npm:a@1.0.0", "npm:b@1.0.0"):
        _marker(cache, other, pid=os.getpid(), started=time.time() - 10)
    assert cli._hook_scan_cached("npm:c@1.0.0", 30)["verdict"]["headline"] == "fake"


def test_checks_hooks_still_wait_for_do_not_count_against_the_cap(cache, fake_supervisor):
    fake = fake_supervisor("wait")
    for other in ("npm:a@1.0.0", "npm:b@1.0.0"):
        _marker(cache, other, pid=os.getpid(), started=time.time() - 10, background=False)
    with pytest.raises(CheckInBackground):
        cli._hook_scan_cached("npm:c@1.0.0", 0.5)
    assert _eventually(lambda: _seen(fake.log))
    [handed] = _seen(fake.log)
    assert handed["job"]["key"] == "npm:c@1.0.0"


def test_a_late_check_finishes_in_the_background_and_the_next_call_is_a_cache_hit(
        tmp_path, cache, monkeypatch):
    """The real thing, on a local folder: the hook stops waiting at once, the check goes on in its
    own processes, records its verdict and removes its directory, and the same check again is
    answered from the cache."""
    temp = tmp_path / "temp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    component = tmp_path / "component"
    component.mkdir()
    (component / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    source = str(component)
    with pytest.raises(CheckInBackground):
        cli._hook_scan_cached(source, 0.05)
    assert _eventually(lambda: source in _cached(cache), 120)
    assert _eventually(lambda: not list(temp.iterdir()), 60)
    assert _markers(cache) == []
    monkeypatch.setattr(hook_scan, "_spawn", _must_not_spawn)
    assert cli._hook_scan_cached(source, 0.05)["risk_level"] == "low"


# --- What the answer says -----------------------------------------------------------------------


def test_the_answer_for_a_check_that_goes_on_in_the_background():
    def late(source, timeout):
        raise CheckInBackground()

    out = hook_response(_bash("npm install big"), scan=late, budget_s=60)
    assert _reason(out) == (
        "SkillTotal needs your approval for this install. npm:big: not checked within "
        "SkillTotal's 60-second time limit; the check continues in the background. Run the same "
        "command again in a few minutes.")

    def known(source, timeout):
        raise CheckInBackground(150)

    out = hook_response(_bash("npm install big"), scan=known, budget_s=60)
    assert _reason(out).endswith(
        "the check continues in the background and takes about 3 minutes more. Run the same "
        "command again after that.")


def test_the_answer_when_the_background_is_full():
    def full(source, timeout):
        raise BackgroundFull(2)

    out = hook_response(_bash("npm install big"), scan=full, budget_s=60)
    assert _reason(out) == (
        "SkillTotal needs your approval for this install. npm:big: not checked; SkillTotal is "
        "already running 2 checks in the background. Run the same command again in a few "
        "minutes.")


# --- How long the hook waits: the size of what is scanned decides ------------------------------


def test_a_size_over_the_time_left_stops_the_wait_at_once(cache, fake_supervisor):
    """A package whose size says its scan outlasts the wait is answered as soon as the size is
    known, not when the wait runs out: the agent is not held for a check that cannot make it."""
    fake_supervisor("size=50,wait")
    started = time.monotonic()
    out = hook_response(_bash("npm install big@1.0.0"), scan=cli._hook_scan_cached, budget_s=30)
    assert time.monotonic() - started < 15
    reason = _reason(out)
    assert reason.startswith(
        "SkillTotal needs your approval for this install. npm:big@1.0.0: a large package; its "
        "full check is running in the background and takes about ")
    assert reason.endswith(" minutes. Run the same command again after that.")
    minutes = int(reason.rsplit("takes about ", 1)[1].split()[0])
    assert minutes == pytest.approx(hook_scan.scan_seconds(50) / 60, abs=1)
    # The marker says when the check should end, for whoever asks while it runs.
    [marker] = [json.loads(path.read_text(encoding="utf-8")) for path in _markers(cache)]
    assert marker["background"] is True
    assert marker["ends"] - time.time() == pytest.approx(hook_scan.scan_seconds(50), abs=15)


def test_no_check_is_promised_past_the_ceiling(cache, fake_supervisor):
    """A check whose size says it cannot end before the ceiling would be stopped there with
    nothing recorded, and every run of the command would start it again. It used to go to the
    background all the same, promised for the ceiling; now it is stopped at once, and the answer
    says to scan the package outside the hook."""
    fake = fake_supervisor("size=500,wait")
    assert hook_scan.scan_seconds(500) > hook_scan.CEILING_S
    started = time.monotonic()
    with pytest.raises(TooLargeToCheck) as big:
        cli._hook_scan_cached("npm:huge@1.0.0", 30)
    assert time.monotonic() - started < 15
    assert big.value.target == "npm:huge@1.0.0"
    assert _eventually(lambda: _seen(fake.log))
    [stopped] = _seen(fake.log)
    assert stopped["abort"]
    assert _markers(cache) == []


def test_the_answer_for_a_package_too_large_to_check_here(cache, fake_supervisor):
    fake_supervisor("size=500,wait")
    out = hook_response(_bash("npm install huge@1.0.0"), scan=cli._hook_scan_cached, budget_s=30)
    assert _reason(out) == (
        "SkillTotal needs your approval for this install. npm:huge@1.0.0: too large for "
        "SkillTotal to check here: its full check would take more than 20 minutes. Run "
        "`skilltotal scan npm:huge@1.0.0` to check it.")


def test_a_size_that_fits_keeps_the_wait_going(cache, fake_supervisor):
    fake_supervisor("size=1,sleep=1.5,report")
    assert cli._hook_scan_cached("npm:x@1.0.0", 30)["verdict"]["headline"] == "fake"
    assert list(_cached(cache)) == ["npm:x@1.0.0"]


def test_a_check_already_running_says_how_long_it_has_left(cache, monkeypatch):
    now = time.time()
    _marker(cache, "npm:big@1.0.0", pid=os.getpid(), started=now - 20, ends=now + 250)
    monkeypatch.setattr(hook_scan, "_spawn", _must_not_spawn)
    out = hook_response(_bash("npm install big@1.0.0"), scan=cli._hook_scan_cached)
    assert ("npm:big@1.0.0: a full check started 20 seconds ago is still running in the "
            "background and takes about 5 minutes more.") in _reason(out)


def test_what_the_scan_is_about_to_read_is_measured_as_an_index_would_read_it(tmp_path):
    from skilltotal.file_index import MAX_FILE_BYTES

    root = tmp_path / "package"
    (root / "lib").mkdir(parents=True)
    (root / "lib" / "index.js").write_bytes(b"x" * 1000)
    (root / "logo.png").write_bytes(b"\0" * 5000)  # never text
    (root / "huge.js").write_bytes(b"y" * (MAX_FILE_BYTES + 1))  # past what the index reads
    for skipped in (".git", "node_modules"):
        (root / skipped).mkdir()
        (root / skipped / "a.js").write_bytes(b"z" * 7000)
    size = hook_scan.tree_size(root)
    assert size.readable == 1000
    assert size.total == 1000 + 5000 + MAX_FILE_BYTES + 1


def test_the_scan_says_its_size_before_it_starts_reading(tmp_path, monkeypatch):
    from skilltotal import engine

    component = tmp_path / "component"
    component.mkdir()
    (component / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    # Made as the hook makes a check's directory: private to this user.
    check = Path(tempfile.mkdtemp(prefix="skilltotal_hook_", dir=tmp_path))
    (check / "scan.json").write_text(json.dumps({"source": str(component), "secret": SECRET}),
                                     encoding="utf-8")
    # As the supervisor starts it: the check's directory is its temp directory, and it holds the
    # check's secret.
    monkeypatch.setattr(tempfile, "tempdir", str(check))
    monkeypatch.setenv(hook_scan.SECRET_ENV, SECRET)
    real = engine.analyze_directory

    def analyze_directory(root, component, **options):
        assert (check / "size").read_text(encoding="ascii") == "0"  # whole megabytes
        return real(root, component, **options)

    monkeypatch.setattr(engine, "analyze_directory", analyze_directory)
    assert hook_scan.scan_into(check) == 0
    report = json.loads((check / "report.json").read_text(encoding="utf-8"))
    assert report["risk_level"] == "low"


def test_packages_the_old_limit_answered_are_still_waited_for():
    """Small packages behave as before: checked while the agent waits. On the machine the model
    was fitted on, what the old 20-second limit could answer held at most 2.4 MB of readable text
    (lodash: 1.4 MB in 17 s; the typescript 7 package: 2.4 MB in 13 s), fetched in up to 6 s.
    Such a package is still waited for, even after another one in the same command took the old
    limit's 20 seconds."""
    from skilltotal.agent_hook import DEFAULT_BUDGET_S

    assert 20 + 6 + hook_scan.scan_seconds(round(2.4)) < DEFAULT_BUDGET_S


@pytest.mark.parametrize(("setting", "budget"), [
    (None, 60.0), ("30", 30.0), ("0", 1.0), ("300", 100.0), ("soon", 60.0),
])
def test_the_hook_waits_sixty_seconds_unless_told_otherwise(monkeypatch, setting, budget):
    import io

    from skilltotal import agent_hook

    seen = []
    monkeypatch.setattr(agent_hook, "hook_response",
                        lambda event, scan, budget_s, **_: seen.append(budget_s))
    if setting is None:
        monkeypatch.delenv("SKILLTOTAL_HOOK_BUDGET", raising=False)
    else:
        monkeypatch.setenv("SKILLTOTAL_HOOK_BUDGET", setting)
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"tool_name": "Bash"}'))
    assert cli.main(["hook", "claude-code"]) == cli.EXIT_OK
    assert seen == [budget]
    assert agent_hook.DEFAULT_BUDGET_S == cli.HOOK_BUDGET_S == 60.0


# --- A hook that goes away, and a hand-over that goes wrong --------------------------------------

# Watches the hook whose process id it is given: notes what it sees first, then waits for it to go.
WATCH = r'''
import sys, time
from pathlib import Path
from skilltotal import hook_scan

watch = hook_scan._watch_hook(int(sys.argv[1]))
Path(sys.argv[2]).write_text("gone" if watch.gone() else "alive", encoding="ascii")
deadline = time.monotonic() + 30
while not watch.gone() and time.monotonic() < deadline:
    time.sleep(0.1)
Path(sys.argv[3]).write_text("gone" if watch.gone() else "still there", encoding="ascii")
'''

# Plays the hook: starts WATCH the way a hook starts its supervisor, waits until it has looked,
# and goes.
HOOK = r'''
import os, subprocess, sys, time
from pathlib import Path
from skilltotal import hook_scan

python, venv = hook_scan._interpreter()
subprocess.Popen([python, sys.argv[1], str(os.getpid()), sys.argv[2], sys.argv[3]],
                 env={**os.environ, **venv})
deadline = time.monotonic() + 30
while not Path(sys.argv[2]).exists() and time.monotonic() < deadline:
    time.sleep(0.05)
'''


def test_the_marker_names_the_checks_supervisor_from_the_start(tmp_path, cache, monkeypatch):
    """A marker naming the hook went stale as soon as the hook went (Esc, Claude Code's timeout):
    its check no longer counted as running, so the same command run again started another check
    of the same artifact, and the cap on background checks did not see it."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    marker = hook_scan.Pending(cache / "hook-pending").claim("npm:x@1.0.0", time.time())

    class Started:
        pid = 4242

    monkeypatch.setattr(hook_scan.subprocess, "Popen", lambda argv, **kwargs: Started())
    job = {**_job(cache, "npm:x@1.0.0"), "token": marker.token}
    check = hook_scan.RunningScan.start("npm:x@1.0.0", job)
    try:
        record = json.loads(marker.path.read_text(encoding="utf-8"))
        assert record["pid"] == 4242
        assert record["background"] is False
        # What the verdict is recorded under goes along before the check starts, in case the
        # hook goes away while it waits.
        spec = json.loads((Path(check.tmp) / "scan.json").read_text(encoding="utf-8"))
        assert spec["job"] == job
    finally:
        hook_scan.remove_tree(check.tmp)


def test_a_check_whose_hook_went_away_is_kept_as_a_background_check(check_dir, cache, fake_scan,
                                                                     monkeypatch):
    fake_scan("sleep=2,report")
    _hook(monkeypatch, False, True)  # there at first, then gone without a word
    adopted = []
    real = hook_scan.Pending.go_background

    def spy(self, marker, ends, pid=None):
        adopted.append(pid)
        return real(self, marker, ends, pid=pid)

    monkeypatch.setattr(hook_scan.Pending, "go_background", spy)
    job, marker = _job_for(cache)
    check = check_dir(hook_pid=os.getpid(), job=job)
    assert hook_scan.supervise(check, remember=cli._hook_remember) == 0
    assert adopted == [os.getpid()]  # a background check now, under this supervisor
    assert list(_cached(cache)) == ["npm:x@1.0.0"]  # its verdict is kept, not thrown away
    assert not marker.exists()
    assert not check.exists()


def test_a_check_whose_hook_went_away_is_stopped_when_the_background_is_full(
        check_dir, cache, fake_scan, monkeypatch):
    fake_scan("sleep=120,report")
    _hook(monkeypatch, True)
    for other in ("npm:a@1.0.0", "npm:b@1.0.0"):
        _marker(cache, other, pid=os.getpid(), started=time.time() - 10)
    job, marker = _job_for(cache)
    check = check_dir(hook_pid=os.getpid(), job=job)
    started = time.monotonic()
    hook_scan.supervise(check, remember=cli._hook_remember)
    assert time.monotonic() - started < 30
    assert _cached(cache) == {}
    assert not marker.exists()
    assert len(_markers(cache)) == 2
    assert not check.exists()


def test_a_process_younger_than_the_check_cannot_be_its_hook():
    """A process id is reused once its process ends. A process that reused the hook's id started
    after the check did, so the check never takes it for its hook."""
    younger = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        assert hook_scan._watch_hook(younger.pid).gone()
    finally:
        younger.kill()
        younger.wait(30)


def test_a_supervisor_sees_its_hook_go(tmp_path):
    watch, hook = tmp_path / "watch.py", tmp_path / "hook.py"
    watch.write_text(WATCH, encoding="utf-8")
    hook.write_text(HOOK, encoding="utf-8")
    first, last = tmp_path / "first", tmp_path / "last"
    subprocess.run([sys.executable, str(hook), str(watch), str(first), str(last)], timeout=60,
                   check=True)
    assert first.read_text(encoding="ascii") == "alive"
    assert _eventually(last.exists, 30)
    assert last.read_text(encoding="ascii") == "gone"


def test_an_error_while_handing_over_stops_the_check_and_frees_its_marker(
        cache, fake_supervisor, monkeypatch):
    """The reviewer's case: the pending lock refuses (as Windows does for a lock file that is being
    deleted). The error escaped the hand-over, so the check was neither handed over nor stopped,
    and its marker and its directory stayed behind."""
    fake = fake_supervisor("wait")

    def refuse(self, wait_s=5.0):
        raise PermissionError(13, "simulated: the pending directory refuses the lock file")

    monkeypatch.setattr(hook_scan.Pending, "lock", refuse)
    out = hook_response(_bash("npm install big@1.0.0"), scan=cli._hook_scan_cached, budget_s=0.5)
    assert ("npm:big@1.0.0: not checked within SkillTotal's 0.5-second time limit."
            in _reason(out))
    assert _eventually(lambda: _seen(fake.log))
    [stopped] = _seen(fake.log)
    assert stopped["abort"]
    assert _markers(cache) == []


def test_an_unexpected_error_while_handing_over_still_stops_the_check(cache, fake_supervisor,
                                                                      monkeypatch):
    fake = fake_supervisor("wait")

    def broken(self, marker, ends, pid=None):
        raise RuntimeError("simulated: a bug while handing the check over")

    monkeypatch.setattr(hook_scan.Pending, "go_background", broken)
    with pytest.raises(RuntimeError):
        cli._hook_scan_cached("npm:big@1.0.0", 0.5)
    assert _eventually(lambda: _seen(fake.log))
    [stopped] = _seen(fake.log)
    assert stopped["abort"]
    assert _markers(cache) == []


def test_the_marker_is_in_the_background_before_the_check_is_handed_over(cache, fake_supervisor,
                                                                         monkeypatch):
    """A check that ends right after the hand-over frees its marker. Written after the hand-over,
    the background marker came back for a check that was over, and the same command run again was
    told a check of it was still running."""
    fake_supervisor("wait")
    seen = []

    def hand_over(self, deadline=None):
        path = hook_scan.Pending(cache / "hook-pending").marker_path("npm:big@1.0.0")
        seen.append(json.loads(path.read_text(encoding="utf-8"))["background"])
        self.stop()  # lets the stand-in go
        return {**_report(), "verdict": {"has_malicious_indicators": False,
                                         "headline": "done first"}}

    monkeypatch.setattr(hook_scan.RunningScan, "hand_over", hand_over)
    report = cli._hook_scan_cached("npm:big@1.0.0", 0.5)
    assert seen == [True]
    assert report["verdict"]["headline"] == "done first"
    assert _markers(cache) == []


# --- The hook answers within its budget, whatever it waits for -----------------------------------


def test_a_hook_that_hands_a_check_over_answers_within_its_budget(cache, fake_supervisor,
                                                                  monkeypatch):
    """Claude Code lets the command run when the hook outlives its timeout, so every wait after
    the budget (the markers' lock, the check's directory) ends by the budget plus a short grace:
    here the markers' lock stays held throughout."""
    fake_supervisor("wait")
    monkeypatch.setattr(hook_scan, "GRACE_S", 0.5)
    (cache / "hook-pending").mkdir(parents=True)
    with _held(cache / "hook-pending" / "pending.lock"):
        started = time.monotonic()
        out = hook_response(_bash("npm install big@1.0.0"), scan=cli._hook_scan_cached,
                            budget_s=1.0)
        took = time.monotonic() - started
    assert took < 1.0 + 0.5 + 1.5
    assert "npm:big@1.0.0: not checked" in _reason(out)


def test_a_hook_keeping_a_verdict_answers_within_its_budget(cache, fake_supervisor, monkeypatch):
    # The cache's lock stays held: the verdict is answered all the same, just not kept this time.
    fake_supervisor("report")
    monkeypatch.setattr(hook_scan, "GRACE_S", 0.5)
    cache.mkdir(parents=True, exist_ok=True)
    with _held(cache / "hook-cache.json.lock"):
        started = time.monotonic()
        report = cli._hook_scan_cached("npm:x@1.0.0", 3.0)
        took = time.monotonic() - started
    assert report["verdict"]["headline"] == "fake"
    assert took < 3.0 + 0.5 + 1.5
    assert _cached(cache) == {}


def test_a_slow_registry_does_not_hold_the_hook(cache, fake_supervisor, monkeypatch):
    """The lookup of the release a name resolves to gets a bounded share of the budget; one that
    does not answer in time counts as a registry that did not answer."""
    from skilltotal import collector

    fake_supervisor("report")

    def hang(source, timeout=0):
        time.sleep(30)

    monkeypatch.setattr(collector, "resolve_release", hang)
    started = time.monotonic()
    report = cli._hook_scan_cached("npm:x", 4.0)
    assert time.monotonic() - started < 4.0
    assert report["verdict"]["headline"] == "fake"
    assert list(_cached(cache)) == ["npm:x"]  # kept under the name, as for a registry that is down


def test_the_longest_wait_ends_before_claude_code_lets_the_command_run():
    from tests.test_plugin_package import _bash_hooks

    (hook,) = _bash_hooks()
    assert cli.HOOK_MAX_BUDGET_S + hook_scan.GRACE_S + 10 <= hook["timeout"]


# --- A marker is data from a file: only plain numbers count -------------------------------------


@pytest.mark.parametrize("fields", [
    {"ends": float("inf")}, {"ends": float("nan")}, {"ends": "soon"}, {"ends": True},
    {"started": float("inf")}, {"started": "now"}, {"pid": True}, {"pid": "4242"}, {"pid": -1},
])
def test_a_marker_with_values_that_are_no_plain_numbers_is_stale(cache, monkeypatch, fields):
    """json.loads reads Infinity and NaN, so a damaged marker can hold them; a marker counts as a
    running check only when its process, its start and its end are plain numbers."""
    record = {"pid": os.getpid(), "started": time.time() - 5, "token": "another",
              "background": True, "ends": time.time() + 60, **fields}
    path = hook_scan.Pending(cache / "hook-pending").marker_path("npm:big@1.0.0")
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(record), encoding="utf-8")  # writes Infinity / NaN as JSON does
    calls = []
    monkeypatch.setattr(cli, "_hook_scan",
                        lambda source, timeout, job=None: calls.append(source) or _report())
    assert cli._hook_scan_cached("npm:big@1.0.0", 30)["risk_level"] == "low"
    assert calls == ["npm:big@1.0.0"]


def test_a_damaged_marker_does_not_turn_a_deny_into_a_question(cache, monkeypatch, capsys):
    """The reviewer's case: a marker ending at Infinity made the answer about one package raise,
    and the whole command got "could not check", turning the deny for another package into an
    ask."""
    import io

    path = hook_scan.Pending(cache / "hook-pending").marker_path("npm:big@1.0.0")
    path.parent.mkdir(parents=True)
    path.write_text(f'{{"pid": {os.getpid()}, "started": {time.time()}, "token": "t", '
                    f'"background": true, "ends": Infinity}}', encoding="utf-8")
    bad = {**_report(), "risk_level": "critical", "risk_score": 100,
           "verdict": {"has_malicious_indicators": True, "headline": "Malicious indicators"}}
    monkeypatch.setattr(cli, "_hook_scan",
                        lambda source, timeout, job=None: bad if "other" in source else _report())
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(_bash(
        "npm install big@1.0.0 other@1.0.0"))))
    assert cli.main(["hook", "claude-code"]) == cli.EXIT_OK
    answer = json.loads(capsys.readouterr().out)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "npm:other@1.0.0" in _reason(answer)


@pytest.mark.parametrize("check", [
    CheckInBackground(float("inf")), CheckInBackground(float("nan")),
    CheckInBackground(30.0, started_ago=float("inf")), CheckInBackground(started_ago=float("nan")),
])
def test_an_answer_about_a_background_check_never_breaks_on_its_numbers(check):
    def running(source, timeout):
        raise check

    out = hook_response(_bash("npm install big"), scan=running, budget_s=60)
    assert "npm:big: " in _reason(out)
    assert "Run the same command again" in _reason(out)


# --- Stopping a scan stops all of it, and nothing of a check is left behind ---------------------


def test_stopping_a_scan_stops_what_it_started(tmp_path, check_dir, cache, fake_scan):
    """Stopped at the ceiling, a scan used to end alone on Windows: the git clone it had started
    went on, with neither the clone's timeout nor its size guard left over it, and kept the check's
    directory from being removed."""
    fake_scan("child=120,sleep=120,report")
    job, marker = _job_for(cache)
    check = check_dir(hook_pid=os.getpid(), ceiling=3.0, job=job, handed_over=True)
    started = time.monotonic()
    hook_scan.supervise(check, remember=cli._hook_remember)
    assert time.monotonic() - started < 40
    child = int((tmp_path / "child.pid").read_text(encoding="ascii"))
    assert _eventually(lambda: not hook_scan.pid_alive(child), 15)
    assert _cached(cache) == {}
    assert not check.exists()


def test_a_checks_directory_goes_even_with_read_only_entries(tmp_path):
    """git keeps its pack files read-only, and Windows does not remove a read-only file; an archive
    can carry a read-only folder, whose files POSIX does not remove."""
    import stat

    check = tmp_path / "skilltotal_hook_readonly"
    pack = check / "repo" / ".git" / "objects" / "pack"
    pack.mkdir(parents=True)
    (pack / "pack-1.pack").write_bytes(b"PACK")
    os.chmod(pack / "pack-1.pack", stat.S_IREAD)
    folder = check / "x" / "locked"
    folder.mkdir(parents=True)
    (folder / "a.js").write_text("module.exports = 1;\n", encoding="utf-8")
    os.chmod(folder, stat.S_IREAD | stat.S_IEXEC)
    hook_scan.remove_tree(check)
    assert not check.exists()
