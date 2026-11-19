"""A Python file that saves a download to a file and then runs that same file.

Shared by three rules, which differ in where the file is and in what else is there:

* ``ST-INSTALL-PY-DOWNLOAD-EXEC``: a ``setup.py`` or an in-tree build backend does it (install
  time, malicious indicator);
* ``ST-SHELL-PIPE-EXEC-PY``: any Python file does it (risky construct: an honest bootstrap script
  downloads an installer and starts it too);
* ``ST-PY-FETCH-EXEC``: the saved file is read back and handed to ``exec``, or it is a hidden or
  temporary file started with its output discarded.

The saved file is run when it is started as a process (``subprocess`` / ``os.system`` on the same
path), run in this process as a module (``runpy.run_path``, ``importlib`` loading it from its
path), or read back into ``exec`` / ``eval``. Matching is by the same path literal or the same
variable name; nothing here runs or imports anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from skilltotal.file_index import IndexedFile

RUN_PROCESS = "process"
RUN_MODULE = "module"
RUN_TEXT = "text"

_PY_DOWNLOAD = re.compile(
    r"\burlretrieve\(\s{0,3}[^,\n]{1,200},\s{0,3}"
    r"(?:([\"'])([^\"'\n]{1,120})\1|([A-Za-z_]\w{0,40}))\s{0,3}\)"
)
# `path, _ = urlretrieve(url, ...)`: the name the saved file's path is returned into.
_PY_DOWNLOAD_RESULT = re.compile(
    r"\b([A-Za-z_]\w{0,40})\s{0,3}(?:,\s{0,3}\w{1,40}\s{0,3})?=\s{0,3}(?:[\w.]{1,60}\.)?"
    r"urlretrieve\("
)
_PY_EXEC_CALL = r"(?:Popen|run|call|check_call|check_output|system|execv\w{0,2}|spawn\w{0,2})"
_INTERPRETER_ARG = (
    r"(?:(?:[\"'](?:sudo|sh|bash|python3?|node)[\"']|sys\.executable),\s{0,3})?"
)

# A response fetched into a name (`r = requests.get(u)`, `resp = urlopen(u)`, httpx, a urllib3
# pool), or opened with `with urlopen(u) as r:`.
_PY_FETCH_INTO = re.compile(
    r"\b([A-Za-z_]\w{0,40})\s{0,3}=\s{0,3}(?:(?:requests|httpx|session|client)\.(?:get|post|request)"
    r"|(?:urllib\.request\.|request\.)?urlopen|[\w.]{0,60}PoolManager\(\s{0,3}\)\.request)\s{0,3}\("
    r"|\bwith\s{1,3}(?:urllib\.request\.)?urlopen\([^\n]{0,300}?\)\s{1,3}as\s{1,3}([A-Za-z_]\w{0,40})"
)
# A file opened for writing (`open(path, "wb")`) or written whole (`Path(path).write_bytes(`).
_PY_WRITE_TARGET = r"(?:([\"'])([^\"'\n]{1,120})\1|([A-Za-z_]\w{0,40}))"
_PY_OPEN_WRITE = re.compile(
    rf"\bopen\(\s{{0,3}}{_PY_WRITE_TARGET}\s{{0,3}},\s{{0,3}}[\"'][wax]b?\+?[\"']"
    rf"|\bPath\(\s{{0,3}}{_PY_WRITE_TARGET}\s{{0,3}}\)\.write_(?:bytes|text)\("
)
_PY_WRITE_REACH = 400
_MAX_RESPONSES = 8
# Downloads of one file whose saved path is named again, and so are followed to a run: far more
# than an installer has, and a bound on what a generated file with thousands of them can cost.
_MAX_DOWNLOADS = 200
# Without one of the first there is no download to a file, without one of the second nothing runs
# one: two substring checks keep the patterns below off nearly every file.
_DOWNLOAD_TOKENS = ("urlretrieve", "urlopen", "requests.", "httpx.", "session.", "client.",
                    "PoolManager")
_RUN_TOKENS = ("subprocess", "Popen", "system(", "spawn", "execv", "run_path",
               "spec_from_file_location", "SourceFileLoader", "exec(", "eval(", ".run(", ".call(",
               "check_call", "check_output")

# How far into a call its arguments are read for the output it discards.
_ARGS_REACH = 400
_SILENCED = re.compile(r"\bDEVNULL\b|/dev/null|[\"']NUL[\"']|\bnohup\b")
_DETACHED = re.compile(
    r"\bPopen\(|\bstart_new_session\b|\bcreationflags\b|\bDETACHED_PROCESS\b|\bCREATE_NO_WINDOW\b"
    r"|\bnohup\b|&\s{0,2}[\"']\s{0,3}[,)]|\bP_NOWAIT\b"
)
_TEMP_PATH = re.compile(
    r"^(?:/tmp/|/var/tmp/|/dev/shm/)|\btempfile\b|\bgettempdir\b|\bmkstemp\b|\bmkdtemp\b"
    r"|\bNamedTemporaryFile\b|[\"'](?:TEMP|TMP|TMPDIR)[\"']|[\"']/(?:var/)?tmp[/\"']"
)
_QUOTED = re.compile(r"""(["'])([^"'\n]{1,200})\1""")


@dataclass(frozen=True)
class DownloadRun:
    """One download saved to a file and the later call that runs that file."""

    download: tuple[int, int]
    run: tuple[int, int]
    kind: str  # RUN_PROCESS, RUN_MODULE or RUN_TEXT
    # A hidden file, or a temporary one started detached, and the run discards its output.
    concealed: bool


def _py_downloads(f: IndexedFile) -> list[tuple[int, int, str | None, str | None]]:
    """``(start, end, literal path, path variable)`` of each file a Python script downloads: an
    ``urlretrieve`` target or the name its saved path is returned into, or a file the script
    writes a fetched response into (the response's own name is written within a few lines of the
    ``open``)."""
    text = f.text
    out = [(m.start(), m.end(), m.group(2), m.group(3)) for m in _PY_DOWNLOAD.finditer(text)]
    if "urlretrieve" in text:
        out += [(m.start(), m.end(), None, m.group(1)) for m in _PY_DOWNLOAD_RESULT.finditer(text)]
    fetched = [(m.group(1) or m.group(2), m.end()) for m in _PY_FETCH_INTO.finditer(text)]
    if not fetched:
        return out
    for w in _PY_OPEN_WRITE.finditer(text):
        literal = w.group(2) or w.group(5)
        name = w.group(3) or w.group(6)
        window = text[w.start():w.end() + _PY_WRITE_REACH]
        # The responses fetched before this write, nearest first; a file is not read further
        # back than a few of them.
        earlier = [response for response, after in fetched if after <= w.start()]
        for response in dict.fromkeys(reversed(earlier[-_MAX_RESPONSES:])):
            r = re.escape(response)
            if re.search(rf"(?:\.write(?:_bytes|_text)?|copyfileobj)\(\s{{0,3}}{r}\b", window):
                out.append((w.start(), w.end(), literal, name))
                break
    return out


def _run_patterns(literal: str | None, name: str | None) -> list[tuple[str, re.Pattern[str]]]:
    """The calls that run the file at this path, by kind."""
    if literal:
        target = re.escape(literal)
        in_command = rf"[\"'][^\"'\n]{{0,80}}?[ /=]?{target}[\"' ]"
    else:
        target = rf"\b{re.escape(name or '')}\b"
        in_command = (
            rf"(?:[fF][\"'][^\"'\n]{{0,80}}?\{{{target}\s{{0,3}}\}}"
            rf"|[\"'][^\"'\n]{{0,80}}[\"']\s{{0,3}}[+%]\s{{0,3}}\(?\s{{0,3}}{target})"
        )
    quote = r"[\"']?" if literal else r"(?<![\"'])"
    return [
        (RUN_PROCESS, re.compile(
            rf"\b{_PY_EXEC_CALL}\(\s{{0,3}}(?:\[\s{{0,3}})?"
            rf"(?:{_INTERPRETER_ARG}{quote}{target}|{in_command})"
        )),
        (RUN_MODULE, re.compile(
            rf"\brun_path\(\s{{0,3}}{quote}{target}"
            rf"|\b(?:spec_from_file_location|SourceFileLoader)\(\s{{0,3}}[^,\n]{{1,120}},"
            rf"\s{{0,3}}{quote}{target}"
        )),
        (RUN_TEXT, re.compile(
            rf"\b(?:exec|eval)\(\s{{0,3}}(?:compile\(\s{{0,3}})?"
            rf"(?:(?:io\.)?open\(\s{{0,3}}{quote}{target}[^()\n]{{0,60}}\)\s{{0,3}}\.read\("
            rf"|(?:pathlib\.)?Path\(\s{{0,3}}{quote}{target}\s{{0,3}}\)\s{{0,3}}"
            rf"\.read_(?:text|bytes)\()"
        )),
    ]


def _path_text(text: str, literal: str | None, name: str | None, before: int) -> str:
    """What the saved file's path is written as: the literal, or what its name is bound to."""
    if literal:
        return literal
    binding = re.compile(rf"(?m)^[ \t]*{re.escape(name or '')}\s{{0,3}}=(?!=)([^\n]{{0,300}})")
    bound = [m.group(1) for m in binding.finditer(text, 0, before)]
    return bound[-1].strip() if bound else ""


def _hidden(path_text: str, literal: str | None) -> bool:
    """True if the file's own name starts with a dot."""
    last = literal
    if not last:
        quoted = _QUOTED.findall(path_text)
        last = quoted[-1][1] if quoted else ""
    base = last.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return base.startswith(".") and base.strip(".") != ""


def _call_text(text: str, start: int) -> str:
    """The call starting at ``start`` up to its closing bracket, or ``_ARGS_REACH`` on."""
    depth = 0
    stop = min(len(text), start + _ARGS_REACH)
    for i in range(start, stop):
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text[start:stop]


def download_runs(f: IndexedFile, *, reach: int | None = None) -> list[DownloadRun]:
    """Each download ``f`` saves to a file and then runs, at most one run per download. ``reach``
    bounds how far after the download the run may be (None: anywhere later in the file)."""
    text = f.text
    if not any(t in text for t in _DOWNLOAD_TOKENS) or not any(t in text for t in _RUN_TOKENS):
        return []
    found: list[DownloadRun] = []
    seen: set[int] = set()
    followed = 0
    for start, end, literal, name in sorted(_py_downloads(f), key=lambda d: d[0]):
        target = literal or name
        stop = len(text) if reach is None else min(len(text), end + reach)
        # A saved file that is never named again is not run: most downloads stop here, before
        # any pattern is built for them.
        if not target or text.find(target, end, stop) < 0:
            continue
        if f.in_comment(start) or f.in_string(start):
            continue
        followed += 1
        if followed > _MAX_DOWNLOADS:
            break
        for kind, pattern in _run_patterns(literal, name):
            run = pattern.search(text, end, stop)
            if run is None or run.start() in seen:
                continue
            if f.in_comment(run.start()) or f.in_string(run.start()):
                continue
            seen.add(run.start())
            concealed = False
            if kind == RUN_PROCESS:
                call = _call_text(text, run.start())
                path = _path_text(text, literal, name, start)
                concealed = _SILENCED.search(call) is not None and (
                    _hidden(path, literal)
                    or (_TEMP_PATH.search(path) is not None and _DETACHED.search(call) is not None)
                )
            found.append(DownloadRun((start, end), (run.start(), run.end()), kind, concealed))
            break
    return found
