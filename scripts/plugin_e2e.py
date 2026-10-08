"""End-to-end check of the Claude Code plugin through a real `claude -p` session.

Run before a release that touches the plugin (needs a logged-in `claude` and the `skilltotal` CLI on
PATH; each case is one short headless session on a small model):

    python scripts/plugin_e2e.py

Unit tests cover the parser and the hook's answer. This covers what only Claude Code can show:
the plugin loads from the tracked files, the hook fires on the agent's command, and Claude Code
acts on the answer. Every case runs through the Bash tool and, on Windows, through the PowerShell
tool, which is where Claude Code on Windows runs most commands. Nothing real is installed: `npm`,
`npx` and `pip` are stand-ins that print a marker, so a command the hook let through is visible and
a blocked one is not. Malicious and high-risk verdicts are seeded in the hook's cache under made-up
package names, so no malicious package is needed; one real public package is scanned for the clean
path.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - runs git, claude and skilltotal with fixed arguments
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKER = "ST-E2E-SHIM-RAN"
SHIM = f"""#!/bin/sh
echo "{MARKER} $(basename "$0") $*"
"""
CMD_SHIM = f"@echo {MARKER} %~n0 %*\r\n"  # PowerShell only runs a file with a known extension
TOOLS = ["Bash", "PowerShell"] if os.name == "nt" else ["Bash"]

# name -> (command the agent runs, what must happen)
CASES = {
    "malicious package is denied": ("npx -y st-e2e-probe-bad", "blocked"),
    "high-risk package is not run without approval": ("npm install st-e2e-probe-risky", "blocked"),
    "custom index is not run without approval": (
        "pip install --index-url https://pypi.example.invalid/simple st-e2e-probe-index",
        "blocked",
    ),
    "clean package runs after a real scan": ("npx -y is-number", "ran"),
    "a command that installs nothing runs": ("echo st-e2e-plain", "plain"),
    "a broken CLI warns and does not block": ("npm install st-e2e-probe-nocli", "warned"),
}

SEEDED = {
    "npm:st-e2e-probe-bad": {
        "risk_level": "critical",
        "risk_score": 100,
        "verdict": {"has_malicious_indicators": True, "headline": "Seeded e2e verdict"},
    },
    "npm:st-e2e-probe-risky": {
        "risk_level": "high",
        "risk_score": 70,
        "verdict": {"has_malicious_indicators": False, "headline": "Seeded e2e verdict"},
    },
}


def _run(argv: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, check=False, **kw)  # nosec B603


def _export_plugin(dest: Path) -> None:
    """Copy the plugin's tracked files, as the marketplace would serve them (no local-only files).

    The plugin is the `plugin/` folder, not the whole repository: the directory validator lints
    every file in a plugin, and the engine's fixtures and detection signatures read as secrets."""
    files = _run(["git", "ls-files", "-z", "plugin"], cwd=ROOT).stdout.decode().split("\0")
    for rel in filter(None, files):
        src = ROOT / rel
        if src.is_file():
            out = dest / Path(rel).relative_to("plugin")
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, out)


def _engine_version(skilltotal: str, env: dict) -> str:
    return _run([skilltotal, "--version"], env=env).stdout.decode().split()[-1]


def _session(
    claude: str, plugin: Path, work: Path, env: dict, command: str, tool: str
) -> list[dict]:
    prompt = (
        f"Use the {tool} tool to run exactly this command once and nothing else, without "
        f"changing it: `{command}`. If it is blocked or denied, do not retry or work around it; "
        "just report what you were told."
    )
    done = _run(
        [claude, "-p", prompt, "--plugin-dir", str(plugin), "--output-format", "stream-json",
         "--verbose", "--allowedTools", tool, "--max-turns", "4", "--model", "haiku",
         "--setting-sources", "project", "--no-session-persistence"],
        cwd=work, env=env, timeout=300,
    )
    events = []
    for line in done.stdout.decode("utf-8", "replace").splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


def _tool_results(events: list[dict], probe: str) -> list[str]:
    """Results of the tool calls whose command contains ``probe``."""
    ids = set()
    results = []
    for event in events:
        message = event.get("message")
        for block in (message.get("content") if isinstance(message, dict) else None) or []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use" and probe in json.dumps(block.get("input")):
                ids.add(block.get("id"))
            if block.get("type") == "tool_result" and block.get("tool_use_id") in ids:
                content = block.get("content")
                results.append(content if isinstance(content, str) else json.dumps(content))
    return results


def _run_cases(
    claude: str, plugin: Path, work: Path, env: dict, broken: Path, cache: Path, tool: str
) -> int:
    failures = 0
    for name, (command, expect) in CASES.items():
        probe = command.split()[-1]
        case_env = env
        if expect == "warned":
            case_env = {**env, "PATH": os.pathsep.join([str(broken), env["PATH"]])}
        events = _session(claude, plugin, work, case_env, command, tool)
        results = _tool_results(events, probe)
        text = "\n".join(results)
        if not results:
            ok, why = False, "the agent never ran the command"
        elif expect == "blocked":
            ok, why = MARKER not in text, "must not reach the shell"
        elif expect == "ran":
            scanned = "npm:is-number" in (cache / "hook-cache.json").read_text(encoding="utf-8")
            ok, why = MARKER in text and scanned, "must run, after a real scan"
        elif expect == "warned":
            warned = "did not check this install" in json.dumps(events)
            ok, why = MARKER in text and warned, "must run, with a warning in the session"
        else:
            ok, why = "st-e2e-plain" in text, "must run"
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {tool}: {name}: {why}")
        print("       " + text.replace("\n", " ")[:300])
    return failures


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")  # claude prints symbols a legacy codepage lacks
    claude, skilltotal = shutil.which("claude"), shutil.which("skilltotal")
    if not claude or not skilltotal:
        print("needs `claude` and `skilltotal` on PATH")
        return 2
    # The CLI on PATH may be a release from PyPI; test this checkout's engine through it.
    base_env = {**os.environ, "PYTHONPATH": os.pathsep.join(
        filter(None, [str(ROOT), os.environ.get("PYTHONPATH")]))}
    version = _engine_version(skilltotal, base_env)
    print(f"claude: {_run([claude, '--version']).stdout.decode().strip()}  skilltotal: {version}")

    with tempfile.TemporaryDirectory(prefix="st-plugin-e2e-") as tmp:
        tmp = Path(tmp)
        plugin, shims, cache, work = (tmp / d for d in ("plugin", "shims", "cache", "work"))
        for d in (plugin, shims, cache, work):
            d.mkdir()
        _export_plugin(plugin)
        validate = _run([claude, "plugin", "validate", str(plugin), "--strict"])
        print(f"plugin validate --strict: {'ok' if validate.returncode == 0 else 'FAILED'}")
        if validate.returncode != 0:
            print(validate.stdout.decode() + validate.stderr.decode())
            return 1
        broken = tmp / "broken"  # a CLI that fails to start, like a stale editable install
        broken.mkdir()
        (broken / "skilltotal").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8", newline="\n")
        (broken / "skilltotal").chmod(0o755)
        for name in ("npm", "npx", "pip"):
            (shims / name).write_text(SHIM, encoding="utf-8", newline="\n")
            (shims / name).chmod(0o755)
            (shims / f"{name}.cmd").write_text(CMD_SHIM, encoding="utf-8", newline="")
        seeded = {source: {"engine": version, "at": time.time(), "report": report}
                  for source, report in SEEDED.items()}
        (cache / "hook-cache.json").write_text(json.dumps(seeded), encoding="utf-8")
        env = {**base_env, "PATH": os.pathsep.join([str(shims), os.environ["PATH"]]),
               "SKILLTOTAL_CACHE_DIR": str(cache), "SKILLTOTAL_HOOK_BUDGET": "60"}

        failures = sum(_run_cases(claude, plugin, work, env, broken, cache, tool)
                       for tool in TOOLS)
    print("all passed" if not failures else f"{failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
