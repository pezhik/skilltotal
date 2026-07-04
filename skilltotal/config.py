"""Optional project configuration — ``.skilltotal.toml``.

A small, optional convenience for CI adoption: a project can commit fail thresholds,
path excludes, and per-rule ignores instead of repeating CLI flags. Stdlib only (tomllib on
3.11+, a minimal regex fallback on 3.10). CLI flags always override config values.

Recognized top-level keys:
    fail_on        = "low" | "medium" | "high" | "critical"
    fail_on_score  = <int 0-100>
    exclude        = ["glob/*", ...]   # path globs (posix, relative to the component root)
    ignore         = ["ST-RULE-ID", ...]
    baseline       = "path/to/baseline.json"

Per-rule policy (reviewable, lives in the repo — no dashboard or account needed):
    [policy]
    "ST-SHELL-PIPE-EXEC" = "block"    # gate trips (exit 2) whenever this rule fires
    "ST-DYN-PY"          = "warn"     # reported, but exempt from the fail_on severity gate
    "ST-SENS-WORD"       = "ignore"   # suppressed entirely (same effect as `ignore`)

`block` overrides severity thresholds (it trips even with no `fail_on` configured); `warn`
is an explicit accept-but-show (the finding stays in the report and still counts toward the
risk score / `fail_on_score`); unknown actions are dropped, not fatal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

CONFIG_NAME = ".skilltotal.toml"
_LEVELS = frozenset({"low", "medium", "high", "critical"})
_POLICY_ACTIONS = frozenset({"block", "warn", "ignore"})


@dataclass
class Config:
    """Resolved project configuration (all fields optional)."""

    fail_on: str | None = None
    fail_on_score: int | None = None
    exclude: list[str] = field(default_factory=list)
    ignore: list[str] = field(default_factory=list)
    baseline: str | None = None
    # Per-rule gate actions: rule id -> "block" | "warn" | "ignore".
    policy: dict[str, str] = field(default_factory=dict)

    def ignored_rules(self) -> set[str]:
        """Rule ids suppressed entirely: the `ignore` list plus policy `ignore` entries."""
        return {*self.ignore, *(r for r, action in self.policy.items() if action == "ignore")}


def find_config(start: Path | None = None) -> Path | None:
    """Return the path to ``.skilltotal.toml`` in ``start`` (default: CWD), or None."""
    candidate = (Path(start) if start else Path.cwd()) / CONFIG_NAME
    return candidate if candidate.is_file() else None


def load_config(path: Path) -> Config:
    """Parse a ``.skilltotal.toml`` file. Unknown/malformed keys are ignored, not fatal."""
    # utf-8-sig strips a leading BOM if present (Windows editors / PowerShell often add one);
    # tomllib rejects a BOM, which would otherwise silently void the whole config (fail-open).
    text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    data = _parse(text)
    fail_on = _as_level(data.get("fail_on"))
    return Config(
        fail_on=fail_on,
        fail_on_score=_as_int(data.get("fail_on_score")),
        exclude=_as_str_list(data.get("exclude")),
        ignore=_as_str_list(data.get("ignore")),
        baseline=_as_str(data.get("baseline")),
        policy=_as_policy(data.get("policy")),
    )


def _parse(text: str) -> dict[str, object]:
    if tomllib is not None:
        try:
            data = tomllib.loads(text)
            return data if isinstance(data, dict) else {}
        except (tomllib.TOMLDecodeError, ValueError):  # pragma: no cover - malformed config
            return {}
    return _fallback_parse(text)  # pragma: no cover - 3.10 path


def _fallback_parse(text: str) -> dict[str, object]:  # pragma: no cover - 3.10 only
    """Best-effort parse of the handful of supported scalar/array keys (no tomllib)."""
    out: dict[str, object] = {}
    for key in ("fail_on", "baseline"):
        m = re.search(rf'^\s*{key}\s*=\s*"([^"]*)"', text, re.MULTILINE)
        if m:
            out[key] = m.group(1)
    m = re.search(r"^\s*fail_on_score\s*=\s*(\d+)", text, re.MULTILINE)
    if m:
        out["fail_on_score"] = int(m.group(1))
    for key in ("exclude", "ignore"):
        m = re.search(rf"^\s*{key}\s*=\s*\[([^\]]*)\]", text, re.MULTILINE)
        if m:
            out[key] = [v.strip().strip("\"'") for v in m.group(1).split(",") if v.strip()]
    m = re.search(r"^\s*\[policy\]\s*$(.*?)(?=^\s*\[|\Z)", text, re.MULTILINE | re.DOTALL)
    if m:
        policy: dict[str, object] = {}
        for line in m.group(1).splitlines():
            kv = re.match(r"""\s*["']?([\w.-]+)["']?\s*=\s*["']([^"']*)["']""", line)
            if kv:
                policy[kv.group(1)] = kv.group(2)
        out["policy"] = policy
    return out


def _as_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _as_level(value: object) -> str | None:
    return value.lower() if isinstance(value, str) and value.lower() in _LEVELS else None


def _as_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _as_str_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, str) and v]
    return []


def _as_policy(value: object) -> dict[str, str]:
    """Keep only ``rule id -> valid action`` string pairs; drop anything malformed."""
    if not isinstance(value, dict):
        return {}
    out: dict[str, str] = {}
    for rule_id, action in value.items():
        if not (isinstance(rule_id, str) and rule_id and isinstance(action, str)):
            continue
        normalized = action.lower()
        if normalized in _POLICY_ACTIONS:
            out[rule_id] = normalized
    return out
