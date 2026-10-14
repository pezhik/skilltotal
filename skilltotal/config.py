"""Optional project configuration — ``.skilltotal.toml``.

A small, optional convenience for CI adoption: a project can commit fail thresholds,
path excludes, and per-rule ignores instead of repeating CLI flags. Stdlib only (tomllib on
3.11+, a minimal regex fallback on 3.10). CLI flags always override config values.

Recognized top-level keys:
    fail_on        = "low" | "medium" | "high" | "critical"
    fail_on_score  = <int 0-100>
    fail_on_unanalyzed = true | false  # fail when a file, or part of one, was not analyzed
    exclude        = ["glob/*", ...]   # path globs (posix, relative to the component root)
    ignore         = ["ST-RULE-ID", ...]
    baseline       = "path/to/baseline.json"

Per-rule policy (reviewable, lives in the repo — no dashboard or account needed):
    [policy]
    "ST-SHELL-PIPE-EXEC" = "block"    # gate trips (exit 2) whenever this rule fires
    "ST-DESERIALIZE-PY"  = "warn"     # reported, but exempt from the fail_on severity gate
    "ST-SENS-WORD"       = "ignore"   # suppressed entirely (same effect as `ignore`)

`block` overrides severity thresholds (it trips even with no `fail_on` configured, also for a
capability rule, which the severity gate never counts on its own); `warn`
is an explicit accept-but-show (the finding stays in the report and still counts toward the
risk score / `fail_on_score`).

A config that cannot be read as written is an error, never an empty config: invalid TOML, an
unknown key (a typo such as `fail_onn`), a value of the wrong kind or out of range (`fail_on =
"hgih"`, `fail_on_score = 200`) and an unknown policy action all raise ``ConfigError``, which
the CLI reports with exit code 1. Read any other way, a typo would turn a CI gate off.
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
_KEYS = ("fail_on", "fail_on_score", "fail_on_unanalyzed", "exclude", "ignore", "baseline",
         "policy")


class ConfigError(ValueError):
    """A config that would switch a gate off by mistake if read leniently: reported, never read
    as off."""


@dataclass
class Config:
    """Resolved project configuration (all fields optional)."""

    fail_on: str | None = None
    fail_on_score: int | None = None
    fail_on_unanalyzed: bool = False
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
    """Parse a ``.skilltotal.toml`` file; raise ``ConfigError`` for anything it cannot honor."""
    # utf-8-sig strips a leading BOM if present (Windows editors / PowerShell often add one);
    # tomllib rejects a BOM, which would otherwise silently void the whole config (fail-open).
    try:
        text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc.strerror or exc}") from exc
    data = _parse(text, path)
    unknown = sorted(k for k in data if k not in _KEYS)
    if unknown:
        raise ConfigError(f"{path}: unknown key(s) {', '.join(unknown)}; "
                          f"known keys: {', '.join(_KEYS)}")
    unanalyzed = data.get("fail_on_unanalyzed", False)
    if not isinstance(unanalyzed, bool):
        raise ConfigError(f"{path}: fail_on_unanalyzed must be true or false, not {unanalyzed!r}")
    return Config(
        fail_on=_level_value(data, path),
        fail_on_score=_score_value(data, path),
        fail_on_unanalyzed=unanalyzed,
        exclude=_str_list_value(data, "exclude", path),
        ignore=_str_list_value(data, "ignore", path),
        baseline=_str_value(data, "baseline", path),
        policy=_policy_value(data, path),
    )


def _parse(text: str, path: Path) -> dict[str, object]:
    if tomllib is not None:
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            raise ConfigError(f"{path}: not valid TOML: {exc}") from exc
        return data if isinstance(data, dict) else {}
    return _fallback_parse(text)  # pragma: no cover - 3.10 path


def _fallback_parse(text: str) -> dict[str, object]:  # pragma: no cover - 3.10 only
    """Best-effort parse of the handful of supported scalar/array keys (no tomllib)."""
    out: dict[str, object] = {}
    # Top-level keys before any [table]: one the parser does not know is reported, not skipped.
    top = re.split(r"^\s*\[", text, maxsplit=1, flags=re.MULTILINE)[0]
    for m in re.finditer(r"^\s*([A-Za-z_][\w-]*)\s*=", top, re.MULTILINE):
        if m.group(1) not in _KEYS:
            out[m.group(1)] = None
    for key in ("fail_on", "baseline"):
        m = re.search(rf'^\s*{key}\s*=\s*(.*?)\s*(?:#.*)?$', text, re.MULTILINE)
        if m:
            raw = m.group(1)
            out[key] = raw[1:-1] if len(raw) >= 2 and raw[0] == raw[-1] == '"' else raw
    m = re.search(r"^\s*fail_on_score\s*=\s*(.*?)\s*(?:#.*)?$", text, re.MULTILINE)
    if m:
        out["fail_on_score"] = int(m.group(1)) if m.group(1).isdigit() else m.group(1)
    m = re.search(r"^\s*fail_on_unanalyzed\s*=\s*([^#\n]*?)\s*(?:#.*)?$", text, re.MULTILINE)
    if m:
        value = m.group(1)
        out["fail_on_unanalyzed"] = {"true": True, "false": False}.get(value, value)
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


def _level_value(data: dict[str, object], path: Path) -> str | None:
    if "fail_on" not in data:
        return None
    value = data["fail_on"]
    if isinstance(value, str) and value.lower() in _LEVELS:
        return value.lower()
    raise ConfigError(f"{path}: fail_on must be one of low, medium, high, critical, "
                      f"not {value!r}")


def _score_value(data: dict[str, object], path: Path) -> int | None:
    if "fail_on_score" not in data:
        return None
    value = data["fail_on_score"]
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100:
        return value
    raise ConfigError(f"{path}: fail_on_score must be a whole number from 0 to 100, "
                      f"not {value!r}")


def _str_value(data: dict[str, object], key: str, path: Path) -> str | None:
    if key not in data:
        return None
    value = data[key]
    if isinstance(value, str) and value:
        return value
    raise ConfigError(f"{path}: {key} must be a non-empty string, not {value!r}")


def _str_list_value(data: dict[str, object], key: str, path: Path) -> list[str]:
    if key not in data:
        return []
    value = data[key]
    if isinstance(value, list) and all(isinstance(v, str) and v for v in value):
        return list(value)
    raise ConfigError(f"{path}: {key} must be a list of non-empty strings, not {value!r}")


def _policy_value(data: dict[str, object], path: Path) -> dict[str, str]:
    """``rule id -> block | warn | ignore``; anything else is an error, not a dropped entry: a
    misspelled `block` would leave the rule unblocked."""
    if "policy" not in data:
        return {}
    value = data["policy"]
    if not isinstance(value, dict):
        raise ConfigError(f"{path}: [policy] must be a table of rule id = action")
    out: dict[str, str] = {}
    for rule_id, action in value.items():
        normalized = action.lower() if isinstance(action, str) else None
        if not (isinstance(rule_id, str) and rule_id) or normalized not in _POLICY_ACTIONS:
            raise ConfigError(f"{path}: [policy] {rule_id!r} = {action!r}: the action must be "
                              f"block, warn or ignore")
        out[rule_id] = normalized
    return out
