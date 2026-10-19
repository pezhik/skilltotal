"""Shipped rule ids are a public contract: they never disappear.

A rule id is what a customer writes into `.skilltotal.toml` (`ignore`, `[policy]`), what a baseline
fingerprint hashes, and what a `skilltotal:ignore[ST-X]` marker names. The config loader refuses an
unknown id, so a rule renamed or removed in a release would break every config that names it, on
an upgrade the customer did not ask to review. ``tests/data/shipped_rule_ids.txt`` lists every id a
release has shipped; it only grows.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.config import load_config
from skilltotal.rules import get_rules

SHIPPED = Path(__file__).resolve().parent / "data" / "shipped_rule_ids.txt"

# A shipped id that no rule has any more -> the id of the rule that replaced it. The config loader
# must accept the old id too (test_the_config_loader_accepts_every_shipped_id), so adding an entry
# here means teaching the loader the alias as well.
_ALIASES: dict[str, str] = {}


def _shipped() -> list[str]:
    lines = SHIPPED.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def _current() -> set[str]:
    return {rule.id for rule in get_rules()}


def test_the_list_is_read_and_has_no_duplicates():
    shipped = _shipped()
    assert len(shipped) >= 90, f"only {len(shipped)} ids read from {SHIPPED.name}"
    assert len(shipped) == len(set(shipped)), "an id is listed twice"


def test_every_shipped_id_still_exists_or_has_an_alias():
    current = _current()
    gone = [rule_id for rule_id in _shipped() if rule_id not in current and rule_id not in _ALIASES]
    assert not gone, (
        f"shipped rule id(s) no longer exist: {gone}. Keep the rule, or map the old id to its "
        "replacement in _ALIASES and make the config loader accept it.")
    dangling = {old: new for old, new in _ALIASES.items() if new not in current}
    assert not dangling, f"aliases point at rule ids that do not exist: {dangling}"


def test_every_current_rule_is_listed():
    """A new rule is appended when it ships, so the next release cannot drop it unnoticed."""
    missing = sorted(_current() - set(_shipped()))
    assert not missing, f"append these rule ids to tests/data/{SHIPPED.name}: {missing}"


def test_the_config_loader_accepts_every_shipped_id(tmp_path):
    shipped = _shipped()
    config_path = tmp_path / ".skilltotal.toml"
    config_path.write_text(
        "ignore = [\n" + "".join(f'    "{rule_id}",\n' for rule_id in shipped) + "]\n",
        encoding="utf-8")
    config = load_config(config_path)  # raises ConfigError on an id it does not know
    assert config.ignore == shipped
