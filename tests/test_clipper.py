"""Clipboard address swap (ST-CLIPPER): a fixed crypto address written over the clipboard right
where the code has recognized an address. Copying the address a user chose stays clean, and so
does a dApp's "copy contract address" button far from its address validation."""

from __future__ import annotations

from pathlib import Path

from skilltotal.engine import analyze_directory
from skilltotal.models import Component, ThreatClass

RULE = "ST-CLIPPER"
ETH = "0x1111111111111111111111111111111111111111"  # fake, never a real wallet
BTC = "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"   # fake bech32 shape


def _scan(tmp_path: Path, name: str, text: str):
    (tmp_path / name).write_text(text, encoding="utf-8", newline="\n")
    return analyze_directory(tmp_path, Component(name="x", type="npm_package", source="x"))


def _ids(report) -> set[str]:
    return {f.id for f in report.findings}


def test_a_node_clipper_with_clipboardy_is_malicious(tmp_path):
    report = _scan(tmp_path, "index.js", f"""\
const clipboardy = require("clipboardy");
const ATTACKER = "{ETH}";
setInterval(() => {{
  const clip = clipboardy.readSync();
  if (/^0x[a-fA-F0-9]{{40}}$/.test(clip)) {{
    clipboardy.writeSync(ATTACKER);
  }}
}}, 500);
""")
    finding = next(f for f in report.findings if f.id == RULE)
    assert finding.threat_class == ThreatClass.MALICIOUS_INDICATOR
    assert report.verdict["has_malicious_indicators"]
    assert {ev.line_start for ev in finding.evidence} == {2, 6}


def test_a_spliced_address_written_through_a_replace_is_malicious(tmp_path):
    report = _scan(tmp_path, "swap.ts", f"""\
const MINE = "{BTC[:10]}" + "{BTC[10:]}";
export async function tick() {{
  const text = await navigator.clipboard.readText();
  const swapped = text.replace(/(bc1|[13])[a-zA-HJ-NP-Z0-9]{{25,62}}/g, MINE);
  await navigator.clipboard.writeText(swapped);
}}
""")
    assert RULE in _ids(report)


def test_a_python_clipper_is_malicious(tmp_path):
    report = _scan(tmp_path, "clip.py", f"""\
import re
import time

import pyperclip

WALLET = "{ETH}"
while True:
    text = pyperclip.paste()
    if re.fullmatch(r"0x[a-fA-F0-9]{{40}}", text):
        pyperclip.copy(WALLET)
    time.sleep(1)
""")
    assert RULE in _ids(report)


def test_copying_the_address_the_user_chose_is_clean(tmp_path):
    report = _scan(tmp_path, "Wallet.tsx", f"""\
const DONATE = "{ETH}";
export function Address({{ address }}) {{
  const valid = /^0x[a-fA-F0-9]{{40}}$/.test(address);
  const copy = () => navigator.clipboard.writeText(address); return valid ? address : DONATE;
}}
""")
    assert RULE not in _ids(report)


def test_a_copy_contract_button_far_from_validation_is_clean(tmp_path):
    filler = "\n".join(f"// layout line {i}" for i in range(20))
    report = _scan(tmp_path, "Token.tsx", f"""\
const USDC = "{ETH}";
export function isAddress(value) {{
  return /^0x[a-fA-F0-9]{{40}}$/.test(value);
}}
{filler}
export function CopyContract() {{
  return <button onClick={{() => navigator.clipboard.writeText(USDC)}}>Copy</button>;
}}
""")
    assert RULE not in _ids(report)


def test_a_swap_returned_without_a_clipboard_api_is_malicious(tmp_path):
    report = _scan(tmp_path, "check.js", f"""\
const ATTACKER = "{ETH}";
function hijack(clipboard) {{
  if (/^(bc1|0x)[a-z0-9]+/i.test(clipboard)) return ATTACKER;
  return clipboard;
}}
module.exports = {{ hijack }};
""")
    # No clipboard API: the caller writes what this returns (the red-team sample shape, flagged
    # since ruleset 78; see test_ruleset78.py).
    assert RULE in _ids(report)
