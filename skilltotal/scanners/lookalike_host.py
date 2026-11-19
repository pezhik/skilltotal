"""A URL host written to read as another host.

An address in an install command, a manifest or a registry setting is checked by eye:
``raw.githubusercontent.com`` looks right, and so does the same name with a Cyrillic ``i`` in it.
The second one is a different domain. Four spellings do this, and none of them is what an honest
internationalized name looks like:

* **mixed scripts in one word**: Latin letters next to Cyrillic, Greek, Armenian or Cherokee
  letters that each look like a Latin letter (``g<U+0456>thub``). Read after punycode decoding, so
  the ``xn--`` form of the same name is covered;
* **a whole word in look-alike letters** that reads as a well-known name (Cyrillic letters that
  spell ``paypal``);
* **full-width or enclosed letters**, which resolve to the plain ASCII host while not matching it
  as text (an allow-list or a reviewer's search for the host does not find it);
* **an ideographic full stop** between two ASCII labels, which resolves as a dot.

A label wholly in one script (``m<U+00FC>nchen``, a Cyrillic or CJK name), with or without
punycode, is an ordinary internationalized domain and is never reported: being non-ASCII is not
the tell. A Cyrillic word joined to a Latin one by a hyphen is two words, each in one script.

Read where an address is acted on without anyone typing it: package and agent manifests,
package-manager configuration, lockfiles, requirements files, shell scripts, and the command
lines of instruction files (``curl``, ``git clone``, ``npx`` ...). A URL quoted in the prose of an
instruction file is not read: a skill that warns about look-alike domains shows one. A file that
lists more than a few such hosts is a data set of them and is noted for review, not scored.
Nothing is resolved or fetched.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import replace

from skilltotal.file_index import FileIndex, IndexedFile, is_instruction_file
from skilltotal.models import Evidence, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    aggregated_review,
)
from skilltotal.text_normalize import _fold_char

R_LOOKALIKE_HOST = "ST-LOOKALIKE-HOST"

# The host of a URL: after the scheme and any `user@`, up to the path, port or the end of the
# token. Only a host with a non-ASCII character or a punycode label can be one of the spellings.
_URL_HOST = re.compile(
    r"(?i)\b(?:https?|wss?|git\+https?|git|ssh)://(?:[^\s/@'\"`<>]{0,200}@)?"
    r"([^\s/:?#'\"`<>|()\[\]{}\\,;=@]{1,255})"
)
_SUSPECT = re.compile(r"(?i)://[^\s/'\"`<>]{0,255}?(?:xn--|[^\x00-\x7f])")
_DOTS = "。．｡"
_LABEL_SPLIT = re.compile(f"[.{_DOTS}]")
_LETTER_RUN = re.compile(r"[^\W\d_]+")
_ASCII_LABEL = re.compile(r"[a-z0-9-]+")
# Scripts whose letters pass for Latin ones.
_LOOKALIKE_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE")
# Names a word written wholly in look-alike letters is measured against: code hosts, registries
# and the services an agent is most often pointed at.
_KNOWN_NAMES = frozenset({
    "github", "githubusercontent", "gitlab", "bitbucket", "google", "googleapis", "gstatic",
    "microsoft", "azure", "apple", "icloud", "amazon", "amazonaws", "cloudflare", "npmjs",
    "yarnpkg", "pypi", "pythonhosted", "python", "nodejs", "docker", "openai", "anthropic",
    "claude", "huggingface", "paypal", "stripe", "slack", "discord", "telegram", "dropbox",
    "vercel", "netlify", "heroku", "jsdelivr", "unpkg", "rubygems", "golang", "mozilla",
    "ubuntu", "debian",
})
# A command that fetches or installs from the address that follows it on the line.
_FETCH_COMMAND = re.compile(
    r"(?i)(?<![\w-])(?:curl|wget|git[ \t]+(?:clone|pull|fetch|remote|submodule)|pip3?|pipx|uvx?"
    r"|npm|npx|pnpm|yarn|bunx?|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer"
    r"|docker[ \t]+(?:pull|run|build)|go[ \t]+(?:install|get)|cargo[ \t]+install|brew"
    r"|claude[ \t]+mcp[ \t]+add)(?![\w-])"
)
_MANIFEST_NAMES = frozenset({
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    ".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini", ".pypirc", "uv.toml",
    "pyproject.toml", "setup.cfg", "pipfile", ".mcp.json", "mcp.json", "settings.json",
    "settings.local.json", "plugin.json", "marketplace.json", "server.json",
    "claude_desktop_config.json", "devcontainer.json", "dockerfile",
})
_REQUIREMENTS = re.compile(r"(?i)^(?:requirements|constraints)[\w.-]*\.txt$")
_MCP_CONFIG = re.compile(r"""["']?(?:mcpServers|mcp_servers)["']?\s*[:=\]]""")
_CONFIG_SUFFIXES = (".json", ".jsonc", ".toml", ".yaml", ".yml")
_SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".command", ".ps1", ".bat", ".cmd")
# More distinct look-alike hosts than this in one file: a list of them (a blocklist, test data).
_MAX_HOSTS_PER_FILE = 3
_MAX_HITS_PER_FILE = 2000


def _script_of(ch: str) -> str:
    """The look-alike script ``ch`` belongs to, "LATIN" for an ASCII letter, else ""."""
    if ch.isascii():
        return "LATIN" if ch.isalpha() else ""
    name = unicodedata.name(ch, "")
    return next((s for s in _LOOKALIKE_SCRIPTS if name.startswith(s)), "")


def _label_reading(label: str) -> tuple[str, str] | None:
    """``(the ASCII text the label reads as, how it is disguised)``, or None for an honest one."""
    compat = unicodedata.normalize("NFKC", label)
    if compat != label and compat.isascii() and any(
        not c.isascii() and unicodedata.normalize("NFKC", c).isalnum() for c in label
    ):
        return compat.lower(), "is written in full-width or enclosed letters"
    reading: list[str] = []
    how = ""
    last = 0
    for run in _LETTER_RUN.finditer(label):
        word = run.group()
        reading.append(label[last:run.start()])
        last = run.end()
        scripts = {_script_of(c) for c in word}
        foreign = sorted(scripts - {"LATIN", ""})
        skeleton = "".join(c if c.isascii() else _fold_char(c) for c in word).lower()
        if not foreign or "" in scripts or not skeleton.isascii() or not skeleton.isalpha():
            reading.append(word)  # one honest script, or letters that pass for nothing
            continue
        if "LATIN" in scripts:
            how = f"mixes Latin letters with look-alike {foreign[0].capitalize()} letters"
        elif skeleton in _KNOWN_NAMES:
            how = f"is written in {foreign[0].capitalize()} letters that read as a known name"
        else:
            reading.append(word)
            continue
        reading.append(skeleton)
    reading.append(label[last:])
    return ("".join(reading), how) if how else None


def lookalike_host(host: str) -> tuple[str, str] | None:
    """``(the ASCII host this one reads as, how)`` when ``host`` is spelled to pass for another
    host, else None. Punycode labels are decoded first; an honest internationalized name (each
    word in one script) is None."""
    host = host.rstrip("." + _DOTS)
    if not host or (host.isascii() and "xn--" not in host.lower()):
        return None
    labels = _LABEL_SPLIT.split(host)
    read: list[str] = []
    reasons: list[str] = []
    for label in labels:
        shown = label
        if label[:4].lower() == "xn--":
            try:
                shown = label[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                read.append(label)
                continue
        found = None if shown.isascii() else _label_reading(shown)
        if found is None:
            read.append(label)
            continue
        read.append(found[0])
        if found[1] not in reasons:
            reasons.append(found[1])
    if not reasons and any(d in host for d in _DOTS) and all(
        _ASCII_LABEL.fullmatch(label.lower()) for label in labels
    ):
        reasons.append("uses an ideographic full stop for a dot")
    if not reasons:
        return None
    return ".".join(read).lower(), "; ".join(reasons)


def _host_text(token: str) -> str:
    """``token`` up to the first full-width punctuation mark: `（`, `）`, `，`, `：` and the like
    close or follow an address in CJK prose the way their ASCII forms do, and are no part of it."""
    for i, ch in enumerate(token):
        if ch.isascii() or ch in _DOTS:
            continue
        plain = unicodedata.normalize("NFKC", ch)
        if plain.isascii() and not plain.isalnum() and plain not in ".-":
            return token[:i]
    return token


def _file_kind(f: IndexedFile) -> str:
    """How ``f`` is read: "instruction", "script", "manifest", or "" (not read)."""
    if is_instruction_file(f):
        return "instruction"
    name = f.name.lower()
    if name.endswith(_SCRIPT_SUFFIXES):
        return "script"
    if name in _MANIFEST_NAMES or name.startswith("dockerfile.") or _REQUIREMENTS.match(name):
        return "manifest"
    if name.endswith(_CONFIG_SUFFIXES) and _MCP_CONFIG.search(f.text):
        return "manifest"
    return ""


class LookalikeHostScanner(Scanner):
    name = "lookalike_host"
    rules = [
        RuleSpec(
            id=R_LOOKALIKE_HOST,
            category="supply_chain",
            severity=Severity.HIGH,
            title="Address written in look-alike letters",
            description=(
                "An address the component installs from, connects to or tells the agent to "
                "fetch has a host spelled to read as another host: Latin letters mixed with "
                "look-alike letters of another alphabet inside one word (directly or as its "
                "punycode `xn--` form), a word written wholly in such letters that reads as a "
                "well-known name, full-width or enclosed letters, or an ideographic full stop "
                "in place of a dot. The host that is contacted is not the one the address "
                "appears to name. An internationalized domain written in one script is not "
                "reported."
            ),
            recommendation=(
                "Do not install or connect. Compare the host character by character with the "
                "one it reads as (the evidence shows both), and find out how the address got "
                "into the file."
            ),
            capability=None,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        lists: list[tuple[str, int | None]] = []
        for f in index.files:
            if f.text.isascii() and "xn--" not in f.text:
                continue
            kind = _file_kind(f)
            if not kind or not _SUSPECT.search(f.text):
                continue
            found = _file_hosts(f, kind)
            if len(found) > _MAX_HOSTS_PER_FILE:
                lists.append((f.relpath, next(iter(found.values())).line_start))
            else:
                evidence.extend(found.values())
        findings = []
        if evidence:
            findings.append(_finding_from_rule(self.rules[0], evidence[:MAX_EVIDENCE_SCANNED]))
        needs_review: list[NeedsReview] = []
        if lists:
            needs_review.append(aggregated_review(
                category="supply_chain",
                title="File lists several look-alike hosts",
                places=lists,
                what="file(s) hold more than a few addresses whose host is spelled in "
                     "look-alike letters",
                advice="Usually a block list or test data. Confirm nothing installs from or "
                       "connects to them.",
            ))
        return ScanResult(findings=findings, needs_review=needs_review)


def _file_hosts(f: IndexedFile, kind: str) -> dict[str, Evidence]:
    """Evidence for each distinct look-alike host of ``f``, by host as written."""
    text = f.text
    found: dict[str, Evidence] = {}
    pos = 0
    for _ in range(_MAX_HITS_PER_FILE):
        suspect = _SUSPECT.search(text, pos)
        if suspect is None:
            break
        # The scheme ends where the suspect match starts: read the URL from the line's start.
        line_start, line_end = f.line_bounds(suspect.start(), suspect.end())
        pos = line_end + 1
        for m in _URL_HOST.finditer(text, line_start, line_end):
            host = _host_text(m.group(1))
            host_end = m.start(1) + len(host)
            if host in found or (host.isascii() and "xn--" not in host.lower()):
                continue
            reading = lookalike_host(host)
            if reading is None:
                continue
            if "full stop" in reading[1] and text[host_end:host_end + 1] not in ("/", ":"):
                continue  # a sentence that ends after an address, in CJK punctuation
            if kind == "instruction" and not _FETCH_COMMAND.search(text, line_start, m.start()):
                continue  # an address shown in prose, not one a command is run against
            if kind == "script" and f.in_shell_comment(m.start()):
                continue
            ev = f.evidence_for_span(m.start(1), host_end)
            note = f"  [host {ascii(host)} reads as {reading[0]!r}: it {reading[1]}]"
            found[host] = replace(ev, snippet=ev.snippet[:200] + note)
    return found
