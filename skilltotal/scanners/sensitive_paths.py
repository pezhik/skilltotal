"""Sensitive path / secret-location reference detection.

Strong, path-like indicators (``~/.ssh``, ``~/.aws``, ``id_rsa``, ``.aws/credentials``, an
``.env`` *file*) are high-severity findings. Bare words ``credentials`` / ``secrets`` are
too ambiguous (often variable or field names) so they are routed to ``needs_review``.

Note the ``.env`` pattern uses a negative lookbehind so it matches the file ``'.env'`` but
**not** ``process.env`` (reading environment variables is not file access).

False-positive calibration: the *bare* ``.env`` token is extremely common in legitimate
documentation (``.rst``/``.md``/``.mdx`` describing dotenv support) and in ignore files
(``.gitignore``/``.dockerignore`` listing ``.env`` precisely so it is **not** committed —
the opposite of accessing it). Those file types are excluded from the ``.env`` signal only;
the strong path-like indicators (``~/.aws``, ``~/.ssh``, ``id_rsa`` …) still fire
everywhere, including documentation, so prompt-injection style instructions to read a
credential file in an ``.md`` are still caught.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterator

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    alternation,
    concat_folded_spans,
)

CATEGORY = "sensitive_path"

# String concatenation is folded for matching only where C-family string literals stay in scope
# (ST-SENS-PATH keeps them; see code_context). In Python a credential path is caught by the AST
# rule and ``"a" "b"`` is folded by the parser, so folding the regex there would only be demoted.
_JS_FAMILY = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")

# Strong, path-like credential locations. These are unambiguous enough to flag in any
# file type, including documentation.
_STRONG_PATHS = alternation(
    # ~/.ssh but NOT `~/.ssh/known_hosts` (public host keys, never a credential — pyzmq reads it
    # for its SSH tunnel). `~/.ssh/config` DOES stay flagged: writing it is a real SSH-config
    # injection vector; a legitimate reader (dulwich's git-over-ssh) is cleared by the provider
    # credential-domain match in scoring, not by dropping detection. Private keys still match.
    # `authorized_keys` and `*.pub` are public keys too: provisioning code appends to the first and
    # uploads the second, and neither grants access to anything when read.
    r"~/\.ssh(?!/(?:known_hosts|authorized_keys)\b|/[\w.-]+\.pub\b)",
    r"\.ssh/(?!known_hosts\b|authorized_keys\b|[\w.-]+\.pub\b)",
    r"~/\.aws",
    r"\.aws/credentials",
    r"~/\.kube",
    r"~/\.config/gcloud",
    r"\bid_rsa\b(?!\.pub\b)",
    # Cloud / registry / wallet credential locations seen in real cred-stealers.
    r"\.docker/config\.json",
    r"~/\.azure",
    r"\.git-credentials",
    r"application_default_credentials\.json",
    r"169\.254\.169\.254",  # cloud instance-metadata endpoint (SSRF / token theft)
    r"\bwallet\.dat\b",
    r"\.ethereum/keystore",
    # Home-relative like the Shai-Hulud paths below: a Solana CLI keypair is read as often via
    # `os.homedir() + "/.config/solana/id.json"` (folds to `/.config/solana/...`) as with `~`.
    r"\.config/solana",
    # Shai-Hulud "Third Coming" (Bitwarden CLI 2026.4.0) and s1ngularity read these, written
    # relative to the home directory as often as with `~`.
    r"\.kube/config\b",
    r"gcloud/credentials\.db",
    r"\.azure/(?:credentials|accessTokens\.json|msal_token_cache)",
    r"~/\.npmrc",
    r"~/\.pypirc",
    r"\.config/gh/hosts\.yml",
    # Local AI coding agents keep their login here; stealing it hands over the account.
    r"\.claude/\.credentials\.json",
    r"\.codex/auth\.json",
    r"\.gemini/oauth_creds\.json",
    r"\.config/github-copilot/(?:hosts|apps)\.json",
    # The sckit stealer (compromised @memtensor npm + PyPI packages, September 2026) targeted
    # these alongside id_rsa: the other OpenSSH key types, a HashiCorp Vault CLI token, and the
    # Hugging Face CLI's cached access token. A written `.ssh/id_ed25519` is already a `.ssh/`
    # path above; the key-type name alone is not a credential (an application can keep its own
    # signing key at ~/.<app>/id_ed25519), so it counts only joined onto an `.ssh` segment.
    r"""['"]\.ssh['"]\s*,\s*['"]id_(?:rsa|ecdsa|ed25519|dsa)['"]""",
    r"\.vault-token\b",
    r"\.cache/huggingface/token\b",
    flags=re.IGNORECASE,
)

# The bare ".env" file token (negative lookbehind so "process.env" is not matched). Common
# in benign docs/ignore files, so it is suppressed there (see _IGNORED_FOR_ENV).
_ENV_FILE = re.compile(r"(?<![\w.])\.env\b", re.IGNORECASE)

# File types where a bare ".env" mention is almost always benign (prose documentation or an
# ignore list), so the ".env" signal is not raised for them.
_DOC_SUFFIXES = frozenset({".md", ".mdx", ".rst", ".txt", ".adoc"})
_IGNORE_FILENAMES = frozenset(
    {".gitignore", ".dockerignore", ".npmignore", ".prettierignore", ".eslintignore"}
)


def _suppresses_env(relpath: str) -> bool:
    """True if a bare ``.env`` mention in this file is too benign to flag."""
    lower = relpath.lower()
    name = lower.rsplit("/", 1)[-1]
    if name in _IGNORE_FILENAMES:
        return True
    dot = name.rfind(".")
    suffix = name[dot:] if dot > 0 else ""
    return suffix in _DOC_SUFFIXES


# A guardrail/denylist that PROTECTS a credential location is the opposite of accessing it: a
# security tool's policy listing `id_rsa`/`.ssh` as paths to deny is a defensive artifact, not an
# exfiltration precursor. Such matches are routed to needs_review so they neither score nor feed
# the credential-exfiltration combo. Real access (a path passed to open()/readFileSync()) is a
# function argument — not a guard segment, keyword, or bare list element — so it still fires.
_GUARD_PATH_SEGMENTS = frozenset(
    {
        "policy",
        "policies",
        "guard",
        "guards",
        "denylist",
        "allowlist",
        "blocklist",
        "blocklists",
        "sandbox",
        "permission",
        "permissions",
        "security",
        "acl",
        "blacklist",
        "whitelist",
        "ignorelist",
    }
)
_GUARD_KEYWORDS = re.compile(
    r"(?i)\b(?:deny|denied|denylist|block|blocked|blocklist|forbid|forbidden|exclude|excluded|"
    r"reject|protect|protected|sensitive|redact|sanitize|allowlist|dangerous|risky|suspicious|"
    # camelCase and snake_case list names: `const dangerousPaths = ['~/.ssh', '~/.aws']`.
    r"(?:dangerous|risky|sensitive|protected|blocked)_?(?:paths?|files?|dirs?))\b"
)
# A bare string-literal list element: only a quoted string + optional `.to_string()`/`.into()`
# and a trailing comma (e.g. `"id_rsa".to_string(),`, `"**/.ssh/*",`). Declarative data, not a call.
# Written so that no text matches it two ways: `0[oxb]?[0-9a-fA-F]+|\d+` both took `01`, so a line
# of `01,01,…` failed in 2^n ways, and optional parts between `\s*` runs (`\s*[\])]?\s*…,?\s*$`)
# split trailing blanks every way. Each optional part now starts with the character that marks it.
_LIST_ITEM = (
    r"""(?:["'][^"'\n]*["'](?:\s*\.\w+\(\))?|0[oxb][0-9a-fA-F]+|0[0-9a-fA-F]+|[1-9]\d*|0)"""
)
_BARE_LIST_ELEMENT = re.compile(
    r"^\s*(?:\|\s*)?(?:[\[(]\s*)?"
    + r"(?:" + _LIST_ITEM + r"\s*[,:]\s*)*" + _LIST_ITEM
    + r"(?:\s*[\])])?(?:\s*=>\s*\w+)?(?:\s*,)?\s*$"
)
# A trailing `// ssh private key` or `# comment` after a list element is still just a list element.
# Starts only where a run of whitespace starts: from every position inside a long run, `\s+` backed
# off across the whole run again (20,000 spaces before a credential path took 49 s).
_TRAILING_COMMENT = re.compile(r"(?<!\s)\s+(?://|#).*$")
# A bare regex-literal list element: a slash-delimited regex (optional flags) on its own line,
# e.g. `/id_rsa/,`, `/credentials/i,`, `/\.pem$/,`. A regex literal is a PATTERN that matches
# against paths, never a path being accessed — so a credential token inside one is a detector's
# denylist entry (as in a `SENSITIVE_PATHS = [ /id_rsa/, ... ]` array), not exfiltration.
_NAME_COMPARISON = re.compile(
    r"""(?:[=!]==?\s*["'`]$|\bstrn?casecmp\s*\(|\bstrcmp\s*\(|\bequals(?:IgnoreCase)?\s*\()"""
)
_BARE_REGEX_ELEMENT = re.compile(r"^\s*/(?:\[[^\]\n]*\]|[^/\\\n\[]|\\.)+/[gimsuvy]*(?:\s*,)?\s*$")


def is_metadata_without_credentials(matched: str, text: str) -> bool:
    """True for an instance-metadata reference that does not ask for the role's credentials.

    A node's own bootstrap script reads its instance id, region or an IMDSv2 session token from
    169.254.169.254; a thief reads `iam/security-credentials` (or a service-account token).
    """
    return bool(_METADATA_MATCH.match(matched)) and not _METADATA_CREDENTIAL.search(text)


def _guard_segment(relpath: str) -> bool:
    # Tokenize each path segment on `._-` so guard code is recognized whether it's a directory
    # (policies/) or a filename (net_guard.rs, path_guard.rs, denylist.go).
    for part in relpath.lower().split("/"):
        if any(tok in _GUARD_PATH_SEGMENTS for tok in re.split(r"[._-]", part)):
            return True
    return False


# A macOS sandbox (Seatbelt / SBPL) rule that DENIES access: `(deny file-read* (literal
# (string-append (param "HOME_DIR") "/.gemini/oauth_creds.json")))`. Agent CLIs ship such profiles
# to keep the tools they run away from the CLI's own login; the path names what is protected, so it
# is the opposite of a read. Only deny rules for file operations count; an `(allow ...)` is not a
# guard. The rule may span many lines, so the enclosing form is found by its parentheses; it must
# open a line and contain only SBPL (forms, symbols, strings) up to the path, so a `// (deny file*`
# comment cannot stand in front of a real read in JavaScript.
_SBPL_DENY_FILE = re.compile(r"(?m)^[ \t]*\(\s*deny\s+file[\w*-]*")
_SBPL_MAX_FORM = 8000
_NOT_SBPL = frozenset(";{}=")


def _sandbox_deny_spans(text: str) -> list[tuple[int, int]]:
    """Char-spans of Seatbelt ``(deny file-…)`` forms, in order and not overlapping.

    Each span runs from the form's ``(`` to its closing ``)``, and stops early at the first
    character that cannot be profile syntax (``;``, ``{``, ``}``, ``=``: code, not a profile). One
    linear pass: a form that starts inside one already walked is skipped.
    """
    spans: list[tuple[int, int]] = []
    walked_to = 0
    for rule in _SBPL_DENY_FILE.finditer(text):
        start = rule.start() + rule.group(0).index("(")
        if start < walked_to:
            continue
        depth, i, stop = 0, start, min(len(text), start + _SBPL_MAX_FORM)
        while i < stop:
            ch = text[i]
            if ch == '"':  # an SBPL string: its parentheses (a regex such as "($|x)") do not count
                close = text.find('"', i + 1, stop)
                while close != -1 and text[close - 1] == "\\":
                    close = text.find('"', close + 1, stop)
                if close == -1:
                    break
                i = close + 1
                continue
            if ch in _NOT_SBPL:
                break
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
        spans.append((start, i))
        walked_to = i
    return spans


def _in_spans(spans: list[tuple[int, int]], offset: int) -> bool:
    """True if ``offset`` falls in one of the sorted, non-overlapping ``spans``."""
    k = bisect.bisect_right(spans, (offset, float("inf"))) - 1
    return k >= 0 and spans[k][0] <= offset < spans[k][1]


def _is_guardlist_context(relpath: str, line_text: str, matched: str = "") -> bool:
    """True if a sensitive-path match is a defensive denylist/guardrail mention, not access."""
    # Leading whitespace goes before the list-element regexes, whose own leading `\s*` runs into a
    # second `\s*` and splits a long indentation every possible way.
    bare = _TRAILING_COMMENT.sub("", line_text).lstrip()
    return (
        _guard_segment(relpath)
        or bool(_NAME_COMPARISON.search(bare[: bare.find(matched)] if matched in bare else ""))
        or bool(_GUARD_KEYWORDS.search(line_text))
        or (bool(_BARE_LIST_ELEMENT.match(bare)) and not _json_command_line(relpath, bare))
        or bool(_BARE_REGEX_ELEMENT.match(bare))
    )


# In a JSON file every string sits on a line of its own shape (`"value",` or `"key": "value"`),
# which is what a bare list element looks like, so the list-element test demoted the command of
# every hook and MCP server entry as if it were a denylist entry: a startup command that uploads
# `~/.ssh/id_rsa` scored nothing. A JSON string that is a command -- a program followed by
# arguments, a string with shell operators, or a URL handed to a network client -- is not a
# denylist entry. A bare path or glob (`"~/.ssh/id_rsa"`, `"**/.aws/**"`) still is, and so is a
# Claude Code permission rule (`"Read(~/.ssh/**)"`, `"Bash(cat ~/.ssh/id_rsa)"`).
_JSON_SUFFIXES = (".json", ".jsonc", ".json5")
_JSON_LINE_STRING = re.compile(r'"((?:[^"\\\n]|\\.){0,2000})"')
_PERMISSION_RULE = re.compile(
    r"^(?:Bash|Read|Write|Edit|MultiEdit|NotebookEdit|WebFetch|WebSearch|Glob|Grep|Task|"
    r"mcp__[\w-]+)\("
)
_PROGRAM = (
    r"(?:curl|wget|nc|ncat|netcat|socat|scp|rsync|sftp|ftp|cat|cp|mv|tar|zip|gzip|base64|"
    r"openssl|gpg|sh|bash|zsh|dash|ksh|pwsh|powershell|cmd|python[0-9.]*|node|deno|bun|npx|bunx|"
    r"uvx|pipx|npm|pnpm|yarn|perl|ruby|php|osascript|security|docker|aws|gcloud|az|kubectl|ssh|"
    r"git|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)"
)
_COMMAND_START = re.compile(
    rf"^(?:[A-Za-z_]\w*=\S*\s+)*(?:sudo\s+)?{_PROGRAM}(?:\.exe)?\s+\S", re.IGNORECASE
)
_PATH_PROGRAM = re.compile(r"^(?:\.{1,2}/|/|~/|\$\{?\w+\}?/)[\w./-]+\s+\S")
_SHELL_OPERATOR = re.compile(
    rf"&&|\|\||\s\|\s*\S|\S\|\s+\S|;\s*(?:sudo\s+)?{_PROGRAM}\b|\$\(", re.IGNORECASE
)
_NETWORK_PROGRAM = re.compile(
    r"\b(?:curl|wget|nc|ncat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b", re.IGNORECASE
)
# Keys whose string is shown to a person: a sentence there describes a command, it is not one.
_JSON_TEXT_KEYS = frozenset(
    {"description", "title", "summary", "help", "message", "label", "example", "examples",
     "note", "notes", "detail", "details", "hint", "comment", "displayname", "name"}
)


def _json_command_line(relpath: str, bare: str) -> bool:
    """True when a JSON line's string value is a command rather than a list entry."""
    if not relpath.lower().endswith(_JSON_SUFFIXES):
        return False
    strings = _JSON_LINE_STRING.findall(bare)
    if not strings:
        return False
    if len(strings) >= 2 and bare.lstrip().startswith('"') and (
        strings[0].strip().lower() in _JSON_TEXT_KEYS
    ):
        return False
    value = strings[-1].replace('\\"', '"').strip()
    if _PERMISSION_RULE.match(value) or not re.search(r"\s", value):
        return False
    if _COMMAND_START.match(value) or _PATH_PROGRAM.match(value):
        return True
    if _SHELL_OPERATOR.search(value):
        return True
    return bool(re.search(r"https?://", value) and _NETWORK_PROGRAM.search(value))


# A credential location that the line names without reading it. Each shape is a different reason:
# a directory being created or locked down (`mkdir -p ~/.ssh && chmod 700 ~/.ssh`), or a private
# key handed to the SSH client as its identity (`ssh -i ~/.ssh/deploy`, `IdentityFile`,
# `ssh-keygen -f`). The SSH client reads that key locally to authenticate; nothing is sent. Writing
# a credential file is NOT among them: `cat > ~/.ssh/config` is an SSH-config injection vector.
# Copying the key somewhere (`scp ~/.ssh/id_rsa host:`, `cat ~/.ssh/id_rsa | curl`) has none of
# these shapes and still fires.
_DIR_SETUP_BEFORE = re.compile(r"\b(?:mkdir|chmod|chown|rm)\b[^|;&\n]*$")
_BARE_DIR_MATCH = re.compile(r"(?i)^(?:~/)?\.ssh/?$")
_SSH_IDENTITY_BEFORE = re.compile(
    r"(?:(?<![\w-])-i\s*=?\s*|\bIdentityFile\s+|\bssh-keygen\b[^|;&\n]*\s-f\s*|\bssh-add\s+)"
    r"[\"']?[^\s\"'|;&]*$"
)
# The same key kept in a variable named for it (`SSH_KEY="$HOME/.ssh/deploy"` in a deploy script,
# `sshKey: get('--ssh-key') ?? '/root/.ssh/id_ed25519'`). The name says what reads it.
_SSH_KEY_VARIABLE_BEFORE = re.compile(
    r"(?i)(?:\b|_)(?:ssh[_-]?key(?:[_-]?path)?|deploy[_-]?key|identity[_-]?file)\w*[\"']?\s*"
    r"(?:[:=]|\?\?|\|\||:-)"
    r"[^|;&\n]*$"
)
# A kubeconfig handed to a Kubernetes client as its configuration (`kc-agent --kubeconfig
# ~/.kube/config`, `KUBECONFIG=~/.kube/config kubectl …`): like `ssh -i`, the client reads it
# locally to authenticate. Only when nothing on the rest of the line pipes, redirects or substitutes
# it: `kubectl --kubeconfig ~/.kube/config config view --raw | curl …` dumps the file and stays
# flagged.
_KUBECONFIG_FLAG_BEFORE = re.compile(r"(?:--kubeconfig[=\s]+|\bKUBECONFIG=)[\"']?$")
_SHELL_PLUMBING = re.compile(r"[|>`]|\$\(|<\(")
# `match = "**/.ssh/*"` in a policy template is a pattern for paths, not a path.
_POLICY_GLOB_BEFORE = re.compile(r"\*\*/$")
# The cloud instance-metadata service answers two very different questions. Asking it for the
# instance id, region or an IMDSv2 session token is what a node's own bootstrap script does; asking
# it for the role's credentials (`iam/security-credentials`, a service-account token, the Azure
# identity endpoint) is the theft that made the address worth flagging.
_METADATA_MATCH = re.compile(r"^169\.254\.169\.254$")
_METADATA_CREDENTIAL = re.compile(
    r"(?i)iam/security-credentials|service-accounts/[^/\s]+/(?:token|identity)|"
    r"metadata/identity/oauth2/token|/latest/meta-data/iam\b"
)
# `[ -f /root/.ssh/deploy ] || exit 1` checks that the key exists; it does not read it.
_EXISTS_TEST_BEFORE = re.compile(r"(?:\[\[?|\btest)\s+-[efsr]\s+[\"']?[^\s\"']*$")
# A whole-line comment in a configuration file (`.npmrc`, `.toml`, `.ini`, `.cfg`, `.conf`).
_CONFIG_COMMENT_LINE = re.compile(r"^\s*[#;]")
_CONFIG_SUFFIXES = frozenset(
    {".npmrc", ".toml", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".properties"}
)
# Object keys and attributes whose string value is shown to a person.
_UI_TEXT_KEY_BEFORE = re.compile(
    r"(?i)\b(?:placeholder|label|hint|description|desc|title|help(?:text)?|tooltip|resolution|"
    r"message|note|example)[\"']?\s*[:=]\s*[`\"']?$"
)
# A sentence in a string: help text, an error message, a blog post kept in a `.ts` module
# (`'Neither KUBECONFIG nor ~/.kube/config exists'`). A path a program opens sits in a short
# string of its own or in a command; neither reads as five words of prose.
_PROSE_WORD = re.compile(r"(?<![\w/.~-])[A-Za-z][a-z]+(?![\w/.-])")
_COMMAND_HINT = re.compile(
    r"\|\s*\w|&&|>\s*[\"'/~$]|<\s*[\"'/~$]|\$\(|\b(?:cat|curl|wget|scp|rsync|nc|base64|tar|cp)\s"
)
_PROSE_MIN_WORDS = 5


_CJK_LETTERS = re.compile(r"[\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]")
_PROSE_MIN_CJK = 4


def _is_prose_string(literal: str) -> bool:
    body = literal.strip("\"'`")
    if _COMMAND_HINT.search(body):
        return False
    return (
        len(_PROSE_WORD.findall(body)) >= _PROSE_MIN_WORDS
        or len(_CJK_LETTERS.findall(body)) >= _PROSE_MIN_CJK
    )


def _line_quoted_segment(line_text: str, col: int) -> str | None:
    """The quoted run holding column ``col`` on this line, for shell/Makefile lines."""
    quote, start = "", 0
    for k, ch in enumerate(line_text):
        if quote:
            if ch == quote:
                if start <= col < k:
                    return line_text[start:k]
                quote = ""
        elif ch in ("'", '"'):
            quote, start = ch, k + 1
    return None


def _not_a_read(f, start: int, matched: str, line_text: str) -> bool:
    """True if the line names a credential location without reading it (see above).

    ``start`` is where the reference begins in the file and ``matched`` the credential path it
    names: the regex match for a written path, the built path for a joined one.
    """
    col = start - f.text.rfind("\n", 0, start) - 1
    before = line_text[: max(0, col)]
    if _BARE_DIR_MATCH.match(matched) and _DIR_SETUP_BEFORE.search(before):
        return True
    if _SSH_IDENTITY_BEFORE.search(before) or _SSH_KEY_VARIABLE_BEFORE.search(before):
        return True
    if _KUBECONFIG_FLAG_BEFORE.search(before) and not _SHELL_PLUMBING.search(
        line_text[col + len(matched):]
    ):
        return True
    if _POLICY_GLOB_BEFORE.search(before) or _EXISTS_TEST_BEFORE.search(before):
        return True
    if is_metadata_without_credentials(matched, line_text):
        return True
    name = f.relpath.rsplit("/", 1)[-1].lower()
    config_suffix = name if name.startswith(".") and "." not in name[1:] else f.suffix
    if config_suffix in _CONFIG_SUFFIXES and _CONFIG_COMMENT_LINE.match(line_text):
        return True
    if f.string_is_executed(start):
        return False
    span = f.string_span_at(start)
    if span is not None:
        # Judge the part of the literal on this line: a blog post kept in one template literal
        # contains tables and code, yet each sentence in it is still a sentence.
        line_start = start - col
        line_end = line_start + len(line_text)
        segment = f.text[max(span[0], line_start) : min(span[1], line_end)]
        # The key in front of the literal, with its opening quote: `placeholder: "~/.ssh/id_rsa"`.
        ahead = f.text[line_start : span[0] + 1] if span[0] >= line_start else ""
        if _is_prose_string(segment) or _UI_TEXT_KEY_BEFORE.search(ahead):
            return True
    elif f.is_shell_like:
        quoted = _line_quoted_segment(line_text, col)
        if quoted is not None and _is_prose_string(quoted):
            return True
    elif len(_CJK_LETTERS.findall(line_text)) >= _PROSE_MIN_CJK:
        # No string lexer for this file type (.astro, .vue): a line of Chinese or Japanese around
        # the path is a sentence wherever it sits.
        return True
    return f.in_rendered_markup_text(start)


# Markdown files where an inline-code span (`...`) is a *cited example*, not path access. A security
# guide that lists `write to ~/.ssh` / `store credentials` as patterns to detect is describing the
# threat, not performing it. Scoped to markdown ONLY — in code, a backtick is a JS template literal
# (`~/.ssh/${x}`) which IS real path usage, so it must still fire there.
_MD_SUFFIXES = frozenset({".md", ".mdx", ".markdown"})


def _cited_in_markdown_code(relpath: str, line_text: str, matched: str) -> bool:
    """True if ``matched`` falls inside a markdown inline-code span on this line. Splitting on the
    backtick delimiter, odd-indexed segments are inside `` `...` `` spans."""
    name = relpath.lower().rsplit("/", 1)[-1]
    dot = name.rfind(".")
    if (name[dot:] if dot > 0 else "") not in _MD_SUFFIXES:
        return False
    segments = line_text.split("`")
    return any(matched in segments[i] for i in range(1, len(segments), 2))


# A credential path built from segments instead of written out: joined onto the home directory
# (`path.join(os.homedir(), '.aws', 'credentials')`, or TypeScript's compiled
# `(0, path_1.join)((0, os_1.homedir)(), ...)`), concatenated to it
# (`os.homedir() + '/.aws/config'`) or interpolated (`${os.homedir()}/.npmrc`). The segments are
# read as the path they build -- the home directory as `~`, a string as written, anything else as a
# segment nothing can match -- and that path is matched like a written one, with the same
# suppressions. Python builds paths the same ways and is read by the AST scanner (ST-SENS-PATH-PY).
_JS_HOME_EXPR = (
    r"(?<![\w$.])(?:\(\s*0\s*,\s*)?"
    r"(?:require\(\s*['\"](?:node:)?os['\"]\s*\)\.|(?:[A-Za-z_$][\w$]{0,60}\.){0,2})"
    r"homedir\s*\)?\s*\(\s*\)"
    r"|(?<![\w$.])process\.env(?:\.(?:HOME|USERPROFILE)\b|\[\s*['\"](?:HOME|USERPROFILE)['\"]\s*\])"
    r"|(?<![\w$.])(?:[A-Za-z_$][\w$]{0,60}\.)?userInfo\(\s*\)\.homedir\b"
)
# `const home = os.homedir();` (or `process.env.HOME || os.homedir()`): the name stands for the
# home directory in the rest of the file.
_JS_HOME_VAR = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]{0,60})\s*=\s*(?:" + _JS_HOME_EXPR + r")"
    r"(?:\s*(?:\|\||\?\?)\s*(?:" + _JS_HOME_EXPR + r"|''|\"\")){0,3}\s*[;\n]"
)
_JS_JOIN_CALL = re.compile(
    r"(?<![\w$.])(?:\(\s*0\s*,\s*)?"
    r"(?:require\(\s*['\"](?:node:)?path['\"]\s*\)\.|(?:[A-Za-z_$][\w$]{0,60}\.){0,3})"
    r"(?:join|resolve)\s*\)?\s*\("
)
_JS_STRING = re.compile(
    r"""(['"])((?:(?!\1)[^\\\n]|\\.){0,300})\1|`((?:[^`\\$]|\\.|\$(?!\{)){0,300})`"""
)
_JS_PLUS_STRING = re.compile(r"""\s*\+\s*(['"])((?:(?!\1)[^\\\n]|\\.){0,300})\1""")
_JS_ARGS_LIMIT = 600
_UNKNOWN_SEGMENT = "\x00"
# Every home expression above, and a `~` string, contains one of these.
_JS_HOME_TOKENS = ("homedir", "HOME", "USERPROFILE", "'~", '"~', "`~")


def _js_string_end(text: str, i: int, stop: int) -> int | None:
    """Index just past the string literal opening at ``text[i]``, or None if it does not close."""
    quote = text[i]
    k = i + 1
    while k < stop:
        ch = text[k]
        if ch == "\\":
            k += 2
            continue
        if ch == quote:
            return k + 1
        if ch == "\n" and quote != "`":
            return None
        k += 1
    return None


def _js_call_args(text: str, open_at: int) -> tuple[list[str], int] | None:
    """The top-level arguments of the call whose ``(`` is at ``open_at`` and the index past its
    ``)``, or None when the call does not close within a few hundred characters."""
    args: list[str] = []
    depth, start, i = 0, open_at + 1, open_at + 1
    stop = min(len(text), open_at + _JS_ARGS_LIMIT)
    while i < stop:
        ch = text[i]
        if ch in "'\"`":
            end = _js_string_end(text, i, stop)
            if end is None:
                return None
            i = end
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                if ch != ")":
                    return None
                args.append(text[start:i])
                return [a.strip() for a in args if a.strip()], i + 1
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(text[start:i])
            start = i + 1
        i += 1
    return None


def _js_segment(arg: str, home: re.Pattern[str]) -> str:
    """A path segment as written: a string literal's text, ``~`` for the home directory (also
    `process.env.HOME || ''`), or a segment nothing matches."""
    literal = _JS_STRING.fullmatch(arg)
    if literal:
        return literal.group(2) if literal.group(1) else literal.group(3)
    if home.fullmatch(arg):
        return "~"
    inner = arg[1:-1].strip() if arg.startswith("(") and arg.endswith(")") else arg
    alternatives = [a.strip() for a in re.split(r"\|\||\?\?", inner)]
    if len(alternatives) > 1 and any(home.fullmatch(a) for a in alternatives) and all(
        home.fullmatch(a) or a in ("''", '""', "``") for a in alternatives
    ):
        return "~"
    return _UNKNOWN_SEGMENT


def _built_path(segments: list[str]) -> str:
    return re.sub(r"/{2,}", "/", "/".join(segments))


def joined_js_paths(f: IndexedFile) -> Iterator[tuple[int, int, str]]:
    """``(start, end, path)`` for each path a JS/TS file builds from the home directory or from
    joined string segments. ``start``/``end`` span the expression in the source."""
    text = f.text
    # Nearly every file names no home directory at all; a substring check skips them for free.
    if not any(token in text for token in _JS_HOME_TOKENS):
        return
    names = {m.group(1) for m in _JS_HOME_VAR.finditer(text)}
    home_alts = [_JS_HOME_EXPR] + [rf"(?<![\w$.]){re.escape(n)}(?![\w$])" for n in sorted(names)]
    home = re.compile("|".join(f"(?:{a})" for a in home_alts))
    # Rooted at the home directory, as `~/…` is: the first argument must be it (or a `~` string).
    # A base the scanner cannot name -- an SDK's own `getHomeDir()`, a parameter -- could be any
    # directory; a credential path written whole inside a segment is matched as written by the
    # first pass. Checked before the arguments are read, so ordinary joins cost nothing more.
    first_arg = re.compile(r"\s*(?:\(\s*)?(?:" + home.pattern + r"|['\"`]~)")
    for m in _JS_JOIN_CALL.finditer(text):
        if not first_arg.match(text, m.end()):
            continue
        call = _js_call_args(text, m.end() - 1)
        if call is None or len(call[0]) < 2:
            continue
        segments = [_js_segment(a, home) for a in call[0]]
        if not segments[0].startswith("~") or all(
            s in ("~", _UNKNOWN_SEGMENT) for s in segments
        ):
            continue
        yield m.start(), call[1], _built_path(segments)
    if "+" not in text and "${" not in text:
        return
    for m in home.finditer(text):
        end, built = m.end(), "~"
        for _ in range(9):
            plus = _JS_PLUS_STRING.match(text, end)
            if plus is None:
                break
            end, built = plus.end(), built + plus.group(2)
        if end > m.end():
            yield m.start(), end, built
    template = r"`\$\{\s*(?:" + home.pattern + r")\s*\}((?:[^`\\$]|\\.|\$(?!\{)){1,200})"
    for m in re.finditer(template, text):
        yield m.start(), m.end(), "~" + m.group(1)


# A dotenv file that ships INSIDE a released package. `.env` is where a project keeps its
# environment secrets, so in a working tree it is normal and gitignored — but a published
# artifact has no reason to carry one, and it gets there the same way the MCP publisher's
# tokens do: the packer captured the project root. Documentation variants are excluded;
# `.env.example` exists in order to be shipped.
_ENV_FILE_RE = re.compile(r"^\.env(\.[A-Za-z0-9_-]+)?$")
_ENV_TEMPLATE_RE = re.compile(
    r"^\.env\.(example|sample|template|dist|defaults?|tpl|schema)$", re.IGNORECASE
)
_ENV_ASSIGNMENT_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")
# Below this the file holds nothing worth calling a shipped configuration.
_MIN_ENV_BYTES = 8
# Variables front-end build tools expose to the browser by design (Vite, Next.js, Create React App,
# Vue CLI, Nuxt, Expo, Gatsby, SvelteKit).
_PUBLIC_BUILD_VAR_PREFIXES = (
    "VITE_", "NEXT_PUBLIC_", "REACT_APP_", "VUE_APP_", "NUXT_PUBLIC_", "EXPO_PUBLIC_", "GATSBY_",
    "PUBLIC_",
)
_ENV_KEYS_SHOWN = 8


def _env_evidence(f) -> Evidence | None:
    """Evidence for a shipped dotenv: the variable NAMES, never their values.

    The values are the entire reason this is a finding, so putting them in the snippet would make
    the report the leak. The names alone are what a reader needs — they say which credentials to
    go and rotate.
    """
    assignments: list[str] = []
    first_line = 1
    for n, raw in enumerate(f.text.splitlines(), start=1):
        m = _ENV_ASSIGNMENT_RE.match(raw)
        if not m or not m.group(2).strip():
            continue
        if not assignments:
            first_line = n
        assignments.append(m.group(1))
    if not assignments:
        return None
    # Build tools inline these into the page they build, for every visitor to read: a file of
    # them alone holds nothing private (a real token among them is still a separate secret finding).
    if all(name.upper().startswith(_PUBLIC_BUILD_VAR_PREFIXES) for name in assignments):
        return None
    shown = ", ".join(f"{k}=…" for k in assignments[:_ENV_KEYS_SHOWN])
    more = len(assignments) - _ENV_KEYS_SHOWN
    if more > 0:
        shown += f", and {more} more"
    return Evidence(
        file=f.relpath,
        line_start=first_line,
        line_end=first_line,
        snippet=f"{len(assignments)} variable(s), values withheld: {shown}",
    )


_WEAK = re.compile(r"\b(?:credentials|secrets)\b", re.IGNORECASE)
_SENS_WORD_EXAMPLES = 8


class SensitivePathScanner(Scanner):
    name = "sensitive_paths"
    rules = [
        RuleSpec(
            id="ST-SENS-PATH",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Sensitive path / secret-location reference",
            description=(
                "References to credential/secret locations were detected "
                "(e.g. ~/.ssh, ~/.aws, .aws/credentials, id_rsa, an .env file)."
            ),
            recommendation=(
                "Verify why the component references credential locations; reading these "
                "is a common precursor to secret exfiltration."
            ),
            capability=Capability.FILESYSTEM_READ,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            # A real reference is a path value (open("~/.ssh/id_rsa")); the same token inside a
            # .py string/comment is a detector's own pattern literal or a doc example (e.g. this
            # scanner defines `id_rsa`). Demote those so a security tool does not flag itself.
            code_context="strings_and_comments",
            pattern=_STRONG_PATHS,
        ),
        RuleSpec(
            id="ST-ENV-SHIPPED",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Environment file shipped in the released package",
            description=(
                "The published artifact contains a .env file. That is where a project keeps its "
                "environment secrets; it reaches a release when the packer captures the project "
                "root, the same way publisher credentials do."
            ),
            recommendation=(
                "If its values are real, rotate them, then exclude the file from the release (a "
                "`files` allowlist or .npmignore for npm, MANIFEST.in for a Python sdist - "
                ".gitignore alone excludes it from neither)."
            ),
            capability=None,
            threat_class=ThreatClass.EXPOSURE,
        ),
        # Listed for `rules list`; bare secret words are routed to needs_review.
        RuleSpec(
            id="ST-SENS-WORD",
            category=CATEGORY,
            severity=Severity.LOW,
            title="Ambiguous secret-related word",
            description="The bare word 'credentials' or 'secrets' was detected.",
            recommendation="Review whether this refers to an actual secret store.",
            capability=None,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        strong_rule = self.rules[0]
        needs_review: list[NeedsReview] = []

        # Strong, path-like credential locations (~/.ssh, id_rsa, .aws/credentials, …) are the
        # scored finding. The bare ".env" file token is NOT: legitimate apps load a local .env
        # constantly (dotenv), so a `.env` reference + network would otherwise flag almost every
        # web app as a credential-exfiltration path. It is surfaced for review instead.
        seen_ev: set[tuple[str, int, int]] = set()
        evidence: list[Evidence] = []
        guard_files: list[str] = []
        cited_files: list[str] = []
        unread_files: list[str] = []
        deny_spans: dict[str, list[tuple[int, int]]] = {}

        def in_deny_rule(f: IndexedFile, offset: int) -> bool:
            spans = deny_spans.get(f.relpath)
            if spans is None:
                spans = _sandbox_deny_spans(f.text) if "deny" in f.text else []
                deny_spans[f.relpath] = spans
            return _in_spans(spans, offset)

        for f, _m, ev in index.search(_STRONG_PATHS):
            key = (ev.file, ev.line_start, ev.line_end)
            if key in seen_ev:
                continue
            seen_ev.add(key)
            line_text = f.line_text(ev.line_start)
            if _is_guardlist_context(ev.file, line_text, _m.group(0)) or in_deny_rule(
                f, _m.start()
            ):
                if ev.file not in guard_files:
                    guard_files.append(ev.file)
                continue
            if _not_a_read(f, _m.start(), _m.group(0), line_text):
                if ev.file not in unread_files:
                    unread_files.append(ev.file)
                continue
            if _cited_in_markdown_code(ev.file, line_text, _m.group(0)):
                if ev.file not in cited_files:
                    cited_files.append(ev.file)
                continue
            evidence.append(ev)
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break

        # Second pass over the concat-folded view: catch a credential path an attacker split across
        # string literals (``"~/." + "ssh/id_rsa"``). The span is anchored back to the original
        # concatenation, so evidence still points at real source. The denylist/guardrail guard is
        # kept (a security tool may split a path in its own policy data); the other benign-shape
        # suppressions are for contiguous paths and do not apply to a spliced one.
        for f, start, end in concat_folded_spans(index, _STRONG_PATHS, suffixes=_JS_FAMILY):
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
            ev = f.evidence_for_span(start, end)
            key = (ev.file, ev.line_start, ev.line_end)
            if key in seen_ev:
                continue
            seen_ev.add(key)
            line_text = f.line_text(ev.line_start)
            if _is_guardlist_context(ev.file, line_text, f.text[start:end]) or in_deny_rule(
                f, start
            ):
                if ev.file not in guard_files:
                    guard_files.append(ev.file)
                continue
            evidence.append(ev)

        # Third pass: a credential path built from segments -- joined onto the home directory,
        # concatenated to it or interpolated (see joined_js_paths). It is the same path, so it is
        # judged like a written one: the denylist, sandbox-deny and not-a-read suppressions all
        # apply. A line the passes above already judged keeps their verdict.
        covered = {(file, n) for file, first, last in seen_ev for n in range(first, last + 1)}
        for f in index.select(suffixes=_JS_FAMILY):
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
            for start, end, built in joined_js_paths(f):
                m = _STRONG_PATHS.search(built)
                if m is None:
                    continue
                ev = f.evidence_for_span(start, end)
                lines = range(ev.line_start, ev.line_end + 1)
                if any((ev.file, n) in covered for n in lines):
                    continue
                covered.update((ev.file, n) for n in lines)
                line_text = f.line_text(ev.line_start)
                if _is_guardlist_context(ev.file, line_text, m.group(0)) or in_deny_rule(
                    f, start
                ):
                    if ev.file not in guard_files:
                        guard_files.append(ev.file)
                    continue
                if _not_a_read(f, start, m.group(0), line_text):
                    if ev.file not in unread_files:
                        unread_files.append(ev.file)
                    continue
                evidence.append(ev)

        if guard_files:
            shown = ", ".join(guard_files[:_SENS_WORD_EXAMPLES])
            more = len(guard_files) - _SENS_WORD_EXAMPLES
            if more > 0:
                shown += f", and {more} more"
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title=f"Credential path in a denylist/guardrail ({len(guard_files)})",
                    reason=(
                        f"A credential location is referenced in a denylist/guardrail context "
                        f"in {len(guard_files)} file(s) (a policy that PROTECTS the path, not "
                        f"access to it); flagged for review, not scored: {shown}."
                    ),
                    file=guard_files[0],
                )
            )

        if unread_files:
            shown = ", ".join(unread_files[:_SENS_WORD_EXAMPLES])
            more = len(unread_files) - _SENS_WORD_EXAMPLES
            if more > 0:
                shown += f", and {more} more"
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title=f"Credential path named but not read ({len(unread_files)})",
                    reason=(
                        f"A credential location appears in {len(unread_files)} file(s) as a "
                        f"directory being created, a key or kubeconfig handed to its own client "
                        f"(ssh -i, --kubeconfig), or words in a sentence; flagged for review, not "
                        f"scored: {shown}."
                    ),
                    file=unread_files[0],
                )
            )

        if cited_files:
            shown = ", ".join(cited_files[:_SENS_WORD_EXAMPLES])
            more = len(cited_files) - _SENS_WORD_EXAMPLES
            if more > 0:
                shown += f", and {more} more"
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title=f"Credential path cited in markdown example ({len(cited_files)})",
                    reason=(
                        f"A credential location appears inside a markdown inline-code example in "
                        f"{len(cited_files)} file(s) (a security doc describing the path, not "
                        f"accessing it); flagged for review, not scored: {shown}."
                    ),
                    file=cited_files[0],
                )
            )

        env_files: list[str] = []
        env_seen: set[str] = set()
        for _f, _m, ev in index.search(_ENV_FILE):
            if _suppresses_env(ev.file) or ev.file in env_seen:
                continue
            env_seen.add(ev.file)
            env_files.append(ev.file)
        if env_files:
            shown = ", ".join(env_files[:_SENS_WORD_EXAMPLES])
            more = len(env_files) - _SENS_WORD_EXAMPLES
            if more > 0:
                shown += f", and {more} more"
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title=f"Local .env file reference ({len(env_files)})",
                    reason=(
                        f"A bare '.env' file is referenced in {len(env_files)} file(s); "
                        f"commonly benign (dotenv config), so flagged for review not scored: "
                        f"{shown}."
                    ),
                    file=env_files[0],
                )
            )

        env_shipped: list[Evidence] = []
        for f in index.files:
            name = f.relpath.rsplit("/", 1)[-1]
            if not _ENV_FILE_RE.match(name) or _ENV_TEMPLATE_RE.match(name):
                continue
            if len(f.text.strip()) < _MIN_ENV_BYTES:
                continue
            ev = _env_evidence(f)
            if ev is not None:
                env_shipped.append(ev)

        evidence = evidence[:MAX_EVIDENCE_SCANNED]
        findings: list[Finding] = []
        if evidence:
            description = strong_rule.description
            if len(evidence) > 1:
                description = f"{description} ({len(evidence)} occurrence(s) shown as evidence)."
            findings.append(
                Finding(
                    id=strong_rule.id,
                    severity=strong_rule.severity,
                    category=strong_rule.category,
                    title=strong_rule.title,
                    description=description,
                    evidence=evidence,
                    recommendation=strong_rule.recommendation,
                )
            )

        if env_shipped:
            env_rule = next(r for r in self.rules if r.id == "ST-ENV-SHIPPED")
            findings.append(
                Finding(
                    id=env_rule.id,
                    severity=env_rule.severity,
                    category=env_rule.category,
                    title=env_rule.title,
                    description=env_rule.description,
                    evidence=env_shipped[:MAX_EVIDENCE_SCANNED],
                    recommendation=env_rule.recommendation,
                    threat_class=env_rule.threat_class,
                )
            )

        # Lines already covered by a strong path match should not also be flagged weak.
        strong_lines: set[tuple[str, int]] = set()
        for f in findings:
            for e in f.evidence:
                strong_lines.add((e.file, e.line_start))

        # Bare secret-related words are common in legitimate code/docs (a large SDK can
        # mention "credentials"/"secret" dozens of times). One row per hit floods the report,
        # so aggregate distinct hit files into a single informational entry.
        seen: set[tuple[str, int]] = set()
        files: list[str] = []
        words: set[str] = set()
        for _f, m, ev in index.search(_WEAK):
            key = (ev.file, ev.line_start)
            if key in strong_lines or key in seen:
                continue
            seen.add(key)
            words.add(m.group(0).lower())
            if ev.file not in files:
                files.append(ev.file)

        if seen:
            shown = ", ".join(files[:_SENS_WORD_EXAMPLES])
            more = len(files) - _SENS_WORD_EXAMPLES
            if more > 0:
                shown += f", and {more} more"
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title=f"Ambiguous secret-related words ({len(seen)})",
                    reason=(
                        f"{len(seen)} mention(s) of secret-related words "
                        f"({', '.join(sorted(words))}) across {len(files)} file(s) may refer "
                        f"to a secret store but are too ambiguous to confirm: {shown}."
                    ),
                    file=files[0] if files else None,
                )
            )
        return ScanResult(findings=findings, needs_review=needs_review)
