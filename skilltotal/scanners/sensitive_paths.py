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

import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    alternation,
)

CATEGORY = "sensitive_path"

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
    r"~/\.config/solana",
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
_LIST_ITEM = r"""(?:["'][^"'\n]*["']\s*(?:\.\w+\(\))?|0[oxb]?[0-9a-fA-F]+|\d+)"""
_BARE_LIST_ELEMENT = re.compile(
    r"^\s*(?:\|\s*)?[\[(]?\s*"
    + r"(?:" + _LIST_ITEM + r"\s*[,:]\s*)*" + _LIST_ITEM
    + r"\s*[\])]?\s*(?:=>\s*\w+\s*)?,?\s*$"
)
# A trailing `// ssh private key` or `# comment` after a list element is still just a list element.
_TRAILING_COMMENT = re.compile(r"\s+(?://|#).*$")
# A bare regex-literal list element: a slash-delimited regex (optional flags) on its own line,
# e.g. `/id_rsa/,`, `/credentials/i,`, `/\.pem$/,`. A regex literal is a PATTERN that matches
# against paths, never a path being accessed — so a credential token inside one is a detector's
# denylist entry (as in a `SENSITIVE_PATHS = [ /id_rsa/, ... ]` array), not exfiltration.
_BARE_REGEX_ELEMENT = re.compile(r"^\s*/(?:\[[^\]\n]*\]|[^/\\\n\[]|\\.)+/[gimsuvy]*\s*,?\s*$")


def _guard_segment(relpath: str) -> bool:
    # Tokenize each path segment on `._-` so guard code is recognized whether it's a directory
    # (policies/) or a filename (net_guard.rs, path_guard.rs, denylist.go).
    for part in relpath.lower().split("/"):
        if any(tok in _GUARD_PATH_SEGMENTS for tok in re.split(r"[._-]", part)):
            return True
    return False


def _is_guardlist_context(relpath: str, line_text: str) -> bool:
    """True if a sensitive-path match is a defensive denylist/guardrail mention, not access."""
    bare = _TRAILING_COMMENT.sub("", line_text)
    return (
        _guard_segment(relpath)
        or bool(_GUARD_KEYWORDS.search(line_text))
        or bool(_BARE_LIST_ELEMENT.match(bare))
        or bool(_BARE_REGEX_ELEMENT.match(bare))
    )


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
# `match = "**/.ssh/*"` in a policy template is a pattern for paths, not a path.
_POLICY_GLOB_BEFORE = re.compile(r"\*\*/$")
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
_PROSE_MIN_CJK = 8


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


def _not_a_read(f, match: re.Match[str], line_text: str) -> bool:
    """True if the line names a credential location without reading it (see above)."""
    col = match.start() - f.text.rfind("\n", 0, match.start()) - 1
    before = line_text[: max(0, col)]
    if _BARE_DIR_MATCH.match(match.group(0)) and _DIR_SETUP_BEFORE.search(before):
        return True
    if _SSH_IDENTITY_BEFORE.search(before) or _SSH_KEY_VARIABLE_BEFORE.search(before):
        return True
    if _POLICY_GLOB_BEFORE.search(before) or _EXISTS_TEST_BEFORE.search(before):
        return True
    name = f.relpath.rsplit("/", 1)[-1].lower()
    config_suffix = name if name.startswith(".") and "." not in name[1:] else f.suffix
    if config_suffix in _CONFIG_SUFFIXES and _CONFIG_COMMENT_LINE.match(line_text):
        return True
    if f.string_is_executed(match.start()):
        return False
    span = f.string_span_at(match.start())
    if span is not None:
        # Judge the part of the literal on this line: a blog post kept in one template literal
        # contains tables and code, yet each sentence in it is still a sentence.
        line_start = match.start() - col
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
    return f.in_rendered_markup_text(match.start())


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
                "Treat every value in it as exposed and rotate it, then exclude the file from the "
                "release (a `files` allowlist or .npmignore for npm, MANIFEST.in for a Python "
                "sdist — .gitignore alone excludes it from neither)."
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
        for f, _m, ev in index.search(_STRONG_PATHS):
            key = (ev.file, ev.line_start, ev.line_end)
            if key in seen_ev:
                continue
            seen_ev.add(key)
            line_text = f.line_text(ev.line_start)
            if _is_guardlist_context(ev.file, line_text):
                if ev.file not in guard_files:
                    guard_files.append(ev.file)
                continue
            if _not_a_read(f, _m, line_text):
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
                        f"directory being created, a key passed to the SSH "
                        f"client as its identity, or words in a sentence; flagged for review, not "
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
