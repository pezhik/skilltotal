"""Where a component's dependencies come from, read from the files it ships.

A lockfile fixes the address every dependency is downloaded from, and a package-manager config
file fixes the registry. Both are read by the tool, not by a person: a ``package-lock.json`` entry
whose ``resolved`` address is moved to another host installs whatever that host serves under a
well-known package's name, and a shipped ``.npmrc`` or ``pip.conf`` does the same for every
package at once. Neither needs a line of code in the component.

* ``ST-DEP-FOREIGN-SOURCE`` (risky construct): a lockfile address on a host that is neither a
  public registry nor a registry the component's own ``.npmrc`` / ``.yarnrc`` declares; a shipped
  config that takes packages from a registry over plain ``http://`` or with certificate checks
  turned off. A private registry does exactly this, so the finding names the source and does not
  judge it. A redirect over https is listed for review only, and a scoped registry
  (``@corp:registry=``) is not reported at all.
* ``ST-DEP-REGISTRY-LOOKALIKE`` (malicious indicator): the host imitates a public registry
  (``registry.npmjs.org.example.invalid``, a name one or two letters off). An honest mirror has a
  name of its own.

Lockfiles are read line by line with a pattern (they are large); nothing is fetched or resolved.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Evidence, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    aggregated_review,
)
from skilltotal.typosquatting import _levenshtein

R_FOREIGN_SOURCE = "ST-DEP-FOREIGN-SOURCE"
R_REGISTRY_LOOKALIKE = "ST-DEP-REGISTRY-LOOKALIKE"

# The public registries, their documented aliases and the public mirrors lockfiles are commonly
# written against.
# Huawei Cloud's and Tencent Cloud's open mirrors joined 2026-11-23: NextChat's yarn.lock and
# trueAI's package-lock.json resolve through them, with every hash equal to npmjs's. A private
# registry (Azure Artifacts, Artifact Registry, a company proxy) stays reported: it is a source
# the component's author controls, which is what the finding names.
_CN_CLOUD_MIRRORS = frozenset({
    "mirrors.huaweicloud.com", "repo.huaweicloud.com", "mirrors.cloud.tencent.com",
    "mirrors.tencentyun.com",
})
_NPM_PUBLIC = frozenset({
    "registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com", "registry.npmmirror.com",
    "registry.npm.taobao.org", "r.cnpmjs.org", "npm.pkg.github.com", "npm.jsr.io",
}) | _CN_CLOUD_MIRRORS
_PYPI_PUBLIC = frozenset({
    "pypi.org", "pypi.python.org", "files.pythonhosted.org", "upload.pypi.org", "test.pypi.org",
    "download.pytorch.org", "pypi.tuna.tsinghua.edu.cn", "mirrors.aliyun.com",
}) | _CN_CLOUD_MIRRORS
# Git hosting: a lockfile address there is a git dependency (ST-NPM-GIT-DEP names it in
# package.json), not a registry tarball.
_GIT_HOSTS = frozenset({"github.com", "codeload.github.com", "gitlab.com", "bitbucket.org"})
# The names an imitation is measured against.
_NPM_IMITATED = ("registry.npmjs.org", "registry.yarnpkg.com")
_PYPI_IMITATED = ("pypi.org", "files.pythonhosted.org")

_LOCK_PATTERNS = {
    "package-lock.json": re.compile(r'"resolved"[ \t]*:[ \t]*"(https?://[^"\s]{1,2000})"'),
    "npm-shrinkwrap.json": re.compile(r'"resolved"[ \t]*:[ \t]*"(https?://[^"\s]{1,2000})"'),
    "yarn.lock": re.compile(r'^[ \t]+resolved[ \t]+"?(https?://[^"\s#]{1,2000})', re.MULTILINE),
    "pnpm-lock.yaml": re.compile(r"\btarball:[ \t]*[\"']?(https?://[^\s,}\"']{1,2000})"),
}
# Registry settings: npm and yarn 1 (`registry=`, `@scope:registry=`, `registry "..."`), yarn 2+
# (`npmRegistryServer:`).
_NPM_REGISTRY = re.compile(
    r"^[ \t]*[\"']?(?:(@[\w.-]{1,100}):)?(?:registry|npmRegistryServer)[\"']?[ \t]*[=: \t][ \t]*"
    r"[\"']?(https?://[^\s\"']{1,2000})",
    re.MULTILINE | re.IGNORECASE,
)
_NPM_TLS_OFF = re.compile(
    r"^[ \t]*(?:strict-ssl[ \t]*=[ \t]*[\"']?false|enableStrictSsl:[ \t]*false"
    r"|strict-ssl[ \t]+false)\b",
    re.MULTILINE | re.IGNORECASE,
)
# pip.conf / pip.ini, .pypirc and uv.toml: an index or upload address.
_PY_INDEX = re.compile(
    r"^[ \t]*(?:extra-index-url|index-url|find-links|repository|url|default-index)[ \t]*[=:]"
    r"[ \t]*\[?[ \t]*[\"']?(https?://[^\s\"',\]]{1,2000})",
    re.MULTILINE | re.IGNORECASE,
)
_PY_TLS_OFF = re.compile(
    r"^[ \t]*(?:trusted-host|allow-insecure-host)[ \t]*[=:][ \t]*\S", re.MULTILINE | re.IGNORECASE
)
_NPM_CONFIG_NAMES = frozenset({".npmrc", ".yarnrc", ".yarnrc.yml"})
_PY_CONFIG_NAMES = frozenset({"pip.conf", "pip.ini", ".pypirc", "uv.toml"})
_LOOPBACK = re.compile(r"^(?:localhost|127\.\d+\.\d+\.\d+|\[?::1\]?)$")
_COMMENT_LINE = re.compile(r"^[ \t]*[#;]")


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def imitates(host: str, originals: tuple[str, ...], public: frozenset[str]) -> bool:
    """Whether ``host`` passes itself off as one of ``originals``: it carries the whole name as
    its first labels or inside it (``registry.npmjs.org.example.invalid``,
    ``cdn.registry.npmjs.org.example.invalid``, ``registry.npmjs.org-cdn.example.invalid``), or
    differs from it by one or two characters. A public registry or mirror is never an imitation.
    """
    if not host or host in public:
        return False
    for original in originals:
        if host.endswith("." + original):
            continue  # a host under the registry's own domain
        if original in host:
            return True
        # A short name has honest neighbours two letters away; one letter is a typo of it.
        edits = 2 if len(original) >= 12 else 1
        if (abs(len(host) - len(original)) <= edits
                and _levenshtein(host, original, edits) is not None):
            return True
    return False


def _line_is_comment(f: IndexedFile, offset: int) -> bool:
    start = f.text.rfind("\n", 0, offset) + 1
    return bool(_COMMENT_LINE.match(f.text, start))


class DependencySourceScanner(Scanner):
    name = "dependency_source"
    rules = [
        RuleSpec(
            id=R_FOREIGN_SOURCE,
            category="supply_chain",
            severity=Severity.MEDIUM,
            title="Lockfile or package-manager config takes packages from a non-default source",
            description=(
                "A lockfile the component ships (package-lock.json, npm-shrinkwrap.json, "
                "yarn.lock, pnpm-lock.yaml) resolves a package from a host that is neither a "
                "public registry nor a registry the component's own .npmrc declares, or a "
                "shipped .npmrc / .yarnrc / pip.conf / .pypirc / uv.toml points the package "
                "manager at a registry over plain http or turns certificate checks off. The "
                "package manager downloads from that address without asking: the code that "
                "arrives is not the registry's release and is not part of this scan. A private "
                "registry looks the same, so this names the source and does not judge it."
            ),
            recommendation=(
                "Check that the host is a registry you trust and that the entry was written by "
                "the package manager, not edited by hand. Regenerate the lockfile against the "
                "public registry if it is not."
            ),
            capability=None,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
        RuleSpec(
            id=R_REGISTRY_LOOKALIKE,
            category="supply_chain",
            severity=Severity.HIGH,
            title="Dependency source imitates a public package registry",
            description=(
                "A lockfile entry or a shipped package-manager config names a host that is "
                "written to look like a public registry and is not one: the registry's name "
                "followed by another domain (`registry.npmjs.org.example.invalid`), or a name "
                "one or two characters away from it. Installing from the lockfile or with the "
                "config downloads packages from that host under the names of well-known ones."
            ),
            recommendation=(
                "Do not install with this lockfile or config. Regenerate the lockfile against "
                "the real registry and find out how the address got there."
            ),
            capability=None,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        foreign: list[Evidence] = []
        lookalike: list[Evidence] = []
        review: list[tuple[str, int | None]] = []
        configs = [f for f in index.files if f.name.lower() in _NPM_CONFIG_NAMES]
        declared = {
            _host(m.group(2)) for f in configs for m in _NPM_REGISTRY.finditer(f.text)
            if not _line_is_comment(f, m.start())
        }
        for f in index.files:
            name = f.name.lower()
            if name in _LOCK_PATTERNS:
                self._lockfile(f, _LOCK_PATTERNS[name], declared, foreign, lookalike)
            elif name in _NPM_CONFIG_NAMES:
                self._config(f, _NPM_REGISTRY, 2, _NPM_TLS_OFF, _NPM_PUBLIC, _NPM_IMITATED,
                             foreign, lookalike, review)
            elif name in _PY_CONFIG_NAMES:
                self._config(f, _PY_INDEX, 1, _PY_TLS_OFF, _PYPI_PUBLIC, _PYPI_IMITATED,
                             foreign, lookalike, review)
        findings = []
        if foreign:
            findings.append(_finding_from_rule(self.rules[0], foreign[:MAX_EVIDENCE_SCANNED]))
        if lookalike:
            findings.append(_finding_from_rule(self.rules[1], lookalike[:MAX_EVIDENCE_SCANNED]))
        needs_review: list[NeedsReview] = []
        if review:
            needs_review.append(aggregated_review(
                category="supply_chain",
                title="Shipped package-manager config sets a non-default registry",
                places=review,
                what="registry or index setting(s) in a shipped .npmrc / .yarnrc / pip.conf / "
                     ".pypirc / uv.toml point the package manager at a host that is not the "
                     "public registry",
                advice="That is what a private registry looks like. Confirm the host is one "
                       "you trust before installing with this config.",
            ))
        return ScanResult(findings=findings, needs_review=needs_review)

    @staticmethod
    def _lockfile(
        f: IndexedFile, pattern: re.Pattern[str], declared: set[str],
        foreign: list[Evidence], lookalike: list[Evidence],
    ) -> None:
        if "http" not in f.text:
            return
        # One piece of evidence per host: a lock written against one private registry has
        # thousands of entries that say the same thing.
        seen: set[str] = set()
        for m in pattern.finditer(f.text):
            host = _host(m.group(1))
            if not host or host in seen or host in _NPM_PUBLIC or host in _GIT_HOSTS:
                continue
            seen.add(host)
            if imitates(host, _NPM_IMITATED, _NPM_PUBLIC):
                lookalike.append(f.evidence_for_span(m.start(1), m.end(1)))
            elif host not in declared and not _LOOPBACK.match(host):
                foreign.append(f.evidence_for_span(m.start(1), m.end(1)))
            if len(seen) >= MAX_EVIDENCE_SCANNED:
                break

    @staticmethod
    def _config(
        f: IndexedFile, setting: re.Pattern[str], url_group: int, tls_off: re.Pattern[str],
        public: frozenset[str], imitated: tuple[str, ...],
        foreign: list[Evidence], lookalike: list[Evidence],
        review: list[tuple[str, int | None]],
    ) -> None:
        text = f.text
        insecure = [m for m in tls_off.finditer(text) if not _line_is_comment(f, m.start())]
        redirected = False
        for k, m in enumerate(setting.finditer(text)):
            if k >= MAX_EVIDENCE_SCANNED:
                break
            if _line_is_comment(f, m.start()):
                continue
            url = m.group(url_group)
            host = _host(url)
            if not host or host in public:
                continue
            ev = f.evidence_for_span(m.start(), m.end())
            if imitates(host, imitated, public):
                lookalike.append(ev)
                continue
            if _LOOPBACK.match(host):
                continue
            # `@corp:registry=`, or a yarn `npmScopes:` entry (indented under its scope): the
            # packages of one scope, which is how a private registry is set up.
            scoped = url_group == 2 and (
                m.group(1) or (f.name.lower().endswith(".yml") and m.group(0)[:1] in " \t")
            )
            if scoped:
                continue
            redirected = True
            if url.lower().startswith("http://") or insecure:
                foreign.append(ev)
            else:
                review.append((f.relpath, ev.line_start))
        # Certificate checks turned off: with a redirect it is part of that finding; alone it
        # still lets anyone on the network path answer for the registry.
        if insecure and (redirected or setting is _NPM_REGISTRY):
            m = insecure[0]
            foreign.append(f.evidence_for_span(m.start(), m.end()))
