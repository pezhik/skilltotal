"""Risk scoring engine.

Score = sum of severity weights of the findings that represent *risk* — i.e. malicious
indicators and risky constructs — capped at 100. Neutral CAPABILITY findings (can read the
filesystem / reach the network / run a shell) are shown but do NOT add to the score:
capability is not risk, so a legitimate-but-powerful component is not pushed into the red by
what it can do. The numeric score maps to a :class:`~skilltotal.models.RiskLevel` band.

Sensitive-data access (a credential-location reference or an embedded secret) combined with
network egress synthesizes a critical risky-construct finding — the genuine credential-
exfiltration pattern. Plain filesystem + network is intentionally NOT flagged: reading ordinary
files and using the network is a neutral capability, so a legitimate-but-powerful tool is not
painted as an exfiltration path.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import (
    Capability,
    Component,
    Evidence,
    Finding,
    RiskLevel,
    Severity,
    ThreatClass,
)
from skilltotal.scanners.sensitive_paths import _STRONG_PATHS

SCORE_CAP = 100

# Cloud instance-metadata endpoints. Reaching one IS itself a network call (a token is fetched
# over HTTP), not a local credential-file read — and it is the legitimate managed-identity auth
# path used by Azure/AWS/GCP SDKs. So a metadata-endpoint reference must NOT be counted as the
# "read a secret from disk" side of the exfiltration combo (that double-counts one fetch and
# mislabels normal cloud auth as a credential-exfiltration path). It still fires as its own
# sensitive-path finding (an SSRF / token-theft surface worth reviewing).
_CLOUD_METADATA_RE = re.compile(
    r"169\.254\.169\.254|metadata\.google\.internal|metadata\.google\b", re.IGNORECASE
)

# Only these threat classes contribute to the risk score; CAPABILITY is informational.
_SCORED_CLASSES = frozenset({ThreatClass.MALICIOUS_INDICATOR, ThreatClass.RISKY_CONSTRUCT})

COMBO_FINDING_ID = "ST-COMBO-EXFIL"
TRIFECTA_FINDING_ID = "ST-FLOW-TRIFECTA"
CONVERGENCE_FINDING_ID = "ST-CONVERGENCE"
INSTALL_DROPPER_FINDING_ID = "ST-INSTALL-DROPPER"
_INSTALL_HOOK_IDS = frozenset(
    {
        "ST-INSTALL-NPM", "ST-INSTALL-NPM-PREPARE", "ST-INSTALL-PY", "ST-INSTALL-GYP",
        "ST-INSTALL-NPM-REMOTE-EXEC",
    }
)
# Payloads that turn an install-time hook into a dropper: decode-and-execute, or credential access.
_DROPPER_PAYLOAD_IDS = frozenset(
    {
        "ST-OBF-DECODE-EXEC", "ST-OBF-DECODE-EXEC-PY", "ST-OBF-DECODE-EXEC-SH",
        "ST-SENS-PATH", "ST-SENS-PATH-PY",
    }
)
# Findings that represent reading a credential location. Plain filesystem access is deliberately
# NOT here — reading ordinary files is a capability, not a risk, so a normal "reads files + uses
# network" tool is not flagged as exfiltration. An embedded secret is not here either: a key the
# component ships is the author's exposure (ThreatClass.EXPOSURE), and calling it plus any network
# call a "credential-exfiltration path" described a theft that nothing in the code performs.
_SENSITIVE_DATA_IDS = frozenset({"ST-SENS-PATH", "ST-SENS-PATH-PY", "ST-SECRET-ENV"})
# A confirmed untrusted-instruction surface (the "untrusted content" axis of the trifecta).
_UNTRUSTED_CONTENT_IDS = frozenset({"ST-PROMPT-INJECTION"})

# Credential-location DOMAINS: which provider a sensitive-path reference belongs to. A package
# whose own identity IS that provider reads that provider's credentials as its documented function
# (botocore reads ~/.aws), so that specific access is not, by itself, an exfiltration signal. This
# is matched against the evidence snippet (the sensitive_paths scanner's own path alternation).
# A path built from segments names its directory as a segment of its own (`".aws"` in
# `join(home, ".aws", "credentials")`, `/ ".ssh" /`), so a directory name standing alone as a path
# segment counts too.
_SEGMENT = r"(?<![\w.-]){}(?![\w.-])"
_CREDENTIAL_DOMAINS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)~/\.aws|\.aws/credentials|" + _SEGMENT.format(r"\.aws")), "aws"),
    (re.compile(r"(?i)\.docker/config\.json|" + _SEGMENT.format(r"\.docker")), "docker"),
    (
        re.compile(
            r"(?i)~/\.config/gcloud|application_default_credentials\.json|"
            + _SEGMENT.format("gcloud")
        ),
        "gcp",
    ),
    (re.compile(r"(?i)~/\.azure|" + _SEGMENT.format(r"\.azure")), "azure"),
    (re.compile(r"(?i)~/\.kube|" + _SEGMENT.format(r"\.kube")), "kube"),
    (re.compile(r"(?i)\.git-credentials"), "git"),
    (re.compile(r"(?i)~/\.ssh|\bid_rsa\b|" + _SEGMENT.format(r"\.ssh")), "ssh"),
    (re.compile(r"(?i)" + _SEGMENT.format(r"\.npmrc")), "npm"),
    (re.compile(r"(?i)" + _SEGMENT.format(r"\.pypirc")), "pypi"),
)

# Known official SDK / client packages mapped to the credential domain(s) they exist to use.
# A CURATED allowlist keyed on the EXACT package name (never a substring — "python-aws-post"
# contains "aws" but is NOT the AWS SDK, so it must still fire). Reading its OWN provider's
# credentials is the package's documented purpose; off-domain access (an AWS SDK reading ~/.ssh)
# and embedded secrets are unaffected and still synthesize the exfil combo.
_SDK_PROVIDER_DOMAINS: dict[str, frozenset[str]] = {
    "botocore": frozenset({"aws"}), "boto3": frozenset({"aws"}), "boto": frozenset({"aws"}),
    # awscli's `eks update-kubeconfig` writes ~/.kube/config, and `codeartifact login` writes the
    # repository token into ~/.npmrc and ~/.pypirc.
    "awscli": frozenset({"aws", "kube", "npm", "pypi"}), "aiobotocore": frozenset({"aws"}),
    "aioboto3": frozenset({"aws"}), "s3transfer": frozenset({"aws"}),
    # docker's SSH transport (docker-over-ssh) reads ~/.ssh/config.
    "docker": frozenset({"docker", "ssh"}),
    "gcsfs": frozenset({"gcp"}), "google-cloud-storage": frozenset({"gcp"}),
    "google-auth": frozenset({"gcp"}), "google-cloud-core": frozenset({"gcp"}),
    "snowflake-connector-python": frozenset({"snowflake"}),
    "kubernetes": frozenset({"kube"}), "kubernetes-asyncio": frozenset({"kube"}),
    "paramiko": frozenset({"ssh"}), "asyncssh": frozenset({"ssh"}), "fabric": frozenset({"ssh"}),
    # git implementations legitimately read ~/.git-credentials AND ~/.ssh/config (git-over-ssh).
    "dulwich": frozenset({"git", "ssh"}), "gitpython": frozenset({"git", "ssh"}),
    "pygit2": frozenset({"git", "ssh"}),
    # Data / IO libraries with a first-class cloud-filesystem layer legitimately read cloud creds
    # (pyarrow.fs S3/GCS filesystems; s3fs/adlfs are the fsspec cloud backends).
    "pyarrow": frozenset({"aws", "gcp"}), "s3fs": frozenset({"aws"}),
    "adlfs": frozenset({"azure"}), "fsspec": frozenset({"aws", "gcp", "azure"}),
    # The Firebase CLI keeps its login as an Application Default Credentials file.
    "firebase-tools": frozenset({"gcp"}),
    # The Azure CLI keeps its configuration and login under ~/.azure, and Microsoft's identity and
    # common SDK packages read it there. Named exactly: the `azure-` prefix is anyone's to publish
    # under on PyPI, so a name that merely starts with it gets no allowance.
    "azure-cli": frozenset({"azure"}), "azure-cli-core": frozenset({"azure"}),
    "azure-cli-telemetry": frozenset({"azure"}), "azure-identity": frozenset({"azure"}),
    "azure-common": frozenset({"azure"}),
    # Package-index clients and upload tools read the index's upload configuration, ~/.pypirc:
    # twine and distlib (its PyPIRCFile), pip and pipenv (both ship distlib vendored), setuptools'
    # bundled distutils upload command, flit and pdm (publish).
    "twine": frozenset({"pypi"}), "distlib": frozenset({"pypi"}), "pip": frozenset({"pypi"}),
    "pipenv": frozenset({"pypi"}), "setuptools": frozenset({"pypi"}), "flit": frozenset({"pypi"}),
    "pdm": frozenset({"pypi"}),
}
# npm scopes belong to one organization, so a scope names its owner as surely as an exact name:
# only AWS publishes under @aws-sdk/ (the JavaScript SDK v3) and @smithy/ (the toolkit it is built
# on, whose shared-ini loader reads ~/.aws/credentials and ~/.aws/config).
_NPM_SCOPE_PROVIDER_DOMAINS: dict[str, frozenset[str]] = {
    "@aws-sdk/": frozenset({"aws"}),
    "@smithy/": frozenset({"aws"}),
}
# The sensitive-path findings a provider SDK's own-credential reads are taken out of.
_SENSITIVE_PATH_IDS = frozenset({"ST-SENS-PATH", "ST-SENS-PATH-PY"})


# Files that describe or configure rather than run: markup, prose, manifests, infrastructure
# templates, unit files. A credential path in them (a kubeconfig default in manifest.json, `ssh -i`
# in a systemd unit, a detection rule listing wallet paths) opens nothing, so it cannot be the read
# half of an exfiltration path. ST-SENS-PATH still reports it.
_DECLARATIVE_SUFFIXES = frozenset(
    {
        ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".xml", ".plist",
        ".properties", ".tf", ".tfvars", ".bicep", ".j2", ".tpl", ".service", ".example",
        ".html", ".htm", ".md", ".mdx", ".rst", ".txt", ".nft", ".eql", ".lucene", ".tmpl",
    }
)
_IGNORE_FILES = frozenset(
    {".gitignore", ".hgignore", ".dockerignore", ".npmignore", ".prettierignore", ".eslintignore",
     ".npmrc", ".yarnrc", ".pypirc", ".editorconfig"}
)


def _is_declarative_file(relpath: str) -> bool:
    name = relpath.rsplit("/", 1)[-1].lower()
    dot = name.rfind(".")
    return (
        name == "dockerfile"
        or name in _IGNORE_FILES
        or (dot > 0 and name[dot:] in _DECLARATIVE_SUFFIXES)
    )


# Writing a credential file is not reading one: a release script puts a token from the environment
# into `~/.npmrc`, and an installer appends to `~/.ssh/authorized_keys`. Neither can be the read
# half
# of an exfiltration path or the payload an install hook steals. ST-SENS-PATH still reports the line
# (writing `~/.ssh/config` is an SSH-config injection vector).
_WRITE_REDIRECT = re.compile(r"(?:>>?|\btee\s+(?:-a\s+)?)\s*[\"']?[^\s\"'|;&]*$")


def _is_write_target(snippet: str) -> bool:
    return any(
        _WRITE_REDIRECT.search(snippet[: m.start()]) for m in _STRONG_PATHS.finditer(snippet)
    )


# The language runtime a source file runs in, for pairing the two halves of ST-COMBO-EXFIL. A
# credential read and the request that sends it off must be code one program runs, or the data
# has no path between them. A Go server that loads its own host key and a Python developer script
# that talks to localhost are two programs, and the engine has no evidence that anything flows
# from one to the other. Files outside this table (shell scripts, Makefiles, markdown read by an
# agent, JSON/YAML config, a file with no suffix) are glue that starts or steers the programs
# around it, so they pair with any runtime: `cp ~/.ssh/id_rsa /tmp/k && node send.js` is one flow.
_RUNTIME_BY_SUFFIX: dict[str, str] = {
    **dict.fromkeys((".py", ".pyw", ".pyi", ".pth"), "python"),
    **dict.fromkeys(
        (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte"), "js"
    ),
    ".go": "go",
    ".rs": "rust",
    **dict.fromkeys((".java", ".kt", ".kts", ".scala", ".groovy"), "jvm"),
    **dict.fromkeys((".cs", ".fs", ".vb"), "dotnet"),
    ".rb": "ruby",
    ".php": "php",
    **dict.fromkeys((".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".m", ".mm"), "native"),
    ".swift": "swift",
    ".dart": "dart",
    **dict.fromkeys((".pl", ".pm"), "perl"),
    ".lua": "lua",
    **dict.fromkeys((".ex", ".exs"), "elixir"),
}


def _runtime(relpath: str) -> str | None:
    name = relpath.rsplit("/", 1)[-1].lower()
    dot = name.rfind(".")
    return _RUNTIME_BY_SUFFIX.get(name[dot:]) if dot > 0 else None


def _same_runtime(sens: Evidence, net: Evidence) -> bool:
    """True if a credential reference and a network call could be one program's flow."""
    a, b = _runtime(sens.file), _runtime(net.file)
    return a is None or b is None or a == b


# Programs in two runtimes are still one flow when the code links them:
# - a staging file: the file holding the credential reference writes a path that the file holding
#   the egress reads (`open("/tmp/.k", "w")` in Python, `fs.readFileSync("/tmp/.k")` in Node.js);
# - a launch: one of the two files starts the other by its file name
#   (`subprocess.run(["node", "send.js"])`, `spawn("python3", ["collect.py"])`).
# A path both sides only read (a shared config file), or a file name mentioned without starting
# it, shows no data passing from one program to the other, so it is not a link.
_STRING_LITERAL = re.compile(r"""(?P<q>["'`])(?P<s>(?:\\.|(?!(?P=q))[^\\\n])*)(?P=q)""")
_PATH_SHAPE = re.compile(r"[^\s\"'`]{4,200}")
_BARE_EXTENSION = re.compile(r"\.[A-Za-z0-9]{1,6}")
_COMMENT_LINE = re.compile(r"\s*(?:#|//|/\*|\*)")
# `NAME = "<path>"` (or `NAME = Path("<path>")`): the path is used through the name.
_PATH_BINDING = re.compile(
    r"^\s*(?:(?:export\s+)?(?:const|let|var)\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?="
    r"(?!=)"
)
_NAME_USE = re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]*")
_FILE_WRITE = re.compile(
    r"\bopen\s*\([^\n]*?,\s*(?:mode\s*=\s*)?[\"'][rbt]*[wax]"
    r"|\.write_(?:text|bytes)\s*\(|\bshutil\.(?:copy\w*|move)\s*\(|\bos\.(?:rename|replace)\s*\("
    r"|\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|copyFile"
    r"|copyFileSync|outputFile|outputFileSync)\s*\("
    r"|\bos\.(?:WriteFile|Create|OpenFile)\s*\(|\bioutil\.WriteFile\s*\("
    r"|\bfs::(?:write|copy)\s*\(|\bFile::create\s*\(|\bFile\.write\s*\(|\bfile_put_contents\s*\("
    r"|\bFiles\.(?:write|writeString|copy)\s*\(|\bnew\s+(?:FileWriter|FileOutputStream)\s*\("
)
_FILE_READ = re.compile(
    r"\bopen\s*\(|\.read_(?:text|bytes)\s*\("
    r"|\b(?:readFile|readFileSync|createReadStream)\s*\("
    r"|\bos\.(?:ReadFile|Open)\s*\(|\bioutil\.ReadFile\s*\("
    r"|\bfs::read(?:_to_string)?\s*\(|\bFile::open\s*\(|\bFile\.(?:read|open)\s*\("
    r"|\bfile_get_contents\s*\(|\bFiles\.read\w*\s*\("
)
# Starting another program: Python, Node.js, Go, Rust and JVM process APIs.
_LAUNCH = re.compile(
    r"\bsubprocess\.(?:run|call|check_call|check_output|getoutput|getstatusoutput)\s*\("
    r"|\bPopen\s*\(|\bos\.(?:system|popen|exec\w*|spawn\w*)\s*\("
    r"|\bcreate_subprocess_\w+\s*\(|\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync"
    r"|fork|execa)\s*\(|\bexec\.Command(?:Context)?\s*\(|\bCommand::new\s*\("
    r"|\bProcessBuilder\s*\(|\bRuntime\.getRuntime\(\)\.exec\s*\("
)
# How many lines below a launch call its arguments (the started file's name) may run.
_LAUNCH_ARG_LINES = 3


def _line_end_after(text: str, offset: int, lines: int) -> int:
    """The offset just past the line ``lines`` lines below the one holding ``offset``."""
    end = offset
    for _ in range(lines + 1):
        newline = text.find("\n", end)
        if newline < 0:
            return len(text)
        end = newline + 1
    return end


def _path_access(f: IndexedFile, access: re.Pattern[str]) -> dict[str, int]:
    """File-path literals this file writes (or reads), per ``access``: path -> offset of the line
    that does it. A literal counts on its own line, and through the name it is bound to."""
    text = f.text
    found: dict[str, int] = {}
    bound: dict[str, tuple[str, int]] = {}  # name -> (path, end of the line that binds it)
    for lit in _STRING_LITERAL.finditer(text):
        path = lit.group("s")
        if (
            path in found
            or not _PATH_SHAPE.fullmatch(path)
            or "://" in path
            or _BARE_EXTENSION.fullmatch(path)
            or not ("/" in path or "\\" in path or "." in path)
        ):
            continue
        first, last = f.line_bounds(lit.start(), lit.end())
        line = text[first:last]
        if _COMMENT_LINE.match(line):
            continue
        if access.search(line):
            found[path] = first
            continue
        binding = _PATH_BINDING.match(line)
        if binding is not None:
            bound.setdefault(binding.group("name"), (path, last))
    if bound:
        # One pass over the lines that write (or read): which bound names they use.
        for m in access.finditer(text):
            first, last = f.line_bounds(m.start(), m.end())
            line = text[first:last]
            if _COMMENT_LINE.match(line):
                continue
            for name in _NAME_USE.findall(line):
                if name in bound and first >= bound[name][1]:
                    found.setdefault(bound[name][0], first)
    return found


def _launch_of(f: IndexedFile, target: str) -> int | None:
    """Offset of a call in ``f`` that starts the file ``target`` by its name, or None."""
    name = re.compile(r"(?:^|[\s/\\])" + re.escape(target.rsplit("/", 1)[-1]) + r"(?:$|\s)")
    text = f.text
    for m in _LAUNCH.finditer(text):
        first, _last = f.line_bounds(m.start(), m.end())
        if _COMMENT_LINE.match(text[first : m.start()] + " "):
            continue
        arguments = _call_arguments(
            text, m.end() - 1, _line_end_after(text, m.start(), _LAUNCH_ARG_LINES)
        )
        if any(name.search(lit.group("s")) for lit in _STRING_LITERAL.finditer(arguments)):
            return m.start()
    return None


def _call_arguments(text: str, start: int, limit: int) -> str:
    """The text between the first ``(`` at or after ``start`` and its matching ``)`` (or
    ``limit``): a launch call's own arguments, not the code after it."""
    open_at = text.find("(", start, limit)
    if open_at < 0:
        return ""
    depth = 0
    for i in range(open_at, limit):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_at + 1 : i]
    return text[open_at + 1 : limit]


class _RuntimeLinks:
    """Evidence that the program in one file hands data to, or starts, the program in another."""

    def __init__(self, index: FileIndex):
        self._files = {f.relpath: f for f in index.files}
        self._writes: dict[str, dict[str, int]] = {}
        self._reads: dict[str, dict[str, int]] = {}
        self._links: dict[tuple[str, str], list[Evidence]] = {}

    def between(self, sens_file: str, net_file: str) -> list[Evidence]:
        """The lines linking a credential reference in ``sens_file`` to egress in ``net_file``:
        a path the first writes and the second reads, or one starting the other. Empty if none."""
        key = (sens_file, net_file)
        if key not in self._links:
            self._links[key] = self._find(sens_file, net_file)
        return self._links[key]

    def _find(self, sens_file: str, net_file: str) -> list[Evidence]:
        sens, net = self._files.get(sens_file), self._files.get(net_file)
        if sens is None or net is None:
            return []
        if sens_file not in self._writes:
            self._writes[sens_file] = _path_access(sens, _FILE_WRITE)
        if net_file not in self._reads:
            self._reads[net_file] = _path_access(net, _FILE_READ)
        reads = self._reads[net_file]
        for path, written_at in self._writes[sens_file].items():
            if path in reads:
                read_at = reads[path]
                return [sens.evidence_for_span(written_at, written_at + 1),
                        net.evidence_for_span(read_at, read_at + 1)]
        for parent, child in ((sens, net_file), (net, sens_file)):
            at = _launch_of(parent, child)
            if at is not None:
                return [parent.evidence_for_span(at, at + 1)]
        return []


def _credential_domain(snippet: str) -> str | None:
    """The provider domain a sensitive-path evidence snippet refers to, or None."""
    for pat, dom in _CREDENTIAL_DOMAINS:
        if pat.search(snippet):
            return dom
    return None


def _package_base_name(component: Component) -> str:
    """The base package name, without a version suffix. A PyPI sdist's ``Component.name`` is the
    ``package-version`` dir (``botocore-1.43.42``), so match on the clean source spec
    (``pypi:botocore``) when present, else strip a trailing ``-<version>`` from the name.

    A scoped npm name keeps its scope: ``npm:@google/gemini-cli@0.63.0`` -> ``@google/gemini-cli``
    (splitting on the first ``@`` returned the empty string for every scoped package)."""
    src = (component.source or "").strip().lower()
    for prefix in ("pypi:", "npm:"):
        if src.startswith(prefix):
            spec = src[len(prefix):]
            scope = "@" if spec.startswith("@") else ""
            return scope + re.split(r"[@=<>!~ ]", spec[len(scope):], maxsplit=1)[0].strip()
    name = (component.name or "").strip().lower()
    return re.sub(r"-\d+(?:\.\d+)*.*$", "", name)


def _package_provider_domains(component: Component | None) -> frozenset[str]:
    """Credential domains this package legitimately accesses as its own documented function.

    Only an exact curated name or an npm scope counts: each has one owner. A name prefix does not
    (anyone can publish a PyPI name that starts with ``azure-``).

    Only a name the registry gives counts (an ``npm:`` or ``pypi:`` source). A git repository, an
    archive or a folder names itself in its own manifest, which its author writes: a credential
    stealer could call itself botocore there and borrow botocore's allowance.
    """
    if component is None:
        return frozenset()
    if not (component.source or "").strip().lower().startswith(("pypi:", "npm:")):
        return frozenset()
    name = _package_base_name(component)
    if name in _SDK_PROVIDER_DOMAINS:
        return _SDK_PROVIDER_DOMAINS[name]
    for scope, domains in _NPM_SCOPE_PROVIDER_DOMAINS.items():
        if name.startswith(scope):
            return domains
    return frozenset()


def is_own_provider_read(finding_id: str, evidence: Evidence, component: Component | None) -> bool:
    """True for a credential path that belongs to the provider whose own SDK this package is.

    botocore reading ~/.aws and the AWS JavaScript SDK reading ~/.aws/credentials do what they
    exist to do, whether the path is written out or joined onto the home directory. Only an exact
    curated package name or an owned npm scope counts; the same read in any other package, and
    another provider's credentials read by an SDK (an AWS SDK reading ~/.ssh), are unaffected.
    """
    if finding_id not in _SENSITIVE_PATH_IDS:
        return False
    domains = _package_provider_domains(component)
    return bool(domains) and _credential_domain(evidence.snippet) in domains


def _dedupe(evidence: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, int, int]] = set()
    out: list[Evidence] = []
    for e in evidence:
        key = (e.file, e.line_start, e.line_end)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


# A component with a malicious indicator scores at least this (the HIGH band). A single indicator
# weighs only its severity, so one HIGH worm hook scored 20/100 (LOW) under a "malicious" verdict:
# a reader of the score, a --fail-on-score gate or a catalog sort took it for a safe package.
MALICIOUS_SCORE_FLOOR = 50


def compute_score(findings: list[Finding]) -> int:
    """Sum severity weights of risk-bearing findings (malicious + risky), capped at SCORE_CAP;
    at least MALICIOUS_SCORE_FLOOR when any finding is a malicious indicator.

    CAPABILITY findings are informational and contribute 0 — capability is not risk.
    """
    total = sum(f.severity.weight for f in findings if f.threat_class in _SCORED_CLASSES)
    if any(f.threat_class == ThreatClass.MALICIOUS_INDICATOR for f in findings):
        total = max(total, MALICIOUS_SCORE_FLOOR)
    return min(total, SCORE_CAP)


def risk_level(score: int) -> RiskLevel:
    return RiskLevel.from_score(score)


def exfiltration_finding(
    findings: list[Finding],
    capabilities: dict[Capability, list[Evidence]],
    component: Component | None = None,
    index: FileIndex | None = None,
) -> Finding | None:
    """Synthesize a critical risky-construct finding for a credential-exfiltration path.

    Fires only when the component BOTH accesses sensitive data (a credential-location reference
    or an embedded secret — see ``_SENSITIVE_DATA_IDS``) AND can reach the network. This is the
    genuinely risky combination (read a secret, send it off-host); plain filesystem + network is
    a neutral capability and is intentionally not flagged here. Evidence is drawn from the
    contributing findings/capabilities so the "no finding without evidence" invariant holds.

    A provider SDK reading its OWN provider's credentials (``botocore`` -> ``~/.aws``) is that
    package's documented function, not exfiltration, so a sensitive-path evidence whose domain
    matches the package's provider (``component`` identity, see ``_SDK_PROVIDER_DOMAINS``) is
    excluded. Off-domain access (an AWS SDK reading ``~/.ssh``), a non-SDK package reading any
    credential path, and embedded secrets (``ST-SECRET-EMBEDDED`` has no path domain) all keep
    firing, so recall for a genuine credential-stealer is preserved.

    The two halves must also be able to belong to one program: a credential reference in one
    language runtime does not pair with egress that exists only in another (``_same_runtime``),
    unless the code links the two programs (``_RuntimeLinks``: a staging file one writes and the
    other reads, or one starting the other), which needs the file ``index``.
    """
    provider_domains = _package_provider_domains(component)
    sens_evidence: list[Evidence] = [
        e
        for f in findings
        if f.id in _SENSITIVE_DATA_IDS
        for e in f.evidence
        if not _CLOUD_METADATA_RE.search(e.snippet)  # metadata fetch is network, not a secret read
        and not (f.id == "ST-SENS-PATH" and _is_declarative_file(e.file))
        and not (f.id == "ST-SENS-PATH" and _is_write_target(e.snippet))
        and not (
            provider_domains
            and f.id in ("ST-SENS-PATH", "ST-SENS-PATH-PY")
            and _credential_domain(e.snippet) in provider_domains
        )
    ]
    net_evidence = capabilities.get(Capability.NETWORK_EGRESS, [])
    # Keep only the pairs one program could form (see ``_same_runtime``), or two programs the
    # code links (see ``_RuntimeLinks``); the linking lines join the evidence.
    links = _RuntimeLinks(index) if index is not None else None

    def link(s: Evidence, n: Evidence) -> list[Evidence]:
        if links is None or _same_runtime(s, n):
            return []
        return links.between(s.file, n.file)

    def paired(s: Evidence, n: Evidence) -> bool:
        return _same_runtime(s, n) or bool(link(s, n))

    paired_sens = [s for s in sens_evidence if any(paired(s, n) for n in net_evidence)]
    net_evidence = [n for n in net_evidence if any(paired(s, n) for s in paired_sens)]
    sens_evidence = paired_sens
    link_evidence = [e for s in sens_evidence for n in net_evidence for e in link(s, n)]

    if not sens_evidence or not net_evidence:
        return None

    evidence = (
        _dedupe(sens_evidence)[:3] + _dedupe(link_evidence)[:2] + _dedupe(net_evidence)[:3]
    )
    description = (
        "The component references credential/secret locations and can also send data over "
        "the network. Together these form a credential-exfiltration path."
    )
    if link_evidence:
        description += (
            " The two halves are programs in different languages; the evidence includes the "
            "line that links them (a file one writes and the other reads, or one starting the "
            "other)."
        )
    return Finding(
        id=COMBO_FINDING_ID,
        severity=Severity.CRITICAL,
        category="exfiltration_path",
        title="Sensitive-data access combined with network egress",
        description=description,
        evidence=evidence,
        recommendation=(
            "Verify that secrets read from disk are never transmitted off-host without "
            "explicit, auditable user consent."
        ),
        threat_class=ThreatClass.RISKY_CONSTRUCT,
    )


def trifecta_finding(
    findings: list[Finding],
    capabilities: dict[Capability, list[Evidence]],
    *,
    combo_fired: bool,
) -> Finding | None:
    """Synthesize the "lethal trifecta" exfiltration flow for an AI component.

    Fires when ALL THREE coincide: an untrusted-instruction surface (a confirmed
    prompt-injection finding), the ability to read files, and network egress — i.e. the
    component is exposed to instructions an attacker controls AND has the file-access + egress
    means to act on them. This is the combination that turns an injected instruction into data
    exfiltration.

    Gated to stay false-positive-free and low-noise: it requires an *actual* prompt-injection
    finding (not mere capability), and it is suppressed when the credential-specific
    ``ST-COMBO-EXFIL`` already fired (that stronger finding covers the same exfil concern).
    """
    if combo_fired:
        return None
    injection = [e for f in findings if f.id in _UNTRUSTED_CONTENT_IDS for e in f.evidence]
    fs_read = capabilities.get(Capability.FILESYSTEM_READ, [])
    net = capabilities.get(Capability.NETWORK_EGRESS, [])
    if not injection or not fs_read or not net:
        return None

    evidence = _dedupe(injection)[:2] + _dedupe(fs_read)[:2] + _dedupe(net)[:2]
    return Finding(
        id=TRIFECTA_FINDING_ID,
        severity=Severity.HIGH,
        category="exfiltration_path",
        title="Untrusted-instruction surface with file access and network egress",
        description=(
            "The component is exposed to untrusted instructions (a prompt-injection surface) and "
            "also can read files and send data over the network. Together these are the 'lethal "
            "trifecta' an attacker needs to turn an injected instruction into data exfiltration."
        ),
        evidence=evidence,
        recommendation=(
            "Remove the injectable instruction surface, or constrain the component so untrusted "
            "input cannot drive file reads and outbound network requests."
        ),
        threat_class=ThreatClass.RISKY_CONSTRUCT,
    )


def install_dropper_finding(findings: list[Finding]) -> Finding | None:
    """Synthesize the install-time dropper pattern: an install/build hook paired with a payload.

    Fires when the component runs code at install time (`ST-INSTALL-*`) AND contains a
    decode-and-execute payload or accesses credential locations — the exact shape behind recent
    npm/PyPI supply-chain compromises (a postinstall hook that drops/runs an obfuscated second
    stage or steals secrets). FP-safe: the install hook alone is a neutral capability; this only
    fires when it co-occurs with an already-suspicious payload.
    """
    hooks = [f for f in findings if f.id in _INSTALL_HOOK_IDS]
    payload_evidence = [
        e
        for f in findings
        if f.id in _DROPPER_PAYLOAD_IDS
        for e in f.evidence
        if not (
            f.id == "ST-SENS-PATH"
            and (_is_declarative_file(e.file) or _is_write_target(e.snippet))
        )
    ]
    if not hooks or not payload_evidence:
        return None
    evidence = (
        _dedupe([e for f in hooks for e in f.evidence])[:2] + _dedupe(payload_evidence)[:3]
    )
    return Finding(
        id=INSTALL_DROPPER_FINDING_ID,
        severity=Severity.HIGH,
        category="install_time_execution",
        title="Install-time hook paired with a dropper payload",
        description=(
            "The component executes code at install time (a package lifecycle / build hook) and "
            "also contains a decode-and-execute payload or accesses credential locations. This is "
            "the install-time dropper pattern behind recent supply-chain compromises."
        ),
        evidence=evidence,
        recommendation=(
            "Inspect the install/build hook and the payload it runs; do not install until the "
            "install-time behavior is understood and trusted."
        ),
        threat_class=ThreatClass.RISKY_CONSTRUCT,
    )


def convergence_finding(findings: list[Finding]) -> Finding | None:
    """Synthesize an elevation finding when multiple distinct malicious indicators co-occur.

    Real malicious components stack deception and payload (e.g. an obfuscated dropper *and* a
    prompt injection); the convergence of two or more distinct malicious-indicator rules in one
    component sharply raises confidence that it is malicious. False-positive-free by construction:
    a benign component has zero malicious indicators, so this can never fire on one.

    Must run after ``_assign_threat_classes`` so each finding's ``threat_class`` is final.
    """
    malicious = [f for f in findings if f.threat_class is ThreatClass.MALICIOUS_INDICATOR]
    distinct_ids = {f.id for f in malicious}
    if len(distinct_ids) < 2:
        return None
    evidence = _dedupe([f.evidence[0] for f in malicious if f.evidence])[:6]
    titles = sorted({f.title for f in malicious})
    return Finding(
        id=CONVERGENCE_FINDING_ID,
        severity=Severity.HIGH,
        category="malware_convergence",
        title="Multiple malicious indicators in one component",
        description=(
            f"{len(distinct_ids)} distinct malicious indicators co-occur in this component "
            f"({', '.join(titles[:4])}). Real malware stacks deception with a payload, so their "
            "convergence sharply raises confidence the component is malicious."
        ),
        evidence=evidence,
        recommendation=(
            "Treat the component as malicious: do not install it, and review each indicator above."
        ),
        threat_class=ThreatClass.RISKY_CONSTRUCT,
    )
