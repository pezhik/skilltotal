"""Post-exploitation tactics: remote access, OS persistence, masquerading and beacons.

What a compromised package does once it runs is a short list that recurs across campaigns: it
opens a way in for someone else (a reverse tunnel to the local SSH server, a planted SSH key, a
reverse shell, a tunnel client started with the attacker's token, remote login switched on), it
makes sure it starts again after a reboot (a LaunchAgent, a cron `@reboot` line, a scheduled task,
a Run key, the Startup folder, a shell profile), it names what it leaves behind after the operating
system's vendor so nobody looks twice, and it calls home with a description of the host.

Each tactic here is one rule whose signals are a family of shapes. A signal is a literal anchor
plus what must stand next to it (a write next to a LaunchAgents path, `/create` and `/sc onstart`
next to `schtasks`), so a path or a command name that is only mentioned does not fire. On its own a
signal is a risky construct: provisioning scripts plant keys, daemons install LaunchAgents,
dotfiles append to `.zshrc`. Masquerading is the exception, a malicious indicator by itself: a
third-party package has no honest reason to label its LaunchAgent `com.apple.*` or its scheduled
task `MicrosoftEdgeUpdate...`. Two tactics together, one of them a way in or a call home, are the
ST-POSTEX-CHAIN combination (skilltotal.scoring).

Detection reads JavaScript/TypeScript, Python, shell, PowerShell and batch files. A match in a
comment or docstring is documentation, not behavior; the engine also sets aside printed commands
(`echo "..."`), documentation, tests and examples.
"""

from __future__ import annotations

import bisect
import ipaddress
import re
from dataclasses import dataclass

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    TACTIC_COMMAND_AND_CONTROL,
    TACTIC_DEFENSE_EVASION,
    TACTIC_PERSISTENCE,
    TACTIC_REMOTE_ACCESS,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
)

R_REMOTE_ACCESS = "ST-POSTEX-REMOTE-ACCESS"
R_PERSIST = "ST-POSTEX-PERSIST"
R_MASQUERADE = "ST-POSTEX-MASQUERADE"
R_BEACON = "ST-POSTEX-BEACON"

_JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
_PY = (".py", ".pyw")
_SH = (".sh", ".bash", ".zsh")
_PS = (".ps1", ".psm1")
_BAT = (".bat", ".cmd")
_CODE_SUFFIXES = (*_JS, *_PY, *_SH, *_PS, *_BAT)

_I = re.IGNORECASE
# Argument separators: a space in a command line, or `", "` between the elements of an argv array
# (`", ["` after the program name of `spawn("code", ["tunnel", ...])`).
_SEP = r"[\"'`\s,\[]{1,6}"

# Code that writes a file: a write call, a shell redirect into a path, or open() for writing.
_WRITE = (
    r"\b(?:appendFile|writeFile|createWriteStream|copyFile|outputFile|"
    r"write_text|write_bytes|Add-Content|Set-Content|Out-File|Copy-Item|New-Item|plistlib\.dump"
    r"|shutil\.copy\w*)"
    r"|\b(?:cp|mv|copy|move|tee)\s+[-\w\"'$~/%]"
    r"|(?<![=>\-<])>>?\s*[\"'$~/%]"
    r"|\.write\("
    r"|\bopen\([^)\n]{0,200}?[\"'][wa]b?\+?[\"']"
)
# A name written out in full: no variable, placeholder or format field (`$u`, `%1`, `{}`, `<user>`).
_LITERAL_NAME = r"[^\s\"'`,{}$%<>()\[\]]+"
_LAUNCHCTL_LOAD =rf"\blaunchctl{_SEP}(?:load|bootstrap|enable)\b"
# Appending to a file (a shell profile is appended to; a rewrite of it is a dotfiles manager).
_APPEND = (
    r"\bappendFile|>>|\btee\s+-a\b|\bAdd-Content\b|\bopen\([^)\n]{0,200}?[\"']a\+?[\"']"
    r"|[\"']a\+?[\"']\s*\)|\bmode\s*=\s*[\"']a"
)
# Names of the operating system's own vendor and processes, as a third party should never label
# a scheduled task, a Run value or a Startup item.
_OS_NAME = (
    r"(?:Microsoft|Windows|OneDrive|SysMon|svchost|WinDefend|SecurityHealth|Defender|csrss"
    r"|lsass|winlogon|RuntimeBroker)"
)


@dataclass(frozen=True)
class _Signal:
    """One shape of a tactic: an anchor, what must stand within ``window`` characters of it (every
    pattern of ``near``), and what the same file must contain somewhere (``requires``)."""

    rule: str
    anchor: re.Pattern[str]
    near: tuple[re.Pattern[str], ...] = ()
    window: int = 400
    requires: re.Pattern[str] | None = None
    suffixes: tuple[str, ...] = _CODE_SUFFIXES
    # A LaunchAgent path under /System/Library is Apple's own; only another place is masquerading.
    not_after_system: bool = False
    # Lower-case words one of which every anchor match contains: a file holding none of them is
    # not searched with the anchor's regex at all (most files hold none).
    keywords: tuple[str, ...] = ()


def _c(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


_SIGNALS: tuple[_Signal, ...] = (
    # --- Remote access -------------------------------------------------------------------------
    # A reverse tunnel whose far end is this machine's SSH (22), RDP (3389) or VNC (5900) port on
    # loopback: whoever holds the server's end gets a login prompt here. `-R 80:localhost:3000`
    # (localhost.run, serveo) publishes a web port and does not match.
    _Signal(R_REMOTE_ACCESS, _c(
        r"(?<![\w-])-R(?:\s*|[\"'`]\s*,\s*[\"'`]|[\"'`]\s+[\"'`]?)(?:[\w.*-]+:)?\d+:"
        r"(?:localhost|127\.0\.0\.1|\[::1\]):(?:22|3389|5900)(?!\d)"
        r"|\bRemoteForward\s+(?:[\w.*-]+:)?\d+\s+(?:localhost|127\.0\.0\.1|\[::1\]):"
        r"(?:22|3389|5900)(?!\d)"),
        keywords=("-r", "remoteforward")),
    # A literal public key written into authorized_keys: whoever holds the private half logs in.
    # Adding the user's own key (from an environment variable or a file) has no literal key.
    _Signal(R_REMOTE_ACCESS, _c(r"\bauthorized_keys2?\b"), near=(_c(_WRITE),), window=600,
            requires=_c(r"(?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp(?:256|384|521)"
                        r"|sk-ssh-ed25519@openssh\.com)\s+AAAA[0-9A-Za-z+/]{16,}"),
            keywords=("authorized_keys",)),
    # Reverse shells: an interactive shell bound to a socket.
    _Signal(R_REMOTE_ACCESS, _c(
        r"\b(?:ba|z|k)?sh\s+-i\b[^\n]{0,120}?/dev/(?:tcp|udp)/"
        r"|/dev/(?:tcp|udp)/[^\s\"'`]{3,120}\s*0>&1"
        r"|\b(?:nc|ncat|netcat)(?:\.exe)?\b[^\n]{0,120}?\s-[a-z]*[ec]\s+[\"']?"
        r"(?:/bin/)?(?:ba|z)?sh\b"
        r"|\b(?:ba)?sh\s+-i\b[^\n]{0,80}?\|\s*(?:nc|ncat|netcat)\b"
        r"|\bsocat\b[^\n]{0,200}?\b(?:exec|system):[\"']?[^\s\"',]{0,40}?(?:sh|cmd|powershell)\b",
        _I),
        keywords=("/dev/tcp", "/dev/udp", "nc", "netcat", "socat")),
    _Signal(R_REMOTE_ACCESS, _c(r"\bos\.dup2\(\s*(?!sys\.)[\w.]+\.fileno\(\)\s*,\s*[012]\s*\)"),
            requires=_c(r"\bsocket\.(?:socket|create_connection)\("),
            keywords=("dup2",)),
    _Signal(R_REMOTE_ACCESS,
            _c(r"\bspawn\(\s*[\"'`](?:/bin/)?(?:ba|z|da)?sh[\"'`]|\bspawn\(\s*[\"'`](?:cmd|powershell)"
               r"(?:\.exe)?[\"'`]"),
            near=(_c(r"\.pipe\(\s*[\w$.]+\.stdin\s*\)"), _c(r"\.stdout\.pipe\(")), window=1500,
            requires=_c(r"\bnet\.(?:connect|createConnection|Socket)\b|\bnew\s+net\.Socket\b"),
            keywords=("spawn",)),
    _Signal(R_REMOTE_ACCESS, _c(r"\bNet\.Sockets\.TCPClient\s*\(", _I),
            near=(_c(r"\bGetStream\(\)", _I), _c(r"\b(?:iex|Invoke-Expression)\b", _I)),
            window=2000,
            keywords=("tcpclient",)),
    # Tunnel clients started with a credential written into the code, or pointed at this
    # machine's SSH/RDP port. `ngrok http 3000` with the user's own configured token does not
    # match; neither does a token read from the environment.
    _Signal(R_REMOTE_ACCESS, _c(
        rf"\bngrok\b[^\n]{{0,200}}?\bauth_?token\b{_SEP}(?:=\s*)?[\"'`]?[A-Za-z0-9_]{{24,}}"
        rf"|\bngrok\b[^\n]{{0,40}}?\b(?:set_auth_token|authtoken)\s*\(\s*[\"'`][A-Za-z0-9_]{{24,}}"
        rf"|\bauthtoken\s*[:=]\s*[\"'`][A-Za-z0-9_]{{24,}}[\"'`][^\n]{{0,200}}?\bngrok\b"
        rf"|\bngrok\b{_SEP}tcp{_SEP}(?:22|3389|5900)\b"
        rf"|\bcloudflared\b[^\n]{{0,200}}?--token(?:{_SEP}|=)eyJ[A-Za-z0-9_-]{{20,}}"
        rf"|\bcloudflared\b{_SEP}service{_SEP}install{_SEP}eyJ[A-Za-z0-9_-]{{20,}}"
        rf"|\btailscale\b{_SEP}up\b[^\n]{{0,200}}?--auth-?key(?:{_SEP}|=)[\"']?tskey-"
        rf"|\bchisel(?:\.exe)?{_SEP}client\b[^\n]{{0,300}}?[\"'`\s,]R:"
        rf"|\bfrpc(?:\.exe)?{_SEP}(?:-c|--config)\b"
        # VS Code's own remote tunnel and Microsoft dev tunnels hand the machine to whoever signs
        # in with the account it registers under. Sub-commands that only inspect or remove one
        # do not match.
        rf"|\bcode(?:-insiders)?(?:\.cmd|\.exe)?{_SEP}tunnel\b(?!{_SEP}(?:user|status|kill"
        rf"|prune|rename|unregister|restart|help|--help|-h)\b)"
        rf"|\bdevtunnel(?:\.exe)?{_SEP}host\b"),
        keywords=("ngrok", "cloudflared", "tailscale", "chisel", "frpc", "tunnel")),
    # Remote login or remote desktop switched on, a hidden admin account added.
    _Signal(R_REMOTE_ACCESS, _c(
        rf"\bsystemsetup{_SEP}-setremotelogin{_SEP}on\b"
        r"|\bkickstart\b[^\n]{0,200}?-activate\b"
        r"|\bAdd-WindowsCapability\b[^\n]{0,200}?OpenSSH\.Server"
        r"|\bSet-Service\b[^\n]{0,60}?\bsshd\b[^\n]{0,80}?-StartupType\s+(?:Automatic|'Automatic'"
        r"|\"Automatic\")"
        r"|\bfDenyTSConnections\W{0,4}(?:\s*/t\s+REG_DWORD)?\s*(?:/d|-Value)\s+[\"']?0\b"
        r"|\bfDenyTSConnections[\"']\s*,\s*0\s*,\s*(?:winreg\.)?REG_DWORD\s*,\s*0\b"
        # An account whose name (and password) the code spells out. User-management code in
        # configuration tools (salt, ansible) fills them in from a parameter: `/Users/{}`,
        # `net user %1`, `$name`.
        rf"|\bnet(?:\.exe)?{_SEP}user{_SEP}{_LITERAL_NAME}{_SEP}{_LITERAL_NAME}{_SEP}/add\b"
        rf"|\bnet(?:\.exe)?{_SEP}localgroup{_SEP}administrators{_SEP}{_LITERAL_NAME}{_SEP}/add\b"
        rf"|\bdscl{_SEP}\.{_SEP}-create{_SEP}/Users/{_LITERAL_NAME}(?:[\"'`\s,]|$)"
        rf"|\bsysadminctl\b[^\n]{{0,40}}?-addUser{_SEP}{_LITERAL_NAME}(?:[\"'`\s,]|$)",
        _I | re.MULTILINE),
        keywords=("systemsetup", "kickstart", "openssh.server", "sshd", "fdenytsconnections",
                  "net", "dscl", "sysadminctl")),

    # --- Persistence ---------------------------------------------------------------------------
    _Signal(R_PERSIST, _c(r"\bLaunch(?:Agents|Daemons)\b"),
            near=(_c(rf"{_WRITE}|{_LAUNCHCTL_LOAD}"),),
            keywords=("launchagents", "launchdaemons")),
    _Signal(R_PERSIST, _c(r"@reboot\b"), near=(_c(r"\bcrontab\b|/etc/cron|/var/spool/cron"),),
            window=300,
            keywords=("@reboot",)),
    # A crontab piped in (`... | crontab -`), or `crontab -` run with the table on its stdin.
    _Signal(R_PERSIST, _c(r"\|\s*crontab\s+-(?=[\s\"'`);]|$)"
                          r"|[\"'`]crontab[\"'`]\s*,\s*[\"'`]-[\"'`]", re.MULTILINE),
            keywords=("crontab",)),
    _Signal(R_PERSIST, _c(r"/etc/cron\.(?:d|hourly|daily|weekly|monthly)/|/var/spool/cron/"),
            near=(_c(_WRITE),), window=300,
            keywords=("/etc/cron", "/var/spool/cron")),
    _Signal(R_PERSIST,
            _c(r"\bsystemd[\\/]{1,2}(?:system|user)[\\/]{1,2}[\w@.-]*\.(?:service|timer)\b"
               r"|\.config[\\/]{1,2}systemd[\\/]{1,2}user\b"),
            near=(_c(_WRITE),),
            requires=_c(rf"\bsystemctl{_SEP}(?:--user{_SEP})?enable\b"),
            keywords=("systemd",)),
    _Signal(R_PERSIST, _c(r"\bschtasks(?:\.exe)?\b", _I),
            near=(_c(r"/create\b", _I), _c(r"/sc\W{1,6}(?:onstart|onlogon)\b", _I)),
            keywords=("schtasks",)),
    _Signal(R_PERSIST, _c(r"\bRegister-ScheduledTask\b", _I),
            requires=_c(r"\bNew-ScheduledTaskTrigger\b[^\n]{0,80}?-At(?:LogOn|Startup)\b", _I),
            keywords=("register-scheduledtask",)),
    _Signal(R_PERSIST, _c(r"\bCurrentVersion(?:\\{1,4}|/)Run(?:Once)?(?![\w])", _I),
            near=(_c(r"\breg(?:\.exe)?[\"'`\s,]{1,6}add\b|\bSet-ItemProperty\b|\bNew-ItemProperty\b"
                     r"|\bSetValue(?:Ex)?\b|\.set\(|\bputValue\b|\bREG_SZ\b", _I),),
            window=300,
            keywords=("currentversion",)),
    _Signal(R_PERSIST,
            _c(r"\bPrograms(?:[\\/]{1,4}|[\"'`]\s*,\s*[\"'`])Startup\b|\bshell:startup\b", _I),
            near=(_c(_WRITE),),
            keywords=("startup",)),
    _Signal(R_PERSIST,
            _c(r"(?<=[/\"'`\\\s])\.(?:bashrc|bash_profile|bash_login|zshrc|zprofile|zshenv|zlogin"
               r"|profile)\b|\$PROFILE\b|\bconfig\.fish\b"),
            near=(_c(_APPEND),), window=250,
            keywords=(
                "bashrc", "bash_profile", "bash_login", "zshrc", "zprofile", "zshenv", "zlogin",
                "profile", "config.fish",
            )),

    # --- Masquerading (a persistence artifact named after the OS vendor) -----------------------
    _Signal(R_MASQUERADE,
            _c(r"\bLaunch(?:Agents|Daemons)(?:[\\/]{1,2}|[\"'`]\s*,\s*[\"'`])com\.(?:apple|microsoft)"
               r"\.[\w.-]+"),
            near=(_c(rf"{_WRITE}|{_LAUNCHCTL_LOAD}"),), not_after_system=True,
            keywords=("launchagents", "launchdaemons")),
    _Signal(R_MASQUERADE,
            _c(r"<key>Label</key>\s*<string>\s*com\.(?:apple|microsoft)\.[\w.-]+"),
            near=(_c(r"\bLaunch(?:Agents|Daemons)\b"), _c(rf"{_WRITE}|{_LAUNCHCTL_LOAD}")),
            window=800,
            keywords=("<key>label</key>",)),
    _Signal(R_MASQUERADE, _c(r"\bschtasks(?:\.exe)?\b", _I),
            near=(_c(r"/create\b", _I), _c(rf"/tn\W{{1,6}}\\?{_OS_NAME}", _I)),
            keywords=("schtasks",)),
    _Signal(R_MASQUERADE, _c(r"\bRegister-ScheduledTask\b", _I),
            near=(_c(rf"-TaskName\W{{1,6}}\\?{_OS_NAME}", _I),), window=300,
            keywords=("register-scheduledtask",)),
    _Signal(R_MASQUERADE, _c(r"\bCurrentVersion(?:\\{1,4}|/)Run(?:Once)?(?![\w])", _I),
            near=(_c(rf"(?:/v|-Name|SetValueEx\(\s*[\w.]+\s*,|\.set\(|putValue\()\W{{0,4}}{_OS_NAME}",
                     _I),),
            window=300,
            keywords=("currentversion",)),
    _Signal(R_MASQUERADE,
            _c(r"\bStartup(?:[\\/]{1,4}|[\"'`]\s*,\s*[\"'`])(?:svchost|sysmon|winlogon|csrss|lsass"
               r"|explorer|WindowsUpdate|MicrosoftEdge\w*|OneDrive\w*|SecurityHealth\w*)"
               r"\.(?:cmd|bat|exe|vbs|lnk|ps1|js)\b", _I),
            near=(_c(_WRITE),),
            keywords=("startup",)),
)


# --- Command and control: a description of the host sent off it ---------------------------------
# Host facts a beacon reports. A recon cluster is two kinds of them within _CLUSTER characters, one
# of which an ordinary program has no use for in a request: the NAMES of the environment's secret
# variables, or the machine's public IP looked up from a what-is-my-IP service. A crash reporter
# that sends the host name and user name does neither.
_RECON = {
    "hostname": _c(r"\bos\.hostname\(\)|\bsocket\.gethostname\(\)|\bplatform\.node\(\)"
                   r"|\$env:COMPUTERNAME\b|%COMPUTERNAME%|\$\(hostname\)|`hostname`", _I),
    "username": _c(r"\buserInfo\(\)\.username\b|\bgetpass\.getuser\(\)|\bos\.getlogin\(\)"
                   r"|\$env:USERNAME\b|%USERNAME%|\$\(whoami\)|`whoami`"),
    "secret_env_names": _c(
        r"(?:Object\.(?:keys|entries)\(\s*process\.env\s*\)|\bos\.environ\b|\bGet-ChildItem\s+env:"
        r"|\bprintenv\b)[^\n]{0,200}?(?:KEY|TOKEN|SECRET|PASS)\w*\|", _I),
    "public_ip": _c(r"\b(?:ifconfig\.me|api\.ipify\.org|ipinfo\.io|icanhazip\.com"
                    r"|checkip\.amazonaws\.com|ipecho\.net|ident\.me|ip-api\.com)\b", _I),
}
_TELLING = frozenset({"secret_env_names", "public_ip"})
# A beacon needs one of the telling facts: a file with no word of them is not searched.
_RECON_KEYWORDS = (
    "process.env", "environ", "env:", "printenv", "ifconfig.me", "ipify", "ipinfo", "icanhazip",
    "checkip", "ipecho", "ident.me", "ip-api", "://",
)
_CLUSTER = 600
_SINK_WINDOW = 1500
_SINK = _c(
    r"\bhttps?\.request\(|\bfetch\(|\baxios\b|\bgot\(|\bXMLHttpRequest\b|\bsendBeacon\(|\bWebSocket\("
    r"|\bnet\.(?:connect|createConnection)\(|\brequests\.(?:post|put|get)\(|\burlopen\("
    r"|\bhttpx\.|\bhttp\.client\b|\bsocket\.create_connection\(|\.sendall?\("
    r"|\bcurl\b|\bwget\b|\bInvoke-WebRequest\b|\bInvoke-RestMethod\b|\bNet\.WebClient\b", _I)
# A URL whose host is a literal IPv4 address with an explicit port.
_RAW_IP_URL = _c(r"\b(?:https?|wss?|tcp)://(\d{1,3}(?:\.\d{1,3}){3}):\d{2,5}\b", _I)


def _code_files(index: FileIndex, suffixes: tuple[str, ...] = _CODE_SUFFIXES) -> list[IndexedFile]:
    return [
        f for f in index.files
        if f.suffix in suffixes or (f.suffix == "" and f.is_shell_like)
    ]


def _in_comment(f: IndexedFile, offset: int) -> bool:
    """True if ``offset`` is in a comment (or a Python docstring): documentation, not behavior."""
    if f.suffix in _PY:
        return f.in_comment(offset) or f.in_python_docstring(offset)
    if f.suffix in _JS:
        return f.in_c_comment(offset)
    if f.is_shell_like:
        return f.in_shell_comment(offset)
    if f.suffix in _BAT:
        line = f.line_text(f.line_of_offset(offset)).lstrip().lower()
        return line.startswith(("rem ", "::", "@rem "))
    return False


# A list of command lines written as data: at least this many of its string elements are whole
# command lines (they hold a space). A security tool keeps its signatures that way; an argv array
# holds one token per element and at most one command line (`["bash", "-c", "..."]`).
_PATTERN_LIST_MIN = 3


def _skip_space_back(text: str, i: int) -> int:
    while i >= 0 and text[i].isspace():
        i -= 1
    return i


def _skip_space(text: str, i: int) -> int:
    while i < len(text) and text[i].isspace():
        i += 1
    return i


def _first_in_code(f: IndexedFile, pattern: re.Pattern[str], start: int = 0,
                   end: int | None = None) -> re.Match[str] | None:
    """The first match of ``pattern`` in ``f.text[start:end]`` that is not in a comment."""
    for m in pattern.finditer(f.text, start, len(f.text) if end is None else end):
        if not _in_comment(f, m.start()):
            return m
    return None


# Anchors (and recon facts) looked at per file and signal: a file padded with thousands of
# `LaunchAgents` mentions does not get thousands of checks.
_MAX_ANCHORS = 2000


class _FileScan:
    """One file's lookups, each done once however many anchors ask: where each neighbour pattern
    matches in code, what each required pattern's first match is, and which string literals are
    elements of a pattern list. Asking each anchor's window afresh was quadratic on padded input."""

    def __init__(self, f: IndexedFile) -> None:
        self.f = f
        self._near: dict[re.Pattern[str], list[int]] = {}
        self._required: dict[re.Pattern[str], re.Match[str] | None] = {}
        self._lists: dict[int, bool] = {}

    def near(self, pattern: re.Pattern[str], lo: int, hi: int) -> bool:
        """True if ``pattern`` matches in code (not a comment) starting within ``[lo, hi)``."""
        starts = self._near.get(pattern)
        if starts is None:
            starts = self._near[pattern] = [m.start() for m in pattern.finditer(self.f.text)]
        k = bisect.bisect_left(starts, lo)
        while k < len(starts) and starts[k] < hi:
            if not _in_comment(self.f, starts[k]):
                return True
            k += 1
        return False

    def required(self, pattern: re.Pattern[str]) -> re.Match[str] | None:
        if pattern not in self._required:
            self._required[pattern] = _first_in_code(self.f, pattern)
        return self._required[pattern]

    def in_pattern_list(self, offset: int) -> bool:
        """True if ``offset`` is in a string element of a bracketed collection made only of
        string literals, of which at least ``_PATTERN_LIST_MIN`` are whole command lines: a list
        of patterns or examples (`SIGNATURES = ["bash -i >& /dev/tcp/...", ...]`), not a command
        the code runs. A collection is walked once; its answer is kept for every element."""
        f, text = self.f, self.f.text
        span = f.string_span_at(offset)
        if span is None:
            return False
        if span[0] in self._lists:
            return self._lists[span[0]]
        elements = [span]
        verdict = False
        start, end = span[0], span[1]
        while True:  # back to the opening bracket
            j = _skip_space_back(text, start - 1)
            if j < 0 or (text[j] not in "[({" and text[j] not in ",:"):
                break
            if text[j] in "[({":
                verdict = True
                break
            k = _skip_space_back(text, j - 1)
            prev = f.string_span_at(k) if k >= 0 else None
            if prev is None or prev[1] - 1 != k:
                break
            elements.append(prev)
            start = prev[0]
        if verdict:
            verdict = False
            while True:  # on to the closing bracket
                j = _skip_space(text, end)
                if j >= len(text) or (text[j] not in "])}" and text[j] not in ",:"):
                    break
                k = _skip_space(text, j + 1)
                if text[j] in "])}" or (k < len(text) and text[k] in "])}"):
                    verdict = True
                    break
                nxt = f.string_span_at(k)
                if nxt is None or nxt[0] != k:
                    break
                elements.append(nxt)
                end = nxt[1]
        if verdict:
            lines = sum(1 for a, b in elements if " " in text[a:b].strip("\"'`rbfuRBFU").strip())
            verdict = lines >= _PATTERN_LIST_MIN
        for a, _b in elements:
            self._lists[a] = verdict
        return verdict


def _signal_evidence(scan: _FileScan, signal: _Signal) -> list[Evidence]:
    f = scan.f
    evidence: list[Evidence] = []
    required: re.Match[str] | None = None
    for n, m in enumerate(signal.anchor.finditer(f.text)):
        if n >= _MAX_ANCHORS:
            break
        if _in_comment(f, m.start()) or scan.in_pattern_list(m.start()):
            continue
        if signal.not_after_system and "System" in f.text[max(0, m.start() - 16) : m.start()]:
            continue
        lo = max(0, m.start() - signal.window)
        hi = min(len(f.text), m.end() + signal.window)
        if not all(scan.near(near, lo, hi) for near in signal.near):
            continue
        if signal.requires is not None:
            required = scan.required(signal.requires)
            if required is None:
                return []
        evidence.append(f.evidence_for_span(m.start(), m.end()))
        if len(evidence) >= MAX_EVIDENCE_SCANNED:
            break
    if evidence and required is not None:
        evidence.append(f.evidence_for_span(required.start(), required.end()))
    return evidence


def _is_reserved(address: str) -> bool:
    """True for an address that does not leave the machine or the local network."""
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        return True
    # Documentation ranges (TEST-NET) are kept: code only writes them as a stand-in for a server.
    if any(ip in ipaddress.IPv4Network(n) for n in ("192.0.2.0/24", "198.51.100.0/24",
                                                    "203.0.113.0/24")):
        return False
    return not ip.is_global


def _beacon_evidence(f: IndexedFile) -> list[Evidence]:
    """A recon cluster with a network sink near it, or host facts sent to a raw-IP URL."""
    hits: list[tuple[int, int, str]] = []
    for kind, pattern in _RECON.items():
        for n, m in enumerate(pattern.finditer(f.text)):
            if n >= _MAX_ANCHORS:
                break
            if not _in_comment(f, m.start()):
                hits.append((m.start(), m.end(), kind))
    if not hits:
        return []
    hits.sort()
    evidence: list[Evidence] = []
    for i, (start, end, kind) in enumerate(hits):
        kinds = {kind}
        last = end
        for s2, e2, k2 in hits[i + 1 :]:
            if s2 - start > _CLUSTER:
                break
            kinds.add(k2)
            last = max(last, e2)
        lo, hi = max(0, start - _SINK_WINDOW), min(len(f.text), last + _SINK_WINDOW)
        telling = len(kinds) >= 2 and bool(kinds & _TELLING)
        raw_ip = None
        if not telling:
            raw_ip = next(
                (u for u in _RAW_IP_URL.finditer(f.text, lo, hi)
                 if not _is_reserved(u.group(1)) and not _in_comment(f, u.start())),
                None,
            )
        if not telling and raw_ip is None:
            continue
        sink = _first_in_code(f, _SINK, lo, hi)
        if sink is None:
            continue
        evidence.append(f.evidence_for_span(start, last))
        evidence.append(f.evidence_for_span(sink.start(), sink.end()))
        if raw_ip is not None:
            evidence.append(f.evidence_for_span(raw_ip.start(), raw_ip.end()))
        break  # one beacon per file is enough evidence
    return evidence


_RULES = [
    RuleSpec(
        id=R_REMOTE_ACCESS,
        category="remote_access",
        severity=Severity.HIGH,
        title="Code opens a way into the machine for someone else",
        description=(
            "The code gives a remote party a way in: a reverse SSH tunnel whose far end is this "
            "machine's SSH, RDP or VNC port; a hardcoded public key appended to authorized_keys, "
            "which grants whoever holds the private key a login; a shell bound to a network "
            "socket; a tunnel client (ngrok, cloudflared, tailscale, chisel, frp, VS Code or dev "
            "tunnels) started with a credential written into the code or pointed at the SSH port; "
            "remote login or remote desktop switched on; or a new local or admin account."
        ),
        recommendation=(
            "Confirm who the access is for and that the user asked for it. A package that sets "
            "up remote access on install or import should not be installed; check machines that "
            "ran it for the key, account, tunnel or service it added."
        ),
        capability=Capability.SHELL_EXECUTION,
        threat_class=ThreatClass.RISKY_CONSTRUCT,
        code_context="comments_and_docstrings",
        tactic=TACTIC_REMOTE_ACCESS,
    ),
    RuleSpec(
        id=R_PERSIST,
        category="persistence",
        severity=Severity.MEDIUM,
        title="Code makes something start again on its own after a reboot or login",
        description=(
            "The code installs an operating-system autostart: a LaunchAgent or LaunchDaemon "
            "plist, a cron @reboot line or a crontab it pipes in, an enabled systemd unit, a "
            "scheduled task that runs at startup or logon, a Run or RunOnce registry value, a "
            "file in the Startup folder, or a line appended to a shell profile. What it registers "
            "runs again without the component being used."
        ),
        recommendation=(
            "Confirm the component tells the user it installs an autostart entry and what the "
            "entry runs. Remove entries a package added without asking."
        ),
        capability=Capability.FILESYSTEM_WRITE,
        threat_class=ThreatClass.RISKY_CONSTRUCT,
        code_context="comments_and_docstrings",
        tactic=TACTIC_PERSISTENCE,
    ),
    RuleSpec(
        id=R_MASQUERADE,
        category="defense_evasion",
        severity=Severity.HIGH,
        title="Autostart entry named after the operating system's vendor",
        description=(
            "The code creates an autostart entry whose name imitates the operating system: a "
            "LaunchAgent labeled com.apple.* or com.microsoft.*, a scheduled task or Run value "
            "named like a Windows or Microsoft component, or a Startup-folder file named after a "
            "system process. Software from another publisher has no reason to use those names; "
            "they make the entry look like part of the system to whoever reviews the list."
        ),
        recommendation=(
            "Do not install the component. Remove the entry it created on any machine that ran "
            "it and check what the entry starts."
        ),
        capability=Capability.FILESYSTEM_WRITE,
        threat_class=ThreatClass.MALICIOUS_INDICATOR,
        code_context="comments_and_docstrings",
        tactic=TACTIC_DEFENSE_EVASION,
    ),
    RuleSpec(
        id=R_BEACON,
        category="command_and_control",
        severity=Severity.MEDIUM,
        title="Code sends a description of the host off the machine",
        description=(
            "Code gathers facts about the machine next to a network call: the names of the "
            "environment variables that look like secrets, or the machine's public IP address "
            "from a what-is-my-IP service, together with the host or user name, or host facts "
            "sent to a URL whose host is a raw IP address with a port. That is the shape of a "
            "check-in to a remote operator."
        ),
        recommendation=(
            "Confirm where the request goes and why it carries these host facts. Telemetry "
            "should be documented, opt-in and sent to the publisher's own domain."
        ),
        capability=Capability.NETWORK_EGRESS,
        threat_class=ThreatClass.RISKY_CONSTRUCT,
        code_context="comments_and_docstrings",
        tactic=TACTIC_COMMAND_AND_CONTROL,
    ),
]
_RULE_BY_ID = {r.id: r for r in _RULES}


class PostExploitationScanner(Scanner):
    name = "postex"
    rules = _RULES

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: dict[str, list[Evidence]] = {r.id: [] for r in _RULES}
        seen: set[tuple[str, str, int]] = set()

        def add(rule_id: str, items: list[Evidence]) -> None:
            bucket = evidence[rule_id]
            for ev in items:
                key = (rule_id, ev.file, ev.line_start)
                if key in seen or len(bucket) >= MAX_EVIDENCE_SCANNED:
                    continue
                seen.add(key)
                bucket.append(ev)

        for f in _code_files(index):
            file_scan = _FileScan(f)
            lower = f.text.lower()
            for signal in _SIGNALS:
                if signal.keywords and not any(k in lower for k in signal.keywords):
                    continue
                if f.suffix in signal.suffixes or f.suffix == "":
                    add(signal.rule, _signal_evidence(file_scan, signal))
            if any(k in lower for k in _RECON_KEYWORDS):
                add(R_BEACON, _beacon_evidence(f))
        findings = [
            _finding_from_rule(_RULE_BY_ID[rule_id], items)
            for rule_id, items in evidence.items() if items
        ]
        return ScanResult(findings=findings)
