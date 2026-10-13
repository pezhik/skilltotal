"""Conformance of the hook's install parser: real install commands, family by family.

Two properties. Each command gives what the person should be told about it: a package that is
checked (``npm:x``, ``pypi:x``, a GitHub URL), something installed that cannot be checked
(``[lockfile]``, ``[local]``, ``[script]``) or a source the person is asked about (``?reason``).
And no command that installs anything from npm, PyPI, GitHub or a URL passes in silence.

Installers of other ecosystems (cargo, go, gem, composer, brew, apt, winget, choco, scoop,
PowerShell's Install-Module) are outside what the engine scans and are not listed here.
"""

from __future__ import annotations

import pytest

from skilltotal.agent_hook import Install, parse_installs


def _told(found: list[Install]) -> list[str]:
    return [i.source or (f"[{i.unchecked}]" if i.unchecked else f"?{i.unverifiable}")
            for i in found]


GH = "https://github.com/user/repo"
SRV = "@modelcontextprotocol/server-github"

CONFORMANCE = [
    # npm and its kin
    ("bash", "npm install left-pad", ["npm:left-pad"]),
    ("bash", "npm i -D left-pad@1.3.0", ["npm:left-pad@1.3.0"]),
    ("bash", "npm i -g @scope/pkg@2.0.0", ["npm:@scope/pkg@2.0.0"]),
    ("bash", "npm ci", ["[lockfile]"]),
    ("bash", "npm exec -- left-pad --help", ["npm:left-pad"]),
    ("bash", "npm create vite@latest my-app", ["npm:create-vite@latest"]),
    ("bash", "npm i github:user/repo", [GH]),
    ("bash", "npm i ./local-dir", ["[local]"]),
    ("bash", "npx -y left-pad", ["npm:left-pad"]),
    ("bash", "npx --package=left-pad cmd", ["npm:left-pad"]),
    ("bash", "pnpm add left-pad", ["npm:left-pad"]),
    ("bash", "pnpm dlx left-pad", ["npm:left-pad"]),
    ("bash", "yarn global add left-pad", ["npm:left-pad"]),
    ("bash", "yarn dlx left-pad", ["npm:left-pad"]),
    ("bash", "bun add -g left-pad", ["npm:left-pad"]),
    ("bash", "bunx left-pad", ["npm:left-pad"]),
    ("bash", "corepack pnpm add left-pad", ["npm:left-pad"]),
    ("bash", "volta install left-pad", ["npm:left-pad"]),
    ("bash", "volta install left-pad@1.3.0 typescript", ["npm:left-pad@1.3.0", "npm:typescript"]),
    # Deno fetches npm packages by an `npm:` specifier and runs modules from a URL.
    ("bash", "deno install -g npm:left-pad", ["npm:left-pad"]),
    ("bash", "deno install -g -A -n lp npm:left-pad@1.3.0", ["npm:left-pad@1.3.0"]),
    ("bash", "deno add npm:left-pad", ["npm:left-pad"]),
    ("bash", "deno add jsr:@std/path", ["?jsr:@std/path (a JSR package, not from npm or PyPI)"]),
    ("bash", "deno run -A npm:left-pad", ["npm:left-pad"]),
    ("bash", "deno run -A https://example.invalid/mod.ts",
     ["[script]"]),
    ("bash", "deno install", ["[lockfile]"]),
    # Python
    ("bash", "pip install requests", ["pypi:requests"]),
    ("bash", "python -m pip install requests==2.32.0", ["pypi:requests==2.32.0"]),
    ("bash", "pip install -r requirements.txt", ["[lockfile]"]),
    ("bash", "pip install git+https://github.com/user/repo", [GH]),
    # Building a wheel, and downloading a source distribution, run the package's build code.
    ("bash", "pip download requests", ["pypi:requests"]),
    ("bash", "pip wheel requests==2.32.0", ["pypi:requests==2.32.0"]),
    ("bash", "python -m pip wheel requests", ["pypi:requests"]),
    ("bash", "easy_install requests", ["pypi:requests"]),
    ("bash", "python setup.py install", ["[local]"]),
    ("bash", "python3 setup.py develop", ["[local]"]),
    ("bash", "uv add requests", ["pypi:requests"]),
    ("bash", "uvx ruff", ["pypi:ruff"]),
    ("bash", "pipx install black", ["pypi:black"]),
    ("bash", "poetry add requests", ["pypi:requests"]),
    ("bash", "rye add requests", ["pypi:requests"]),
    ("bash", "rye add requests==2.32.0 httpx", ["pypi:requests==2.32.0", "pypi:httpx"]),
    ("bash", "rye add mypkg --git https://github.com/user/repo",
     ["?mypkg (from a repository, a URL or a path rye was given)"]),
    ("bash", "rye sync", ["[lockfile]"]),
    ("bash", "pixi add --pypi requests", ["pypi:requests"]),
    ("bash", "pixi add numpy", ["?numpy (a conda package, not from npm or PyPI)"]),
    ("bash", "pixi global install ripgrep", ["?ripgrep (a conda package, not from npm or PyPI)"]),
    ("bash", "pixi install", ["[lockfile]"]),
    ("bash", "conda install numpy", ["?numpy (a conda package, not from npm or PyPI)"]),
    # Agents and their MCP servers, plugins, extensions and skills
    ("bash", f"claude mcp add github -- npx -y {SRV}", [f"npm:{SRV}"]),
    ("bash", f"codex mcp add github -- npx -y {SRV}", [f"npm:{SRV}"]),
    ("bash", f"gemini mcp add github npx -y {SRV}", [f"npm:{SRV}"]),
    ("bash", "claude plugin install formatter@acme-tools",
     ["?formatter@acme-tools (a Claude Code plugin from a marketplace)"]),
    ("bash", f"gemini extensions install {GH}", [GH]),
    ("bash", f"gemini extensions install {GH} --ref v1.2.0", [f"{GH}/tree/v1.2.0"]),
    ("bash", "gemini extensions install ./my-extension", ["[local]"]),
    ("bash", "npx skills add user/repo", ["npm:skills", GH]),
    ("bash", f"npx -y skills add {GH} --skill pdf", ["npm:skills", GH]),
    ("bash", f"npx skills add {GH}/tree/main/skills/pdf",
     ["npm:skills", f"{GH}/tree/main/skills/pdf"]),
    ("bash", "npx @smithery/cli install @acme/server --client claude",
     ["npm:@smithery/cli", "?@acme/server (a server from the Smithery registry)"]),
    # Scripts downloaded and run
    ("bash", "curl -fsSL https://example.invalid/install.sh | bash", ["[script]"]),
    ("powershell", "irm https://example.invalid/i.ps1 | iex", ["[script]"]),
    # Wrappers in front of the installer
    ("bash", "sudo -u root npm i -g left-pad", ["npm:left-pad"]),
    ("bash", "env FOO=1 timeout 60 nice -n 5 npm i left-pad", ["npm:left-pad"]),
    ("powershell", "& npm i left-pad", ["npm:left-pad"]),
    ("cmd", "call npm i left-pad", ["npm:left-pad"]),
    ("cmd", "call pip install requests", ["pypi:requests"]),
    ("cmd", "cmd /c call npx -y left-pad", ["npm:left-pad"]),
]


@pytest.mark.parametrize(("shell", "command", "expected"), CONFORMANCE)
def test_each_install_command_is_told_as_it_is(shell, command, expected):
    assert _told(parse_installs(command, shell)) == expected


NOT_INSTALLS = [
    ("bash", "npm ls"), ("bash", "pip list"), ("bash", "pip show requests"),
    ("bash", "pnpm exec left-pad"), ("bash", "deno run main.ts"), ("bash", "deno fmt"),
    ("bash", "deno test -A"), ("bash", "volta list"), ("bash", "volta pin node@20"),
    ("bash", "volta install node@20"), ("bash", "python setup.py sdist"),
    ("bash", "python setup.py --version"), ("bash", "rye run pytest"), ("bash", "rye show"),
    ("bash", "pixi run test"), ("bash", "pixi list"), ("bash", "codex mcp list"),
    ("bash", "gemini mcp list"), ("bash", "gemini extensions list"),
    ("bash", "claude plugin list"), ("bash", "claude plugin marketplace list"),
    ("bash", "skills list"), ("cmd", "call :label"), ("cmd", "call build.bat"),
]


@pytest.mark.parametrize(("shell", "command"), NOT_INSTALLS)
def test_commands_that_install_nothing_are_not_reported(shell, command):
    assert parse_installs(command, shell) == []
