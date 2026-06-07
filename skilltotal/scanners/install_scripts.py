"""Install-time execution detection (npm lifecycle hooks, Python build hooks).

Install-time hooks run automatically when a user installs a package — a classic supply
chain execution vector. npm hooks are matched directly on ``package.json``; Python's
``setup.py`` is only flagged when it contains execution-y constructs (a bare ``setup()``
call is not, by itself, suspicious).
"""

from __future__ import annotations

import re

from skilltotal.models import Capability, Severity
from skilltotal.scanners.base import PatternScanner, RuleSpec, alternation

CATEGORY = "install_time_execution"


class InstallScriptsScanner(PatternScanner):
    name = "install_scripts"
    rules = [
        RuleSpec(
            id="ST-INSTALL-NPM",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="npm install-time lifecycle hook",
            description=(
                "package.json declares install-time lifecycle scripts "
                "(preinstall / install / postinstall) that run automatically when the "
                "package is installed by a consumer."
            ),
            recommendation=(
                "Inspect the hook command. Install-time scripts are a common supply chain "
                "execution vector; ensure they do nothing beyond a documented build step."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            names=("package.json",),
            pattern=re.compile(r'"(?:preinstall|install|postinstall)"\s*:'),
        ),
        RuleSpec(
            id="ST-INSTALL-NPM-PREPARE",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            title="npm prepare hook",
            description=(
                "package.json declares a 'prepare' script. It runs on local/git installs "
                "and before publish (typically a build step), but not for consumers "
                "installing the published package from the registry."
            ),
            recommendation=(
                "Usually a legitimate build step; confirm it only builds and does not fetch "
                "or execute remote code."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            names=("package.json",),
            pattern=re.compile(r'"prepare"\s*:'),
        ),
        RuleSpec(
            id="ST-INSTALL-PY",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Python install/build-time execution hook",
            description=(
                "setup.py / pyproject build configuration contains execution constructs "
                "(custom cmdclass, command-class override, subprocess/os.system, eval/exec, "
                "or network access) that run at build/install time."
            ),
            recommendation=(
                "Verify the build hook performs only a legitimate build step and does not "
                "execute commands or reach the network during installation."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            names=("setup.py", "pyproject.toml"),
            pattern=alternation(
                r"\bcmdclass\b",
                r"class\s+\w*(?:Install|Develop|EggInfo|BuildPy|Build)\b",
                r"\bos\.system\s*\(",
                r"\bsubprocess\.",
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"\bimport\s+(?:urllib|requests|socket|http)\b",
                flags=re.MULTILINE,
            ),
        ),
    ]
