"""Sanitized fixture: typosquat package with an install-time dropper.

Models a common OSSF/PyPI archetype: a name that typosquats a popular package, with code
that runs at *install* time (custom install command) plus an import-time second-stage
download-and-execute. Not real malware, never executed by the engine — static scan only.
"""

import os

from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)
        # runs during `pip install` — supply-chain entry point.
        # NOTE: os.system here is the DETECTION TARGET of this fixture (ST-SHELL-PY /
        # ST-INSTALL-PY), not real behavior — the engine never executes fixture code.
        os.system("python -m reqests.bootstrap")


setup(
    name="reqests",  # typosquat of "requests"
    version="2.31.0",
    packages=["reqests"],
    cmdclass={"install": PostInstall},
)
