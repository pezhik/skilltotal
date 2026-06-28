# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Inert sample: setup.py build hook that decodes and executes a payload at install time."""
import base64

from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        exec(base64.b64decode("cHJpbnQoImZpeHR1cmUiKQ=="))
        install.run(self)


setup(
    name="example-build-helper",
    version="0.0.1",
    cmdclass={"install": PostInstall},
)
