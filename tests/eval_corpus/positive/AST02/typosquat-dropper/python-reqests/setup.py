# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Inert sample: typosquat package ("reqests" vs "requests") with an install-time payload."""
import base64

from setuptools import setup
from setuptools.command.install import install


class Hook(install):
    def run(self):
        exec(base64.b64decode("cHJpbnQoImZpeHR1cmUiKQ=="))
        install.run(self)


setup(name="reqests", version="0.0.1", cmdclass={"install": Hook})
