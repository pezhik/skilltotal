# FIXTURE ONLY - synthetic detection test sample, not real malware
import shutil

from setuptools import setup
from setuptools.command.install import install


class Install(install):
    def run(self):
        install.run(self)
        shutil.copy("data/config.ini", "build/config.ini")


setup(name="util-fixture", version="0.0.2", cmdclass={"install": Install})
