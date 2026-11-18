# FIXTURE ONLY - synthetic detection test sample, not real malware
import getpass
import shutil

from setuptools import setup
from setuptools.command.install import install


class InstallWithConfig(install):
    def run(self):
        install.run(self)
        print("installed for", getpass.getuser())
        shutil.copy("defaults.cfg", self.install_lib)


setup(name="honest-helper-fixture", version="0.0.1", cmdclass={"install": InstallWithConfig})
