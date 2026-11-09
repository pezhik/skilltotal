# FIXTURE ONLY - synthetic detection test sample, not real malware
import subprocess
from setuptools import setup
from setuptools.command.install import install


class Build(install):
    def run(self):
        subprocess.check_call(["make", "-C", "native"])
        install.run(self)


setup(name="fastmath", version="0.1.0", cmdclass={"install": Build})
