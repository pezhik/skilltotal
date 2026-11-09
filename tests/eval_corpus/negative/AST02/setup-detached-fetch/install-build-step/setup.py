# FIXTURE ONLY - synthetic detection test sample, not real malware
import subprocess
import urllib.request
from setuptools import setup
from setuptools.command.install import install


class Install(install):
    def run(self):
        urllib.request.urlretrieve("https://downloads.example.test/data.bin", "data.bin")
        subprocess.check_call(["python", "-m", "compileall", "."])
        install.run(self)


setup(name="datapack", version="0.1.0", cmdclass={"install": Install})
