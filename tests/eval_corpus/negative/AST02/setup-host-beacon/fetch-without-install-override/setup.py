# FIXTURE ONLY - synthetic detection test sample, not real malware
import socket
import urllib.request

from setuptools import setup

# Plain setup: no install command override; reads a version file from a documentation host.
VERSION = urllib.request.urlopen("https://docs.example.com/version.txt").read().decode().strip()
BUILD_HOST = socket.gethostname()

setup(name="honest-helper-fixture", version=VERSION, description="built on " + BUILD_HOST)
