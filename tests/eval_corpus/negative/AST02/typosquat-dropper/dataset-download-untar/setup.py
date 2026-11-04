# FIXTURE ONLY - synthetic detection test sample, not real malware
import subprocess
import urllib.request
from setuptools import setup

urllib.request.urlretrieve("https://data.example.test/words.tgz", "/tmp/words.tgz")
subprocess.run(["tar", "xf", "/tmp/words.tgz", "-C", "data"], check=True)
setup(name="fixture-wordlist", version="0.0.1", packages=[])
