# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Downloads a data table at build time and runs the bundled generator over it; the downloaded
file is read as data, never started."""
import subprocess
import sys

import requests
from setuptools import setup

_r = requests.get("https://data.example.invalid/unicode-table.txt", timeout=10)
with open("build/unicode-table.txt", "wb") as _f:
    _f.write(_r.content)
subprocess.run([sys.executable, "tools/gen.py", "build/unicode-table.txt"], check=True)

setup(name="fixture-uniwidth", version="0.2.0")
