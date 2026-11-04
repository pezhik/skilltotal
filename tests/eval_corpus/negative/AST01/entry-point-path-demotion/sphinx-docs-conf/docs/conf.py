# FIXTURE ONLY — synthetic detection test sample, not real malware
import os
import subprocess
import sys

sys.path.insert(0, os.path.abspath(".."))
project = "widgets"
release = subprocess.check_output(["git", "describe", "--tags"]).decode().strip()
extensions = ["sphinx.ext.autodoc", "sphinx.ext.intersphinx"]
intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}
html_theme = "alabaster"
