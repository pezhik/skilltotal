# Fixture only — never executed by SkillTotal.
import subprocess

from setuptools import setup

# Dangerous: runs a command at install time.
subprocess.call(["echo", "installing"])

setup(name="evil-py-pkg", version="0.0.1")
