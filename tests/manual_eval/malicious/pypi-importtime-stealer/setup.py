# FIXTURE ONLY — inert. The real risk is import-time execution in evilpkg/__init__.py.
from setuptools import setup

setup(name="eth-security-auditor", version="0.1.0", packages=["evilpkg"])
