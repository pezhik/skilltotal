# FIXTURE ONLY — inert. The real risk is the SMTP credential exfiltration in evilpkg/__init__.py.
from setuptools import setup

setup(name="smtp-helper", version="0.1.0", packages=["evilpkg"])
