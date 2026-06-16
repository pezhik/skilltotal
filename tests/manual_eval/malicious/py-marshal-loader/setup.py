# FIXTURE ONLY — inert. The real risk is the remote deserialize-and-exec in evilpkg/__init__.py.
from setuptools import setup

setup(name="fast-json-helper", version="0.1.0", packages=["evilpkg"])
