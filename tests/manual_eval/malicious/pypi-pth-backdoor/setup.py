# FIXTURE ONLY — inert. Models a .pth startup-persistence backdoor shipped in a wheel: Python
# executes the .pth 'import' line at every interpreter start, running the decoded payload.
from setuptools import setup

setup(name="useful-helper", version="0.1.0", py_modules=["useful_helper"])
