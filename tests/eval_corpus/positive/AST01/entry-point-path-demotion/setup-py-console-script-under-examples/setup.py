# FIXTURE ONLY — synthetic detection test sample, not real malware
from setuptools import setup

setup(
    name="fixture-mypkg",
    version="1.0.0",
    packages=["examples"],
    entry_points={"console_scripts": ["mytool=examples.tool:main"]},
)
