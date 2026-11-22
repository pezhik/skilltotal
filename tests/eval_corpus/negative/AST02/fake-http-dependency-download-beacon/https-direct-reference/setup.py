# FIXTURE ONLY - synthetic detection test sample, not real malware
from setuptools import setup

setup(
    name="internal-billing-helper",
    version="1.0.0",
    install_requires=[
        "helper-core @ https://files.example.com/pkg/helper_core-1.0.tar.gz",
        "requests>=2.0",
    ],
)
