# FIXTURE ONLY — synthetic detection test sample, not real malware
"""In-tree backend: regenerates the lookup tables with the bundled script, then defers to
setuptools to build the wheel."""
import subprocess
import sys

from setuptools import build_meta as _orig
from setuptools.build_meta import *  # noqa: F401,F403


def _generate_tables():
    subprocess.run([sys.executable, "tools/gen_tables.py", "--out", "gridcalc/_tables.py"], check=True)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _generate_tables()
    return _orig.build_wheel(wheel_directory, config_settings, metadata_directory)
