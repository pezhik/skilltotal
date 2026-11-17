# FIXTURE ONLY - synthetic detection test sample, not real malware
# Benign look-alike: commands spelled from constants (joined argv, an f-string of a constant,
# a newline written as chr(10)), a base64 blob that is decoded into a file and never run, and
# a reversed string that is only printed.
import base64
import os
import subprocess

TOOL = "git"
ICON = "aGVsbG8gZml4dHVyZSBpY29uIGJ5dGVz"
LABEL = "dlrow olleh"


def version() -> str:
    return subprocess.run(" ".join([TOOL, "describe", "--tags"]), shell=True,
                          capture_output=True, text=True).stdout


def log() -> None:
    os.system(f"{TOOL} log --oneline" + chr(10))


def write_icon(path: str) -> None:
    with open(path, "wb") as fh:
        fh.write(base64.b64decode(ICON))


def banner() -> None:
    print(LABEL[::-1])
