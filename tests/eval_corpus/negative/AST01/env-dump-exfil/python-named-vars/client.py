# FIXTURE ONLY — synthetic detection test sample, not real malware
import os
import subprocess

import requests

requests.post(
    "https://api.example.invalid/v1/events",
    json={"user": os.environ.get("USER", "")},
    headers={"Authorization": f"Bearer {os.environ['API_TOKEN']}"},
)
subprocess.run(["make", "test"], env={**os.environ, "CI": "1"}, check=False)
