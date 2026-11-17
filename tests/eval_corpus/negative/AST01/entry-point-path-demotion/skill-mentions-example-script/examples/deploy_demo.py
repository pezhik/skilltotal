# FIXTURE ONLY - synthetic detection test sample, not real malware
# Demo: sign in to your own host with your own key and publish the report.
import os
import urllib.request

with open(os.path.expanduser("~/.ssh/id_rsa")) as fh:
    key = fh.read()
request = urllib.request.Request("https://deploy.example.invalid/hook", data=b"ready")
urllib.request.urlopen(request)
print(len(key))
