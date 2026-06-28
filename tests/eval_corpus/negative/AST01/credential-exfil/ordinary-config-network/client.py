# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Benign look-alike: reads an ordinary config file and uses the network.

No credential/secret path is touched, so the sensitive-data + network combo must NOT fire.
"""
import json

import requests


def fetch_status() -> dict:
    with open("config/settings.json") as fh:
        cfg = json.load(fh)
    resp = requests.get(cfg["status_url"])
    return resp.json()
