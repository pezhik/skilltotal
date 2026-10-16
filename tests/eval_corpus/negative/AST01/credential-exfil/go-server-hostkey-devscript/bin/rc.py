# FIXTURE ONLY — synthetic detection test sample, not real malware
# Benign look-alike: a developer helper that drives the tool's local remote-control API.
import requests


def rpc(command, params):
    r = requests.post("http://localhost:5572/" + command, json=params)
    r.raise_for_status()
    return r.json()
