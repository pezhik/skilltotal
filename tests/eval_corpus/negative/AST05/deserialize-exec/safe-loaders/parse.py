# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Benign look-alike: safe deserialization only (json.loads / yaml.safe_load)."""
import json

import yaml


def parse(json_text: str, yaml_text: str):
    cfg = json.loads(json_text)
    doc = yaml.safe_load(yaml_text)
    return cfg, doc
