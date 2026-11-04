# FIXTURE ONLY - synthetic detection test sample, not real malware
"""Benign twin: a compressed JSON cache. The decompressed text is parsed as JSON and its pattern
compiled as a regular expression; nothing decompressed is executed."""
import json
import re
import zlib


def load(path: str) -> dict:
    with open(path, "rb") as fh:
        raw = zlib.decompress(fh.read())
    config = json.loads(raw)
    config["matcher"] = re.compile(config["pattern"])
    return config
