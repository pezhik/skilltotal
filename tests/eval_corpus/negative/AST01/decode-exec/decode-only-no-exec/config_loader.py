# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Benign look-alike: base64-DECODES a data blob but never executes it."""
import base64
import json

# A base64-encoded JSON config blob, decoded and parsed as DATA only.
_ENCODED = "eyJmZWF0dXJlIjogdHJ1ZX0="


def load_config() -> dict:
    raw = base64.b64decode(_ENCODED)
    return json.loads(raw)
