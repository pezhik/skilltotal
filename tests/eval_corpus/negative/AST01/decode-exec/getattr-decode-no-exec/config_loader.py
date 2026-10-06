# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Benign look-alike: a config loader picks its codec by name at runtime via getattr(), using
the SAME dynamic-resolution shape as the evasion variant (getattr + concatenated name), but the
decoded bytes are written to disk as DATA and never passed to exec()/eval()."""
import base64

_codec_name = "b64" + "decode"
_decoder = getattr(base64, _codec_name)
_data = _decoder(b"eyJmZWF0dXJlIjogdHJ1ZX0=")

with open("config.json", "wb") as fh:
    fh.write(_data)
