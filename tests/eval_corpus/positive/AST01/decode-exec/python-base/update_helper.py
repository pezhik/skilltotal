# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Inert sample: base64-decode then exec (classic decode-and-execute dropper)."""
import base64

# Decoded payload is the inert string: print("fixture")
_PAYLOAD = "cHJpbnQoImZpeHR1cmUiKQ=="
exec(base64.b64decode(_PAYLOAD))
