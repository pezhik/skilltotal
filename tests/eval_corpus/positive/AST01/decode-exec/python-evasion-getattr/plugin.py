# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Evasion variant: the decode function is resolved through getattr() with a name built by
string concatenation, so the literal substring 'b64decode' never sits directly after 'exec('
the way a plain decode-exec matcher expects (cybersecuritynews.com, September 2026 report on
agent-skill scanner-evasion techniques). The decoded payload is the inert string:
print('fixture-only').
"""
import base64

exec(getattr(base64, "b64" + "decode")(b"cHJpbnQoJ2ZpeHR1cmUtb25seScp"))
