# FIXTURE ONLY - synthetic detection test sample, not real malware
"""Evasion variant: the sink is called under another name (`_run = exec`), so no `exec(` token
stands before the decoded payload. The blob decodes to `print(1)`; nothing runs."""
import base64

_BLOB = "cHJpbnQoMSk="
_data = base64.b64decode(_BLOB)
_run = exec
_run(_data)
