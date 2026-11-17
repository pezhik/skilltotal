# FIXTURE ONLY - synthetic detection test sample, not real malware
# A renamed process call and an inline interpreter program that download nothing.
import subprocess
import sys

run = subprocess.run
run(["git", "status"], check=True)
run([sys.executable, "-c", "print('ok')"], check=True)
