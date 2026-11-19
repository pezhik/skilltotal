# FIXTURE ONLY - synthetic detection test sample, not real malware
# Benign look-alike: an updater downloads a pinned installer, checks its SHA-256 against a value
# written here, and only then starts it, in the foreground with its output shown. Downloading and
# running a file is reported as a risk; it is not a malicious verdict.
import hashlib
import subprocess
import sys
import urllib.request

URL = "https://downloads.example.test/tool-1.2.3-installer.py"
SHA256 = "3b5d5c3712955042212316173ccf37be800a6e1bd8f5b0e9d8e1c7a1b5e6f7a8"


def main() -> int:
    urllib.request.urlretrieve(URL, "tool-installer.py")
    with open("tool-installer.py", "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    if digest != SHA256:
        print("checksum mismatch, not installing", file=sys.stderr)
        return 1
    return subprocess.call([sys.executable, "tool-installer.py", "--prefix", "./vendor"])


if __name__ == "__main__":
    sys.exit(main())
