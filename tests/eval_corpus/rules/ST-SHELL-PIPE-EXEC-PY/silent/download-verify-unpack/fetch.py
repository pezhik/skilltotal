# FIXTURE ONLY - synthetic detection test sample, not real malware
# Look-alike: an archive is downloaded, checked and unpacked; a tool the package ships is then
# run on the unpacked folder. The downloaded file itself is never started.
import hashlib
import subprocess
import sys
import tarfile
import urllib.request

SHA256 = "3b5d5c3712955042212316173ccf37be800a6e1bd8f5b0e9d8e1c7a1b5e6f7a8"

urllib.request.urlretrieve("https://downloads.example.test/data-1.2.3.tar.gz", "data.tar.gz")
with open("data.tar.gz", "rb") as fh:
    if hashlib.sha256(fh.read()).hexdigest() != SHA256:
        sys.exit("checksum mismatch")
with tarfile.open("data.tar.gz") as archive:
    archive.extractall("vendor", filter="data")
subprocess.run([sys.executable, "tools/index_data.py", "vendor"], check=True)
