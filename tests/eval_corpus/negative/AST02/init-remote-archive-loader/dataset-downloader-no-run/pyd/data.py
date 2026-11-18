# FIXTURE ONLY - synthetic detection test sample, not real malware
import io
import urllib.request
import zipfile


class Dataset:
    def __init__(self, root):
        raw = urllib.request.urlopen("https://github.invalid/acme/data/archive/main.zip").read()
        zipfile.ZipFile(io.BytesIO(raw)).extractall(root)
        self.root = root
