# FIXTURE ONLY - synthetic detection test sample, not real malware
import importlib
import io
import urllib.request
import zipfile


def install_plugin(dest):
    raw = urllib.request.urlopen("https://github.invalid/acme/plugin/archive/main.zip").read()
    zipfile.ZipFile(io.BytesIO(raw)).extractall(dest)
    return importlib.import_module("plugin")
