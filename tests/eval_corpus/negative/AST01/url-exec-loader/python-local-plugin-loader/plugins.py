# FIXTURE ONLY - synthetic detection test sample, not real malware
# Benign look-alike: a plugin loader imports a module file of the package from its path, and a
# helper downloads a data file that is only parsed. Nothing downloaded is imported or run.
import importlib.util
import json
import urllib.request
from pathlib import Path


def load(name: str):
    path = Path(__file__).parent / "plugins" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def catalog():
    urllib.request.urlretrieve("https://plugins.example.test/catalog.json", "catalog.json")
    with open("catalog.json", encoding="utf-8") as fh:
        return json.load(fh)
