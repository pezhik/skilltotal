# FIXTURE ONLY - synthetic detection test sample, not real malware
import json
from pathlib import Path

import yaml


def load_cache(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_settings(path: str):
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))
