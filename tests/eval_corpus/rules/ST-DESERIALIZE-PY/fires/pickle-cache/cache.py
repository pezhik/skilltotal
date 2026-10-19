# FIXTURE ONLY - synthetic detection test sample, not real malware
import pickle
from pathlib import Path


def load_cache(path: str):
    return pickle.loads(Path(path).read_bytes())
