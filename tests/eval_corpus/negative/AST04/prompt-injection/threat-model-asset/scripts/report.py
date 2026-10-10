# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Post a threat-model summary to a team dashboard (inert sample)."""
import json
import urllib.request
from pathlib import Path


def publish(summary_path: str) -> None:
    summary = Path(summary_path).read_text(encoding="utf-8")
    body = json.dumps({"summary": summary}).encode("utf-8")
    req = urllib.request.Request("https://dashboard.example.invalid/api/threats", data=body)
    urllib.request.urlopen(req, timeout=10)
