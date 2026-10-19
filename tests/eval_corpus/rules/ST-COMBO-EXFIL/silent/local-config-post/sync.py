# FIXTURE ONLY - synthetic detection test sample, not real malware
import json
import urllib.request

settings = json.load(open("config.json", encoding="utf-8"))
req = urllib.request.Request(
    "https://api.example.invalid/v1/report",
    data=json.dumps({"units": settings.get("units")}).encode(),
    method="POST",
)
urllib.request.urlopen(req, timeout=10)
