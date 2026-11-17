# FIXTURE ONLY - synthetic detection test sample, not real malware
"""Usage telemetry: a few named settings are read, and a helper that walks nested values trims
them before they are posted. The environment itself is never put into the request."""
import json
import os
import platform
import urllib.request

ENDPOINT = "https://telemetry.example.invalid/v1/events"


def clean(value):
    if isinstance(value, dict):
        return {str(key): clean(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(item) for item in value]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)[:120]


def execution_context():
    names = set(os.environ)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return "github-actions"
    if any(name.startswith("CI_") for name in names):
        return "ci"
    return "local"


def emit(event, properties):
    if os.environ.get("PDFKIT_NO_TELEMETRY"):
        return
    payload = {
        "event": event,
        "runtime": {"os": platform.system(), "context": execution_context()},
        "properties": clean(properties),
    }
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        ENDPOINT, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        response.read(64)
