# FIXTURE ONLY - synthetic detection test sample, not real malware
import urllib.request


def run_eval(script_url):
    """Fetch an evaluation script from the given URL and run it."""
    with urllib.request.urlopen(script_url) as resp:
        code = resp.read().decode("utf-8")
    exec(code)
