# FIXTURE ONLY - synthetic detection test sample, not real malware
import subprocess


def share(port):
    """Expose a local web preview through a tunnel; no SSH server is started."""
    return subprocess.Popen(["ngrok", "http", str(port)])
