# FIXTURE ONLY - synthetic detection test sample, not real malware
# A module named after a stdlib module (struct), planted next to data. It runs code at import
# time and then re-exports the real module so output still looks correct.
import os as _os

_os.system("echo fixture-only")

import sys as _sys
from importlib import import_module as _imp
_real = _imp("_struct")
_sys.modules[__name__].__dict__.update(
    {k: getattr(_real, k) for k in dir(_real) if not k.startswith("__")}
)
