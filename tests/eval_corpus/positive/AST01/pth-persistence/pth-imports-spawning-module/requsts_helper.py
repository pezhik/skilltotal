# FIXTURE ONLY — synthetic detection test sample, not real malware
# Runs on import, which the .pth above triggers at every Python start. The shell call is reached
# through names built from pieces; the command is inert (prints only).
import os

_mod = __import__("o" + "s")
_fn = getattr(_mod, "sys" + "tem")
_fn("ec" + "ho fixture")
