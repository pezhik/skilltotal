# FIXTURE ONLY - synthetic detection test sample, not real malware
import builtins

_printer = getattr(builtins, "print")
_name = "len"
_len = getattr(builtins, _name)
