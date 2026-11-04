# FIXTURE ONLY - synthetic detection test sample, not real malware
"""Evasion variant: the marshalled code object is deserialized into a name first and executed one
statement later, so exec() never holds the marshal.loads call. The blob is a stand-in."""
import marshal

_BLOB = b"\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
_code = marshal.loads(_BLOB)
exec(_code)
