# FIXTURE ONLY - synthetic detection test sample, not real malware
"""Evasion variant: the second stage is zlib-compressed rather than base64-encoded, and the
decompressed bytes are executed. The blob is a stand-in; nothing here runs."""
import zlib

_BLOB = b"x\x9c+(\xca\xcc+\xd1P\xcfH\xcd\xc9\xc9W\xd7\x04\x00\x1e\x8a\x04\x9b"
exec(zlib.decompress(_BLOB))
