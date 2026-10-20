# FIXTURE ONLY - synthetic detection test sample, not real malware
# A local helper that happens to be named struct.py but only defines functions and constants.
# No import-time side effects, so it is a naming mistake, not a shadowing attack.
HEADER_SIZE = 8


def pack_header(length):
    return HEADER_SIZE + int(length)


def unpack_header(buffer):
    return len(buffer) - HEADER_SIZE
