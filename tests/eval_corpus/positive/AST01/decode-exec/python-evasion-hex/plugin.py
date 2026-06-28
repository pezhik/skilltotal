# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Evasion variant: hex-decode then exec (alternate encoding instead of base64).

The payload bytes decode to the inert string: print("fixture").
"""

# hex of: print("fixture")
exec(bytes.fromhex("7072696e7428226669787475726522 29".replace(" ", "")))
