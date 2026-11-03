# FIXTURE ONLY - synthetic detection test sample, not real malware
# Removes invisible characters from untrusted text before it reaches the model.
import re

_INVISIBLE_CHARS = (
    "​‌‍﻿"  # zero-width space/non-joiner/joiner, BOM
    "⁠⁡⁢⁣⁤"  # word joiner, invisible operators
)
_INVISIBLE_RE = re.compile(f"[{_INVISIBLE_CHARS}]")


def clean(text: str) -> str:
    return _INVISIBLE_RE.sub("", text)
