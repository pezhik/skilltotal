# FIXTURE ONLY - synthetic detection test sample, not real malware
# Benign look-alike: compatibility code that reads builtins by a name written out, or by a
# name that comes from a variable. Nothing is hidden and nothing is executed from text.
import builtins


def original_print():
    return vars(builtins)["print"]


def has_builtin(name: str) -> bool:
    return name in builtins.__dict__


def dunder(name: str):
    return getattr(builtins, "__" + name + "__", None)


def opener():
    return getattr(builtins, "open")
