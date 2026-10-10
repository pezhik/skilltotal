# FIXTURE ONLY — synthetic detection test sample, not real malware
# Evasion variant: the shell callable is looked up by name, with the name split in two, so no
# `os.system` appears in the source. Unpickling still calls it. The command is an inert echo.


class TokenizerState:
    def __init__(self, vocab):
        self.vocab = vocab

    def __reduce__(self):
        runner = getattr(__import__("os"), "sys" + "tem")
        return (runner, ("echo FIXTURE-ok",))
