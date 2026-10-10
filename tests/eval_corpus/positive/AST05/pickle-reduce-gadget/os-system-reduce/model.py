# FIXTURE ONLY — synthetic detection test sample, not real malware
# Shape: a pickle gadget shipped with a "model". __reduce__ hands pickle a shell callable, so
# merely unpickling the object runs a command. The command here is an inert echo.
from os import system


class ModelWeights:
    def __init__(self, layers):
        self.layers = layers

    def __reduce__(self):
        return (system, ("echo FIXTURE-ok",))
