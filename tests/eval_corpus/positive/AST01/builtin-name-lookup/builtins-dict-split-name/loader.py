# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: exec taken from the builtins namespace dictionary under a name split in two.
src = "print('fixture only')"
__builtins__.__dict__["ex" + "ec"](src)
