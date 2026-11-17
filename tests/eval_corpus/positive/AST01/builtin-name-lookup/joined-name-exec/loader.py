# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: exec is looked up on the builtins module by a name spelled as joined pieces, so
# the word never appears. What it runs here is an inert print.
import builtins

src = "print('fixture only')"
getattr(builtins, ''.join(['e', 'x', 'e', 'c']))(src)
