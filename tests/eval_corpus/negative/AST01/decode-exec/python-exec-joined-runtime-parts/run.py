# FIXTURE ONLY - synthetic detection test sample, not real malware
# Honest look-alike: exec runs text that includes a runtime argument, so it is not assembled from
# literal fragments; a literal join that never reaches exec is an ordinary log line.
import sys

name = sys.argv[1]
exec("".join(["print(", repr(name), ")"]))
print(" ".join(["a", "b", "c"]))
