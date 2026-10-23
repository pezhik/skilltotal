# FIXTURE ONLY - synthetic detection test sample, not real malware
# An ordinary site hook: extends sys.path and sets the default encoding. No process, network or
# decode. This is what a legitimate sitecustomize does.
import sys
import os

sys.path.append(os.path.join(sys.prefix, "local-plugins"))
