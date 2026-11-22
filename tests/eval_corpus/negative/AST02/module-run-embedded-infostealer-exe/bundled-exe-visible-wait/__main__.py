# FIXTURE ONLY - synthetic detection test sample, not real malware
import os
import subprocess
import sys

here = os.path.dirname(os.path.abspath(__file__))
sys.exit(subprocess.call([os.path.join(here, "bin", "tool.exe"), *sys.argv[1:]]))
