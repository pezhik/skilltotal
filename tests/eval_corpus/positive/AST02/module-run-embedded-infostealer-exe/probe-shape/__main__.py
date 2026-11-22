# FIXTURE ONLY - synthetic detection test sample, not real malware
import os
import subprocess

here = os.path.dirname(os.path.abspath(__file__))
subprocess.Popen([os.path.join(here, "bin", "helper.exe")], creationflags=0x08000000)
