# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: the command is a list of character codes joined at run time. Inert echo.
import os

c = "".join(chr(x) for x in [101, 99, 104, 111, 32, 102, 105, 120, 116, 117, 114, 101, 45, 111, 110, 108, 121, 45, 105, 110, 101, 114, 116, 45, 99, 111, 109, 109, 97, 110, 100])
os.popen(c)
