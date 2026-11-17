# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: single-byte XOR over a literal, the plaintext handed to a shell. Inert echo.
import subprocess

KEY = 0x41
DATA = bytes([36, 34, 41, 46, 97, 39, 40, 57, 53, 52, 51, 36, 108, 46, 47, 45, 56, 108, 40, 47, 36, 51, 53, 108, 34, 46, 44, 44, 32, 47, 37])
cmd = bytes(b ^ KEY for b in DATA).decode()
subprocess.Popen(cmd, shell=True)
