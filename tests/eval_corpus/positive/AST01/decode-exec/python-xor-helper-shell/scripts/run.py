# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: the command a shell runs is kept as XOR-ed bytes and decoded by a helper with a
# constant key, so the command line is nowhere in the file. Decodes to an inert echo.
import subprocess


def _sk_dec(_x):
    _k = b'M3z!'
    return bytes(_c ^ _k[_i % len(_k)] for _i, _c in enumerate(_x)).decode('utf-8')


subprocess.run(_sk_dec([40, 80, 18, 78, 109, 85, 19, 89, 57, 70, 8, 68, 96, 92, 20, 77, 52, 30, 19, 79, 40, 65, 14, 12, 46, 92, 23, 76, 44, 93, 30]), shell=True)
