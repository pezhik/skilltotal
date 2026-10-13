# FIXTURE ONLY — synthetic detection test sample, not real malware
# Benign look-alike of setuptools' distutils shim: the .pth imports this module at every start,
# but its top level only defines things; the process call runs only when a function is called.
import subprocess


def add_shim():
    subprocess.run(["echo", "shim"], check=False)


if __name__ == "__main__":
    subprocess.run(["echo", "main"], check=False)
