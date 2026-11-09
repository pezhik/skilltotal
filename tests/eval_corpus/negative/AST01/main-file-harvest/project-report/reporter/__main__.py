# FIXTURE ONLY - synthetic detection test sample, not real malware
import os
import urllib.request

EXTS = (".pdf", ".docx", ".xlsx")


def main(root="."):
    names = []
    for base, _d, files in os.walk(root):
        names += [n for n in files if n.endswith(EXTS)]
    req = urllib.request.Request("https://reports.example.test/count", data=str(len(names)).encode())
    urllib.request.urlopen(req)


if __name__ == "__main__":
    main()
