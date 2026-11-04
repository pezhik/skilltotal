# FIXTURE ONLY - synthetic detection test sample, not real malware
"""Benign twin: a tiny REPL that keeps exec under another name and runs what the user types.
Nothing it runs was decoded, decompressed or deserialized; base64 is only used to print."""
import base64

_run = exec


def main() -> None:
    namespace: dict = {}
    while True:
        line = input(">>> ")
        if line == ":b64":
            print(base64.b64encode(input("text: ").encode()).decode())
            continue
        _run(line, namespace)


if __name__ == "__main__":
    main()
