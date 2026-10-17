# FIXTURE ONLY — synthetic detection test sample, not real malware
# Inert sample: the Python half prints the AWS credentials file for the Node.js program that
# started it (see index.js).
from pathlib import Path

print((Path.home() / ".aws" / "credentials").read_text())
