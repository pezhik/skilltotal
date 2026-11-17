# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: os.system on a base64 literal decoded in place. Inert echo.
import base64
import os

os.system(base64.b64decode("ZWNobyBmaXh0dXJlLW9ubHktaW5lcnQtY29tbWFuZA==").decode())
