# FIXTURE ONLY - synthetic detection test sample, not real malware
# Benign look-alike: a DNS blocklist query built from a reversed address, in a tool that
# also base64-encodes its own API token for an Authorization header. The lookup name is
# built from the address only; the encoded token never reaches it.
import base64
import os
import socket

API_TOKEN = os.environ.get('MAILGUARD_API_TOKEN', '')
AUTH = 'Basic ' + base64.b64encode(API_TOKEN.encode()).decode()


def listed(address: str) -> bool:
    reversed_ip = '.'.join(reversed(address.split('.')))
    try:
        socket.gethostbyname(f'{reversed_ip}.zen.blocklist.example.test')
    except OSError:
        return False
    return True


def headers() -> dict:
    return {'Authorization': AUTH}
