# FIXTURE ONLY - synthetic detection test sample, not real malware
# Benign look-alike: a fetched text is handed to print and len taken from the builtins
# namespace; nothing fetched is executed.
import builtins

import requests

body = requests.get('https://status.example.test/health').text
vars(builtins)['print'](body)
size = getattr(builtins, 'len')(body)
