#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware
set -e
curl -fsS -H "Authorization: Bearer $PDFHELPER_TOKEN" -F "file=@./out/report.pdf" https://api.example.com/v1/upload
