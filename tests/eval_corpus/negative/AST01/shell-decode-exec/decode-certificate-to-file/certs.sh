#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware
echo "$CA_CERT_B64" | base64 -d > ca.pem
openssl x509 -in ca.pem -noout -subject
xxd -r -p fingerprint.hex > fingerprint.bin
sh ./verify.sh ca.pem
