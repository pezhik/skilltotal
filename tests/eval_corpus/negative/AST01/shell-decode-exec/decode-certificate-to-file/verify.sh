#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware
openssl verify -CAfile "$1" server.pem
