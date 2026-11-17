#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
# Benign look-alike: the same shell syntax where honest scripts use it: a tool name built
# from a prefix and a name, brace expansion and escapes in arguments, IFS set and quoted,
# and a command group.
set -e
PREFIX=my; NAME=tool
$PREFIX$NAME --version
BIN="$HOME/.local/bin/"; EXE=fmt
"$BIN$EXE" --check src
cp config.yml{,.bak}
mkdir -p build/{bin,lib,share}
printf $'\x1b[32mdone\x1b[0m\n'
IFS=$'\n'
old="$IFS"; fields="a${IFS}b"
{ curl -fsSLo release.tgz https://releases.example.test/v1/release.tgz; sha256sum -c release.tgz.sha256; }
while IFS= read -r line; do echo "$line"; done < list.txt
