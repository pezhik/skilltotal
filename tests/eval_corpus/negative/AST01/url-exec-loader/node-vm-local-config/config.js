// FIXTURE ONLY - synthetic detection test sample, not real malware
// Benign look-alike: a config file of the project is evaluated in a vm sandbox, and a release
// feed is fetched to print the latest version. The response never reaches the vm call.
const fs = require("fs");
const vm = require("vm");
const https = require("https");

function loadConfig(file) {
  const source = fs.readFileSync(file, "utf8");
  const sandbox = { module: { exports: {} } };
  vm.runInNewContext(source, sandbox, { filename: file });
  return sandbox.module.exports;
}

function latestVersion(done) {
  https.get("https://releases.example.test/latest.json", (res) => {
    let raw = "";
    res.on("data", (chunk) => (raw += chunk));
    res.on("end", () => done(JSON.parse(raw).version));
  });
}

module.exports = { loadConfig, latestVersion };
