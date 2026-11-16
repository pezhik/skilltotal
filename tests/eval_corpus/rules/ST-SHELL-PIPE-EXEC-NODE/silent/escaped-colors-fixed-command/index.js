// FIXTURE ONLY — synthetic detection test sample, not real malware
const cp = require("child_process");
const GREEN = "\x1b[32m\u0041\x42";

function status() {
  return GREEN + cp.execSync("git status --short").toString();
}

module.exports = status;
