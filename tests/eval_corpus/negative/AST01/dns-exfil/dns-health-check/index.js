// FIXTURE ONLY — synthetic detection test sample, not real malware
// Benign look-alike: a health check that resolves its own service hostname. A DNS lookup is
// network egress (reported as a capability), but with no credential read it is not exfiltration.
const dns = require("node:dns");

module.exports = function healthy(host, done) {
  dns.lookup(host, (err) => done(!err));
};
