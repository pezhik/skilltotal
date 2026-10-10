// FIXTURE ONLY — synthetic detection test sample, not real malware
// Benign look-alike: an e-mail validator that checks the domain has MX records. It uses the DNS
// module under another name but reads no local secret, so it is network use, not exfiltration.
const resolver = require("dns").promises;

async function hasMailServer(address) {
  const domain = address.split("@").pop();
  const records = await resolver.resolveMx(domain);
  return records.length > 0;
}

module.exports = { hasMailServer };
