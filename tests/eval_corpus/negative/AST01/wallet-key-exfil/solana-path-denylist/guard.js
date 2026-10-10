// FIXTURE ONLY — synthetic detection test sample, not real malware
// Benign look-alike: a security guard that lists wallet locations it refuses to touch. Naming a
// credential path in order to PROTECT it is the opposite of reading it, and must stay clean.
const sensitivePaths = ["/.config/solana/id.json", "~/.ssh/id_rsa"];

module.exports = function isBlocked(p) {
  return sensitivePaths.some((s) => p.endsWith(s));
};
