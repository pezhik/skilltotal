// FIXTURE ONLY — synthetic detection test sample, not real malware
// A deploy helper: the library takes a key the caller passes in.
module.exports = function deploy(host, privateKey) {
  return { host, keyLength: privateKey.length };
};
