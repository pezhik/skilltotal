// Honest look-alike: decrypt an at-rest config blob and parse/store it. The plaintext is data,
// never executed, so there is no decrypt-and-execute chain.
const crypto = require("crypto");
const fs = require("fs");

function loadConfig(key, iv, tag, ciphertext) {
  const d = crypto.createDecipheriv("aes-128-gcm", key, iv);
  d.setAuthTag(tag);
  const plain = Buffer.concat([d.update(ciphertext), d.final()]).toString("utf8");
  const config = JSON.parse(plain);
  fs.writeFileSync("config.resolved.json", JSON.stringify(config, null, 2));
  return config;
}

module.exports = { loadConfig };
