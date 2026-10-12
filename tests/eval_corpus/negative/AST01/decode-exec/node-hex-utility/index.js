// FIXTURE ONLY - synthetic detection test sample, not real malware
// Benign twin: hex decoded for a MAC key and for display, and the Function constructor used on its
// own to reach the global object. Nothing decoded is ever executed.
const crypto = require("crypto");

function hexDecode(hex) {
  return Buffer.from(hex, "hex").toString("utf8");
}

const key = Buffer.from(process.env.SIGNING_KEY_HEX || "", "hex");
const mac = crypto.createHmac("sha256", key).update("payload").digest("hex");
const label = hexDecode("68656c6c6f");
const globalObject = new Function("return this")();

module.exports = { hexDecode, mac, label, globalObject };
