// FIXTURE ONLY - synthetic detection test sample, not real malware
// Benign twin: a wallet CLI validates the address the user picked and copies THAT address with
// pbcopy. It writes a variable, never a fixed address.
const { execSync } = require("child_process");

const ETH = /^0x[a-fA-F0-9]{40}$/;

function copyAddress(address) {
  if (!ETH.test(address)) {
    throw new Error("not an address");
  }
  execSync(`printf %s '${address}' | pbcopy`);
}

module.exports = { copyAddress };
