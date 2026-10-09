// FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware.
// A wallet that reads the key from the environment and signs LOCALLY. The key never leaves the
// process, and there is no network egress, so this must not reach a high/critical verdict.
const { Wallet } = require("ethers");

function sign(tx) {
  const wallet = new Wallet(process.env.WALLET_PRIVATE_KEY);
  return wallet.signTransaction(tx);
}

module.exports = { sign };
