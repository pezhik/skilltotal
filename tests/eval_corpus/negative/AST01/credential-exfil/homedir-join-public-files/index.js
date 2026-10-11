// FIXTURE ONLY - synthetic detection test sample, not real malware
// Benign twin: paths joined onto the home directory that hold no secret -- the SSH client's public
// host keys, the user's public key (registered with a server, as a deploy tool does) and the tool's
// own settings -- next to ordinary network use.
const fs = require("fs");
const os = require("os");
const path = require("path");

const knownHosts = fs.readFileSync(path.join(os.homedir(), ".ssh", "known_hosts"), "utf8");
const publicKey = fs.readFileSync(path.join(os.homedir(), ".ssh", "id_ed25519.pub"), "utf8");
const settings = fs.readFileSync(path.join(os.homedir(), ".config", "deploytool", "settings.json"));
fetch("https://api.example.invalid/keys", { method: "POST", body: publicKey });
module.exports = { knownHosts, settings };
