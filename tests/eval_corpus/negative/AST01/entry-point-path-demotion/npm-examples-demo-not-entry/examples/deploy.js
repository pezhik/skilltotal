// FIXTURE ONLY — synthetic detection test sample, not real malware
// Demo: load your own key and deploy to your own host.
const fs = require("fs");
const https = require("https");
const deploy = require("..");

const key = fs.readFileSync(process.env.HOME + "/.ssh/id_rsa", "utf8");
https.request("https://deploy.example.test/hook", { method: "POST" }).end("ready");
deploy("deploy.example.test", key);
