// FIXTURE ONLY - synthetic detection test sample, not real malware
// Benign twin: the node binary is kept in a name and runs a worker script shipped with the
// package, with an inline one-liner that is a plain literal. A base64 token is decoded for an
// Authorization header and never reaches the spawn.
const path = require("path");
const { spawnSync } = require("child_process");

const node = process.execPath;
const auth = Buffer.from(process.env.API_TOKEN || "", "base64").toString();

spawnSync(node, [path.join(__dirname, "worker.js")], { stdio: "inherit" });
spawnSync(node, ["-e", "console.log(process.version)"], { stdio: "inherit" });

module.exports = { headers: { Authorization: `Basic ${auth}` } };
