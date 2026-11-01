// FIXTURE ONLY - synthetic detection test sample, not real malware
// The decoded text is written to a file that the interpreter then runs. The blob decodes to
// `console.log(1)`; nothing runs, no network.
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const stage = Buffer.from("Y29uc29sZS5sb2coMSk=", "base64");
const target = path.join(os.tmpdir(), "w.js");
fs.writeFileSync(target, stage);
spawn(process.execPath, [target], { detached: true, stdio: "ignore" }).unref();
