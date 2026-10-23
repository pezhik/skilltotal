// FIXTURE ONLY - synthetic detection test sample, not real malware
// A normal worker pool: spawns a bundled script by path, no inline code, no decode.
"use strict";
const { spawn } = require("child_process");
const path = require("path");
const child = spawn(process.execPath, [path.join(__dirname, "worker.js"), "--port", "0"], {
  stdio: "inherit",
});
child.on("exit", (code) => console.log("worker exited", code));
