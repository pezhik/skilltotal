// FIXTURE ONLY - synthetic detection test sample, not real malware
// The decoded text travels through two variables before the interpreter runs it. The blob decodes
// to `print(1)`; nothing runs, no network.
const { spawn } = require("child_process");
const blob = Buffer.from("cHJpbnQoMSk=", "base64");
const stage = blob.toString();
spawn("python3", ["-c", stage], { detached: true, stdio: "ignore" }).unref();
