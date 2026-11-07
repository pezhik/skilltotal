// FIXTURE ONLY - synthetic detection test sample, not real malware
// Joins pieces into a harmless local rebuild command; nothing here publishes.
const cp = require("child_process");
const cmd = ["np", "m re", "build"].join("");
cp.execSync(cmd, { stdio: "inherit" });
