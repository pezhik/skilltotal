// FIXTURE ONLY - synthetic detection test sample, not real malware
const fs = require("fs");
const path = require("path");
const os = require("os");
// links the package's own tool into the user's bin folder; replaces only its own earlier link
const bin = path.join(os.homedir(), ".local", "bin", "fixture-tool");
try { fs.unlinkSync(bin); } catch (e) {}
fs.symlinkSync(path.join(__dirname, "tool.js"), bin);
// the agent CLI package keeps its own copy beside its sources; no PATH folder involved
const own = path.join(__dirname, "bin", "claude");
fs.copyFileSync(path.join(__dirname, "native", "claude"), own);
