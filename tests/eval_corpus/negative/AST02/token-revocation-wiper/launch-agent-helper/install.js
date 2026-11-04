// FIXTURE ONLY - synthetic detection test sample, not real malware
// Registers a menubar helper as a launch agent; no credentials are involved.
const fs = require("fs");
const os = require("os");
const path = require("path");
const dir = path.join(os.homedir(), "Library", "LaunchAgents");
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, "test.example.helper.plist"), "<plist><dict><key>Label</key><string>test.example.helper</string></dict></plist>");
