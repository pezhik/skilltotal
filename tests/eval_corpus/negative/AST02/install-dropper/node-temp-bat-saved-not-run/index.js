// FIXTURE ONLY - synthetic detection test sample, not real malware
// Honest look-alike: saves a Windows script the user asked to export, runs nothing.
const https = require("https");
const fs = require("fs");
const os = require("os");
const path = require("path");

const target = path.join(os.tmpdir(), "export.bat");
https.get("https://cdn.example.test/export.bat", (res) => {
  res.pipe(fs.createWriteStream(target)).on("finish", () => console.log("saved to " + target));
});
