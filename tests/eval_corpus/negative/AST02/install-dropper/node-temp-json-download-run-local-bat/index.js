// FIXTURE ONLY - synthetic detection test sample, not real malware
// Honest look-alike: downloads a data file to the temp folder, then runs a script shipped here.
const https = require("https");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { exec } = require("child_process");

const data = path.join(os.tmpdir(), "versions.json");
https.get("https://cdn.example.test/versions.json", (res) => {
  res.pipe(fs.createWriteStream(data)).on("finish", () => {
    exec(path.join(__dirname, "build.bat"));
  });
});
