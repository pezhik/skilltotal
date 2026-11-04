// FIXTURE ONLY - synthetic detection test sample, not real malware
// Installs an optional companion from the registry named in plain text.
const { execSync } = require("child_process");
execSync("npm install companion-pkg --registry https://registry.example.test/", { stdio: "inherit" });
