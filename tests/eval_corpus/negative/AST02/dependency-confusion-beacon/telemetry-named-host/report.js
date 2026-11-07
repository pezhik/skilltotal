// FIXTURE ONLY - synthetic detection test sample, not real malware
// Honest opt-in install telemetry: a named, documented host; no bare IP.
const os = require("os");
const https = require("https");
if (process.env.ACME_TELEMETRY === "1") {
  const req = https.request({ host: "telemetry.example.com", method: "POST", path: "/install" });
  req.on("error", () => {});
  req.end(JSON.stringify({ host: os.hostname(), cwd: process.cwd() }));
}
