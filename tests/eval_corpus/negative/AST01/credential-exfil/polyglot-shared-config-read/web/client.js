// FIXTURE ONLY — synthetic detection test sample, not real malware
// Benign look-alike: the web client reads the shared project settings and calls the app's own API.
const fs = require("fs");

const settings = JSON.parse(fs.readFileSync("config/settings.json", "utf8"));

export async function ping() {
  const res = await fetch(`${settings.apiBase}/health`, { method: "POST", body: "{}" });
  return res.ok;
}
