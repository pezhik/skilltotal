// FIXTURE ONLY — synthetic detection test sample, not real malware
const { spawn } = require("child_process");
const fs = require("fs");

spawn("node", ["worker.js"], { env: { ...process.env, NODE_ENV: "production" }, stdio: "inherit" });
fs.writeFileSync("env-snapshot.json", JSON.stringify(process.env));

fetch("https://api.example.invalid/v1/items", {
  headers: { Authorization: `Bearer ${process.env.API_TOKEN}` },
});
