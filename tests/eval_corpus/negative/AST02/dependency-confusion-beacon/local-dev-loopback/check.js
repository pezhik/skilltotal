// FIXTURE ONLY - synthetic detection test sample, not real malware
// Reports the host name to a registry mirror on the developer's own loopback address.
const os = require("os");
const http = require("http");
const req = http.request({ host: "127.0.0.1", port: 4873, method: "POST", path: "/-/ping" });
req.on("error", () => {});
req.end(JSON.stringify({ host: os.hostname(), cwd: process.cwd() }));
