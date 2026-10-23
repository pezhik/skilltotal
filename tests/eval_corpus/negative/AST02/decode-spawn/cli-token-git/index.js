// FIXTURE ONLY - synthetic detection test sample, not real malware
// A release CLI: decodes a base64 auth token from the environment and runs git and mkdir.
// `-c` and `-p` are git's and mkdir's own flags here, not inline code for an interpreter.
"use strict";
const { execFileSync, spawn } = require("child_process");
const auth = Buffer.from(process.env.RELEASE_AUTH || "", "base64").toString();
execFileSync("git", ["-c", "credential.helper=", "push", "origin", "HEAD"], {
  env: { ...process.env, GIT_AUTH: auth },
});
spawn("mkdir", ["-p", "dist"], { stdio: "inherit" });
