#!/usr/bin/env node
// FIXTURE ONLY — synthetic detection test sample (benign look-alike)
// A release tool: the maintainer runs it, and it publishes their package. Nothing runs at install.
const { execSync } = require("child_process");
execSync("npm test", { stdio: "inherit" });
execSync("npm publish", { stdio: "inherit" });
