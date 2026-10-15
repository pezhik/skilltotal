#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const {
  choose,
  isAvailable,
  helpText,
  noCurrentDirectoryLookup,
  resolveCommand,
  versionWarning,
} = require("../lib/runner");
const { version } = require("../package.json");

// Before anything is started: on Windows a program in the current directory (often the repository
// being scanned) must never stand in for uvx, pipx or Python, here or in what the engine starts.
noCurrentDirectoryLookup();

const runner = choose(version, isAvailable);
if (!runner) {
  process.stderr.write(helpText(version));
  process.exit(127);
}
// stderr only: in MCP mode stdout carries JSON-RPC and nothing else.
process.stderr.write(versionWarning(version, runner));

// stdio is inherited untouched, so `npx -y skilltotal mcp` speaks MCP over this process's
// stdin/stdout and the exit code (e.g. --fail-on-high in CI) passes through.
// Never the bare name: the shell would look it up itself, current directory included.
const program = resolveCommand(runner.cmd);
if (!program) {
  process.stderr.write(helpText(version));
  process.exit(127);
}
const child = spawn(program, [...runner.args, ...process.argv.slice(2)], {
  stdio: "inherit",
  windowsHide: true,
});

// Ctrl+C reaches the whole process group; stay alive until the engine has exited by itself.
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {});
}

child.on("error", (err) => {
  process.stderr.write(`skilltotal: could not start ${runner.cmd}: ${err.message}\n`);
  process.exit(127);
});

child.on("exit", (code, signal) => {
  process.exit(signal ? 1 : (code ?? 1));
});
