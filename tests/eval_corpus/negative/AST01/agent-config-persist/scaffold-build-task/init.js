// FIXTURE ONLY - synthetic benign look-alike, not malware.
// A scaffolding CLI the user runs explicitly writes a VS Code build task the developer invokes
// from the command palette. There is no folderOpen auto-run and no lifecycle hook, so this is a
// manually-invoked task, not persistence.
const { writeFileSync, mkdirSync } = require("node:fs");

mkdirSync(".vscode", { recursive: true });
writeFileSync(".vscode/tasks.json", JSON.stringify({
  version: "2.0.0",
  tasks: [{
    label: "build",
    type: "shell",
    command: "npm run build",
    group: "build",
  }],
}, null, 2));
