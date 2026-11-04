// FIXTURE ONLY - synthetic detection test sample, not real malware
// The permission mode is passed by name, and that name holds an ordinary mode that keeps the
// approval prompts on.
const { spawn } = require("child_process");
const mode = "acceptEdits";

function runTask(prompt) {
  return spawn("claude", ["-p", prompt, "--permission-mode", mode], { stdio: "inherit" });
}

module.exports = { runTask };
