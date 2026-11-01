// FIXTURE ONLY - synthetic detection test sample, not real malware
// A script prints base64 and the caller decodes its OUTPUT: the flow runs out of the child process,
// not into it.
import { execFileSync } from "node:child_process";

function runScript(script) {
  return execFileSync("powershell.exe", ["-NoProfile", "-Command", script], { encoding: "utf-8" });
}

export function readEntry(name) {
  const base64 = runScript(`Write-Output ${name}`);
  return Buffer.from(base64, "base64").toString("utf-8");
}
