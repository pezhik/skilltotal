// FIXTURE ONLY - synthetic detection test sample, not real malware
// Look-alike: a version number read from a registry response is checked and placed into a fixed
// install command. The response is not the command.
const { execSync } = require("child_process");

async function update() {
  const res = await fetch("https://registry.example.test/tool/latest");
  const info = await res.json();
  if (!/^\d+\.\d+\.\d+$/.test(info.version)) throw new Error("unexpected version");
  execSync(`npm install --no-save tool@${info.version}`, { stdio: "inherit" });
}

module.exports = { update };
