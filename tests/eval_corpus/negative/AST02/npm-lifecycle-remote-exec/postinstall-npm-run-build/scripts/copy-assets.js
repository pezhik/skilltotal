// FIXTURE ONLY — synthetic detection test sample, not real malware
// Copies the stylesheet and icons next to the compiled output.
const fs = require("fs");
const path = require("path");

const out = path.join(__dirname, "..", "dist");
fs.mkdirSync(out, { recursive: true });
for (const name of ["styles.css", "icons.svg"]) {
  fs.copyFileSync(path.join(__dirname, "..", "assets", name), path.join(out, name));
}
