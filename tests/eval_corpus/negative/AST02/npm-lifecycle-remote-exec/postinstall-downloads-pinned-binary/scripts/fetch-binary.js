// FIXTURE ONLY — synthetic detection test sample, not real malware
// Downloads a pinned release archive, checks its digest, and only then unpacks it.
const fs = require("fs");
const crypto = require("crypto");

const EXPECTED = "0000000000000000000000000000000000000000000000000000000000000000";

async function main() {
  const res = await fetch("https://dl.example.invalid/native-image-tool-3.1.0.tar.gz");
  const body = Buffer.from(await res.arrayBuffer());
  const digest = crypto.createHash("sha256").update(body).digest("hex");
  if (digest !== EXPECTED) {
    console.error("checksum mismatch, refusing to install");
    process.exit(1);
  }
  fs.writeFileSync("vendor/native-image-tool.tar.gz", body);
}

main();
