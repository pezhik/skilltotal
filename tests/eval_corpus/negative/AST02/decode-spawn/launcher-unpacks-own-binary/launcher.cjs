// FIXTURE ONLY - synthetic detection test sample, not real malware
// A bundle launcher: the package ships its native binary brotli-compressed, checks the unpacked
// bytes against the manifest's SHA-256, writes them to a temp folder and runs that binary.
"use strict";
const { spawn } = require("node:child_process");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { brotliDecompressSync } = require("node:zlib");

const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "manifest.json"), "utf8"));
const bytes = brotliDecompressSync(
  fs.readFileSync(path.join(__dirname, "bin", "fixture-tool.br")),
  { maxOutputLength: manifest.bytes },
);
if (createHash("sha256").update(bytes).digest("hex") !== manifest.sha256) {
  throw new Error("checksum mismatch");
}
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fixture-"));
const executable = path.join(dir, "fixture-tool");
fs.writeFileSync(executable, bytes, { mode: 0o700, flag: "wx" });
const child = spawn(executable, process.argv.slice(2), { stdio: "inherit" });
child.on("exit", (code) => { process.exitCode = code ?? 1; });
