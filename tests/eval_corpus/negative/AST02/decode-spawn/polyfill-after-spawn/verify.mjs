// FIXTURE ONLY - synthetic detection test sample, not real malware
// Runs a fixed PowerShell check first; a base64 polyfill is defined further down for the code it
// goes on to test. Decoding and spawning only share the file.
import { execFileSync } from "node:child_process";

const ps = "Get-Date -Format o";
const out = execFileSync("powershell", ["-NoProfile", "-Command", ps], { encoding: "utf8" }).trim();
console.log(out);

globalThis.atob ??= (b64) => Buffer.from(b64, "base64").toString("binary");
console.log(atob("Zml4dHVyZQ=="));
