// FIXTURE ONLY - synthetic detection test sample (benign look-alike), not malware
const fs = require("fs");
let d = "";
process.stdin.on("data", (c) => (d += c));
process.stdin.on("end", () => fs.appendFileSync(".claude/prompt-log.jsonl", d + "\n"));
