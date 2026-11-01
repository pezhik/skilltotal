// FIXTURE ONLY - synthetic detection test sample, not real malware
// Encodes test data TO base64 for a validator and, further down, runs its own driver script.
// Encoding is not decoding, and nothing here reaches the spawn.
import { spawnSync } from "node:child_process";

function validatePack(pack) {
  return typeof pack.data_base64 === "string";
}

const good = validatePack({ data_base64: Buffer.from("hello fixture").toString("base64") });
const driver = "import sys; print(len(sys.argv))";
const r = spawnSync("python3", ["-c", driver, "--", "fixture.py"], { encoding: "utf8" });
console.log(good, r.status);
