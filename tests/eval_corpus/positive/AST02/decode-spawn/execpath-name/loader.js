// FIXTURE ONLY - synthetic detection test sample, not real malware
// Evasion variant: the interpreter path is put in a name before the spawn, so no process.execPath
// stands right after spawnSync(. The blob is gzip+base64 of `console.log(1)`; nothing runs.
const zlib = require("zlib");
const cp = require("child_process");
const BLOB = "H4sIAAAAAAAAA0vOzyvOz0nVy8lP19AEAJ1rC50OAAAA";
const stage = zlib.gunzipSync(Buffer.from(BLOB, "base64")).toString();
const bin = process.execPath;
cp.spawnSync(bin, ["-e", stage]);
